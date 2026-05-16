/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 SiFive Inc.
 */

#include <sbi/riscv_asm.h>
#include <sbi/riscv_atomic.h>
#include <sbi/riscv_barrier.h>
#include <sbi/sbi_bitmap.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_domain.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_hart_protection.h>
#include <sbi/sbi_heap.h>
#include <sbi/sbi_math.h>
#include <sbi/sbi_platform.h>
#include <sbi/sbi_string.h>
#include <sbi/sbi_types.h>
#include <sbi/sbi_hart_smmpt.h>

#if __riscv_xlen == 32
#define MMPT_PPN_MASK           _UL(0x003FFFFF)
#define MMPT_SDID_MASK          _UL(0x0FC00000)
#define MMPT_MODE_MASK          _UL(0xC0000000)
#define MMPT_PPN_MAX            0x3FFFFF
#else
#define MMPT_PPN_MASK           _ULL(0x00000FFFFFFFFFFF)
#define MMPT_SDID_MASK          _ULL(0x03F0000000000000)
#define MMPT_MODE_MASK          _ULL(0xF000000000000000)
#define MMPT_PPN_MAX            0xFFFFFFFFFFF
#endif

#define MMPT_SDID_MAX           0x3F

#if __riscv_xlen == 32
#define NUM_PG_BITS_IN_RANGE     3
#define NAPOT_G                  6
static unsigned long mpt_pte_indexes = 10;
#else
#define NUM_PG_BITS_IN_RANGE     4
#define NAPOT_G                  4
static unsigned long mpt_pte_indexes = 9;
#endif

#define PG_RANGE_OFFSET_SHIFT   ((NUM_PG_BITS_IN_RANGE) + (PAGE_SHIFT))
#define PG_MASK                 ((1 << NUM_PG_BITS_IN_RANGE) - 1)
#define NAPOT_NUM_PAGES_ORDER   ((NUM_PG_BITS_IN_RANGE) + ((NAPOT_G) + 1))
#define NAPOT_NUM_PAGES         (1 << NAPOT_NUM_PAGES_ORDER)
#define PAGES_PER_MPTE          (1 << (NUM_PG_BITS_IN_RANGE))

#define MPTE_VALID              BIT(0)
#define MPTE_LEAF               BIT(1)
#define MPTE_NAPOT              BIT(2)
#if __riscv_xlen == 32
#define MPTE_PPN                _UL(0xFFFFFC00)
#define MPTE_G                  _UL(0x0000F000)
#else
#define MPTE_PPN                _ULL(0x003FFFFFFFFFFC00)
#define MPTE_G                  _ULL(0x000000000000F000)
#endif
#define MPTE_XWR_SHIFT          8
#define MPTE_XWR_MASK           _UL(0x7)

/* MPT population states */
typedef enum {
    /* Initial state, ready for first attempt */
    MPT_STATE_NOT_POPULATED = 0,
    /* Currently being populated by one hart */
    MPT_STATE_POPULATING,
    /* Successfully populated, ready to use */
    MPT_STATE_POPULATED,
    /* Population failed permanently, no retry */
    MPT_STATE_FAILED,
} mpt_populate_state_t;

typedef enum {
    SMMPT_BARE = 0,
#if __riscv_xlen == 32
    SMMPT34 = 1,
#else
    SMMPT43 = 1,
    SMMPT52 = 2,
    SMMPT64 = 3,
#endif
    SMMPT_MAX,
} mpt_mode_t;

/* Per-domain Smmpt state */
struct smmpt_state {
    /** Root of the memory protection table */
    unsigned long *mpt;
    /** Supervisor domain identifier */
    u32 sdid;
    /** Spinlock for accessing MPT */
    spinlock_t mpt_lock;
    /** MPT population flag, see: mpt_populate_state_t */
    atomic_t mpt_populate_state;
};

static u32 mpt_sdidlen;
static mpt_mode_t mpt_mode;
static u32 mpt_pg_levels;

static u32 sdid_next = 0;

static struct sbi_heap_control *smmpt_hpctrl;

static inline int sbi_hart_smmpt_check_addr_size(unsigned long addr,
                unsigned long size, u32 page_order)
{
    unsigned long page_size = BIT(page_order);

    /* Address must at least be aligned to the page size. */
    if (addr & (page_size - 1))
        return SBI_EINVALID_ADDR;

    if (size < page_size)
        return SBI_EINVAL;

    /* Size must at least be multiples of 4 KiB. */
    if (size & (PAGE_SIZE - 1))
        return SBI_EINVAL;

    return SBI_OK;
}

static inline unsigned long sbi_hart_smmpt_page_table_size(u32 level)
{
    /* Smmpt64 page table size is 32 KiB, others are 4 KiB. */
    return (level == 4) ? (PAGE_SIZE << 3) : PAGE_SIZE;
}

/*
 * Return the maximum physical address space that Smmpt could supoort.
 */
static unsigned long sbi_hart_smmpt_max_addr(void)
{
    u32 addr_bits;

    /* Smmpt64 */
    if (mpt_pg_levels == 5)
        return ~0UL;

    addr_bits = PG_RANGE_OFFSET_SHIFT + mpt_pte_indexes +
        9 * (mpt_pg_levels - 1);

    if (addr_bits >= __riscv_xlen)
        return ~0UL;

    return (BIT(addr_bits)) - 1;
}

static inline u32 sbi_hart_smmpt_page_order(u32 level)
{
    return (level == 0) ? PAGE_SHIFT :
        PAGE_SHIFT + mpt_pte_indexes + 9 * (level - 1);
}

/*
 * Convert domain flags to Smmpt XWR permission tuple.
 */
static inline int sbi_hart_smmpt_flags_to_xwr(unsigned long flags, u32 *xwr)
{
    /*
     * Reject reserved combinations:
     * - Write-only (X=0, W=1, R=0)
     * - Execute-only with write (X=1, W=1, R=0)
     */
    if ((flags & SBI_DOMAIN_MEMREGION_SU_WRITABLE) &&
        !(flags & SBI_DOMAIN_MEMREGION_SU_READABLE))
        return SBI_EINVAL;

    *xwr = (flags >> SBI_DOMAIN_MEMREGION_SU_ACCESS_SHIFT) & MPTE_XWR_MASK;
    return SBI_OK;
}

/*
 * Return the page index within an MPTE for an address.
 */
static inline u32 sbi_hart_smmpt_start_pg(unsigned long addr, u32 level)
{
    return (addr >> sbi_hart_smmpt_page_order(level)) & PG_MASK;
}

static inline bool sbi_hart_smmpt_is_leaf_mpte(unsigned long mpte)
{
    return EXTRACT_FIELD(mpte, MPTE_LEAF);
}

static inline bool sbi_hart_smmpt_is_valid_mpte(unsigned long mpte)
{
    return EXTRACT_FIELD(mpte, MPTE_VALID);
}

static inline bool sbi_hart_smmpt_is_napot_mpte(unsigned long mpte)
{
    return EXTRACT_FIELD(mpte, MPTE_NAPOT);
}

static inline unsigned long sbi_hart_smmpt_mpte_ppn(unsigned long mpte)
{
    return EXTRACT_FIELD(mpte, MPTE_PPN);
}

/*
 * Return the page number of MPTE at the given address within the page table.
 */
static u32 sbi_hart_smmpt_mpte_pn(unsigned long addr, u32 level)
{
    u32 shift, mask;

    if (level == 0) {
        shift = PG_RANGE_OFFSET_SHIFT;
        mask = GENMASK(mpt_pte_indexes - 1, 0);
    } else {
        shift = PG_RANGE_OFFSET_SHIFT + mpt_pte_indexes + 9 * (level - 1);
        mask = GENMASK((level == 4) ? 11 : 8, 0);
    }

    return (addr >> shift) & mask;
}

static inline void sbi_hart_smmpt_mpte_set_valid(unsigned long *mpte, bool valid)
{
    *mpte = INSERT_FIELD(*mpte, MPTE_VALID, valid);
}

static unsigned long sbi_hart_smmpt_mpte_xwr_mask(bool napot, u32 start_pg,
                u32 num_pages)
{
    unsigned long mask = 0;

    if (napot)
        return MPTE_XWR_MASK << MPTE_XWR_SHIFT;

    for (u32 i = 0; i < num_pages; i++) {
        mask |= (MPTE_XWR_MASK << (MPTE_XWR_SHIFT + 3 * (start_pg + i)));
    }

    return mask;
}

static int sbi_hart_smmpt_mpte_set_xwr(unsigned long *mpte, bool napot,
                unsigned long xwr, u32 start_pg, u32 num_pages)
{
    unsigned long xwr_mask = sbi_hart_smmpt_mpte_xwr_mask(napot, start_pg,
                                num_pages);
    unsigned long xwr_val = 0;

    if (unlikely(!napot && start_pg + num_pages > PAGES_PER_MPTE))
        return SBI_EINVAL;

    if (napot) {
        *mpte = INSERT_FIELD(*mpte, xwr_mask, xwr);
    } else {
        for (u32 i = 0; i < num_pages; i++) {
            xwr_val |= xwr << 3 * i;
        }
        *mpte = INSERT_FIELD(*mpte, xwr_mask, xwr_val);
    }

    return SBI_OK;
}

/*
 * Set a non-leaf MPTE.
 */
static inline void sbi_hart_smmpt_nonleaf_mpte(unsigned long *mpte,
                unsigned long ppn)
{
    *mpte = INSERT_FIELD(*mpte, MPTE_VALID, true);
    *mpte = INSERT_FIELD(*mpte, MPTE_LEAF, false);
    *mpte = INSERT_FIELD(*mpte, MPTE_PPN, ppn);
}

/*
 * Set a leaf MPTE.
 */
static inline int sbi_hart_smmpt_leaf_mpte(unsigned long *mpte, bool napot,
                unsigned long xwr, u32 start_pg, u32 num_pages)
{
    *mpte = INSERT_FIELD(*mpte, MPTE_VALID, true);
    *mpte = INSERT_FIELD(*mpte, MPTE_LEAF, true);

    if (napot) {
        *mpte = INSERT_FIELD(*mpte, MPTE_NAPOT, true);
        *mpte = INSERT_FIELD(*mpte, MPTE_G, NAPOT_G);
    }

    return sbi_hart_smmpt_mpte_set_xwr(mpte, napot, xwr, start_pg, num_pages);
}

/*
 * Detect the Smmpt configurations (SDIDLEN, maximum mmpt.MODE) supported by
 * the platform.
 */
static int sbi_hart_smmpt_detect(void)
{
    unsigned long mmpt = 0, old_mmpt = 0;
    uint32_t sdid_value, mode_value = SMMPT_BARE;
    int rc = SBI_OK;

    old_mmpt = csr_read(CSR_MMPT);

    mmpt = INSERT_FIELD(mmpt, MMPT_SDID_MASK, MMPT_SDID_MAX);

    for (u32 i = SMMPT_MAX - 1; i > SMMPT_BARE; i--) {
        mmpt = INSERT_FIELD(mmpt, MMPT_MODE_MASK, i);
        csr_write(CSR_MMPT, mmpt);

        mmpt = csr_read(CSR_MMPT);
        mode_value = EXTRACT_FIELD(mmpt, MMPT_MODE_MASK);
        if (mode_value == i)
            break;
    }

    /* We don't support Bare-mode only Smmpt. */
    if (mode_value == SMMPT_BARE) {
        rc = SBI_ENOTSUPP;
        goto done;
    }

    sdid_value = EXTRACT_FIELD(mmpt, MMPT_SDID_MASK);
    mpt_sdidlen = sdid_value ? sbi_fls(sdid_value) + 1 : 0;
    mpt_mode = mode_value;
    mpt_pg_levels = mpt_mode + ((__riscv_xlen == 32) ? 1 : 2);

done:
    csr_write(CSR_MMPT, old_mmpt);
    mfence_pa_all();

    return rc;
}

static int domain_smmpt_alloc_root_page(unsigned long **mpt)
{
    unsigned long pgtable_size = sbi_hart_smmpt_page_table_size(mpt_pg_levels - 1);

    *mpt = sbi_aligned_alloc_from(smmpt_hpctrl, pgtable_size, pgtable_size);
    if (!*mpt)
        return SBI_ENOMEM;

    sbi_memset(*mpt, 0, pgtable_size);

    return SBI_OK;
}

static int domain_smmpt_state_data_setup(struct sbi_domain *dom,
                struct sbi_domain_data *data, void *data_ptr)
{
    struct smmpt_state *s = (struct smmpt_state *)data_ptr;
    int rc;

    if (sdid_next == BIT(mpt_sdidlen))
        return SBI_EBAD_RANGE;

    s->sdid = sdid_next++;

    SPIN_LOCK_INIT(s->mpt_lock);
    ATOMIC_INIT(&s->mpt_populate_state, MPT_STATE_NOT_POPULATED);

    rc = domain_smmpt_alloc_root_page(&s->mpt);
    if (rc)
        return rc;

    return SBI_OK;
}

static void domain_smmpt_state_data_cleanup(struct sbi_domain *dom,
                struct sbi_domain_data *data, void *data_ptr)
{
    struct smmpt_state *s = (struct smmpt_state *)data_ptr;

    /* Free root page table. */
    if (s->mpt)
        sbi_free_from(smmpt_hpctrl, s->mpt);
}

static struct sbi_domain_data dmspriv = {
    .data_size = sizeof(struct smmpt_state),
    .data_setup = domain_smmpt_state_data_setup,
    .data_cleanup = domain_smmpt_state_data_cleanup,
};

static int sbi_hart_smmpt_hart_install_mpt(struct smmpt_state *s)
{
    unsigned long mmpt = 0;
    unsigned long ppn;

    if (!s->mpt) {
        return SBI_EINVAL;
    }

    ppn = (unsigned long)s->mpt >> PAGE_SHIFT;
    if (ppn > MMPT_PPN_MAX)
        return SBI_EINVALID_ADDR;

    mmpt = INSERT_FIELD(mmpt, MMPT_PPN_MASK, ppn);
    mmpt = INSERT_FIELD(mmpt, MMPT_SDID_MASK, s->sdid);
    mmpt = INSERT_FIELD(mmpt, MMPT_MODE_MASK, mpt_mode);
    csr_write(CSR_MMPT, mmpt);
    mfence_pa_sdid(s->sdid);

    return SBI_OK;
}

static inline void sbi_hart_smmpt_hart_uninstall_mpt(struct smmpt_state *s)
{
    if (!s)
        return;

    csr_write(CSR_MMPT, 0);
    mfence_pa_all();
}

/*
 * Invalidate or free the MPTEs on the address path for the given address range.
 *
 * Note: Must be called with smmpt_state->mpt_lock held.
 */
static int __sbi_hart_smmpt_zap_mpte(u32 sdid, unsigned long addr,
                unsigned long size,  unsigned long *mptep,
                u32 current_level, unsigned long *zap_size,
                bool *need_fence, bool free_pages)
{
    unsigned long *next_mptep, ppn;
    u32 num_next_mptes, start_pg, num_pages;
    bool free_next_pgtable = true;
    int rc;

    if (!mptep || !*mptep) {
        return SBI_EINVAL;
    } else if (sbi_hart_smmpt_is_leaf_mpte(*mptep)) {
        start_pg = sbi_hart_smmpt_start_pg(addr, current_level);
        num_pages = MIN(size >> PAGE_SHIFT, PAGES_PER_MPTE - start_pg);
        *zap_size = (unsigned long)num_pages << PAGE_SHIFT;

        if (start_pg == 0 && num_pages == PAGES_PER_MPTE) {
            /* Clear the whole leaf MPTE. */
            *mptep = 0;
        } else {
            /* Clear the corresponding MPTE XWR bits. */
            sbi_hart_smmpt_mpte_set_xwr(mptep, false, 0, start_pg, num_pages);
        }

        *need_fence = true;
        return SBI_OK;
    } else {
        ppn = sbi_hart_smmpt_mpte_ppn(*mptep);
        next_mptep = (unsigned long *)(ppn << PAGE_SHIFT);
        current_level -= 1;
        num_next_mptes = 1 << ((current_level == 0) ? mpt_pte_indexes : 9);

        /* Zap the child MPTE on the given address path. */
        rc = __sbi_hart_smmpt_zap_mpte(sdid, addr, size,
            &next_mptep[sbi_hart_smmpt_mpte_pn(addr, current_level)],
            current_level, zap_size, need_fence, free_pages);
        if (rc)
            return rc;

        if (!free_pages)
            return SBI_OK;

        /* If all child MPTEs are empty, free the child page table. */
        for (u32 i = 0; i < num_next_mptes; i++) {
            if (next_mptep[i]) {
                free_next_pgtable = false;
                break;
            }
        }

        if (free_next_pgtable) {
            /*
             * Child page table is empty. Clear the parent non-leaf MPTE first,
             * then fence before freeing the child table so hardware cannot
             * walk through a stale non-leaf MPTE into freed memory.
             */
            *mptep = 0;

            mfence_pa_sdid(sdid);
            *need_fence = false;

            /* Free child page table after it is unreachable. */
            sbi_free_from(smmpt_hpctrl, next_mptep);
        }

        return SBI_OK;
    }
}

/*
 * Invalidate or remove the Smmpt mappings for the given address range.
 *
 * Note: Must be called with smmpt_state->mpt_lock held.
 */
static int __sbi_hart_smmpt_unmap_pages(unsigned long *mpt, u32 sdid,
                unsigned long addr, unsigned long size, bool free_pages)
{
    unsigned long cur_addr = addr;
    unsigned long remaining = size;
    unsigned long *next_mptep, *mptep, zap_size;
    bool need_fence;
    u32 level;
    int rc;

    rc = sbi_hart_smmpt_check_addr_size(addr, size, PAGE_SHIFT);
    if (rc)
        return rc;

    if (!mpt) {
        return SBI_EINVAL;
    }

    while (remaining) {
        /*
         * level (starting from index 0):
         *   Smmpt34 = 1
         *   Smmpt43,52,64 = 2, 3, 4
         */
        level = mpt_pg_levels - 1;
        next_mptep = mpt;
        mptep = &next_mptep[sbi_hart_smmpt_mpte_pn(cur_addr, level)];

        if (!*mptep)
            return SBI_EINVAL;

        need_fence = false;
        rc = __sbi_hart_smmpt_zap_mpte(sdid, cur_addr, remaining, mptep, level,
                &zap_size, &need_fence, free_pages);
        if (rc)
            return rc;

        if (need_fence)
            mfence_pa_sdid(sdid);

        cur_addr += zap_size;
        remaining -= zap_size;
    }

    return SBI_OK;
}

/*
 * Install one MPTE for the given address at the target level.
 *
 * Walks from the root MPT to the target level, allocating intermediate
 * page tables as needed. Fails if the walk crosses an existing leaf MPTE
 * or if the target MPTE is already a non-leaf MPTE.
 *
 * Note: Must be called with smmpt_state->mpt_lock held.
 */
static int __sbi_hart_smmpt_set_mpte(unsigned long *mpt, u32 sdid,
                u32 target_level, unsigned long addr, unsigned long new_mpte,
                unsigned long mpte_mask)
{
    /*
     * current_level (starting from index 0):
     *   Smmpt34 = 1
     *   Smmpt43,52,64 = 2, 3, 4
     */
    u32 current_level = mpt_pg_levels - 1;
    unsigned long *next_mptep, *mptep;
    unsigned long pgtable_size, ppn, diff;

    if (current_level < target_level)
        return SBI_EINVAL;

    next_mptep = mpt;
    mptep = &next_mptep[sbi_hart_smmpt_mpte_pn(addr, current_level)];

    while (current_level != target_level) {
        if (sbi_hart_smmpt_is_leaf_mpte(*mptep))
            return SBI_EALREADY;

        if (!*mptep) {
            /* Allocate child page table. */
            pgtable_size = sbi_hart_smmpt_page_table_size(current_level - 1);
            next_mptep = sbi_aligned_alloc_from(smmpt_hpctrl,
                pgtable_size, pgtable_size);

            if (!next_mptep)
                return SBI_ENOMEM;

            sbi_memset(next_mptep, 0, pgtable_size);
            sbi_hart_smmpt_nonleaf_mpte(mptep,
                (unsigned long)next_mptep >> PAGE_SHIFT);
        } else {
            ppn = sbi_hart_smmpt_mpte_ppn(*mptep);
            next_mptep = (unsigned long *)(ppn << PAGE_SHIFT);
        }

        mptep = &next_mptep[sbi_hart_smmpt_mpte_pn(addr, --current_level)];
    }

    if (*mptep && !sbi_hart_smmpt_is_leaf_mpte(*mptep))
        return SBI_EALREADY;

    new_mpte = (*mptep & ~mpte_mask) | (new_mpte & mpte_mask);
    diff = new_mpte ^ *mptep;

    if (diff) {
        *mptep = new_mpte;

        /*
         * Fence is not required when the change is from invalid to valid only.
         * Otherwise, fence is required.
         */
        if (!((diff & MPTE_VALID) && (new_mpte & MPTE_VALID))) {
            mfence_pa(addr, sdid);
        }
    }

    return SBI_OK;
}

/*
 * Create the Smmpt mappings for the given address range.
 *
 * Note: Must be called with smmpt_state->mpt_lock held.
 */
static int __sbi_hart_smmpt_map_pages(unsigned long *mpt, u32 sdid,
                unsigned long addr, unsigned long size, unsigned long flags)
{
    unsigned long cur_addr = addr;
    unsigned long remaining = size;
    unsigned long map_size = 0;
    u32 xwr, start_pg, num_pages;
    unsigned long mpte, pages_size, mpte_mask;
    int rc, rollback_rc;

    rc = sbi_hart_smmpt_check_addr_size(addr, size, PAGE_SHIFT);
    if (rc)
        return rc;

    rc = sbi_hart_smmpt_flags_to_xwr(flags, &xwr);
    if (rc)
        return rc;

    if (!mpt) {
        return SBI_OK;
    }

    while (remaining) {
        start_pg = sbi_hart_smmpt_start_pg(addr, 0);
        num_pages = MIN(remaining >> PAGE_SHIFT, PAGES_PER_MPTE - start_pg);
        pages_size = (unsigned long)num_pages << PAGE_SHIFT;

        mpte = 0;
        rc = sbi_hart_smmpt_leaf_mpte(&mpte, false, xwr, start_pg, num_pages);
        if (rc)
            return rc;

        /* Mask out the XWR bits that are not being set. */
        mpte_mask = MPTE_VALID | MPTE_LEAF |
            sbi_hart_smmpt_mpte_xwr_mask(false, start_pg, num_pages);
        rc = __sbi_hart_smmpt_set_mpte(mpt, sdid, 0, cur_addr, mpte, mpte_mask);
        if (rc)
            goto rollback;

        cur_addr += pages_size;
        remaining -= pages_size;
        map_size += pages_size;
    }

    return SBI_OK;

rollback:
    /* Something goes wrong, rollback the Smmpt mappings we've created. */
    if (map_size) {
        rollback_rc = __sbi_hart_smmpt_unmap_pages(mpt, sdid,
                            addr, map_size, true);
        if (rollback_rc)
            sbi_panic("%s: failed to rollback Smmpt mapping "
                  "0x%lx-0x%lx (map error %d, rollback error %d)\n",
                  __func__, addr, addr + map_size - 1,
                  rc, rollback_rc);
    }

    return rc;
}

/*
 * Return the representable end address of a range.
 */
static unsigned long sbi_hart_smmpt_range_end(unsigned long cur,
                unsigned long end)
{
    /*
     * The inclusive span [0, ~0UL] cannot be represented by unsigned long size.
     * Split off the final 4 KiB page so each size passed to the map()/unmap()
     * is representable.
     */
    if (cur == 0 && end == ~0UL)
        return ~0UL - PAGE_SIZE;

    return end;
}

static int sbi_hart_smmpt_unmap_range(struct smmpt_state *s,
                unsigned long base, unsigned long end, bool free_pages)
{
    unsigned long cur = base, next, size;
    int rc;

    while (cur <= end) {
        next = sbi_hart_smmpt_range_end(cur, end);
        size = next - cur + 1;

        rc = __sbi_hart_smmpt_unmap_pages(s->mpt, s->sdid, cur, size,
                        free_pages);
        if (rc)
            return rc;

        if (next == end)
            break;

        cur = next + 1;
    }

    return SBI_OK;
}

static int sbi_hart_smmpt_map_range(struct smmpt_state *s,
                unsigned long base, unsigned long end, unsigned long flags)
{
    unsigned long cur = base, next, size;
    int rc, rollback_rc;

    while (cur <= end) {
        next = sbi_hart_smmpt_range_end(cur, end);
        size = next - cur + 1;

        rc = __sbi_hart_smmpt_map_pages(s->mpt, s->sdid, cur, size, flags);
        if (rc) {
            if (cur != base) {
                rollback_rc = sbi_hart_smmpt_unmap_range(s, base, cur - 1, true);
                if (rollback_rc)
                    sbi_panic("%s: failed to rollback Smmpt mapping "
                          "0x%lx-0x%lx (map error %d, "
                          "rollback error %d)\n", __func__,
                          base, cur - 1, rc, rollback_rc);
            }

            return rc;
        }

        if (next == end)
            break;

        cur = next + 1;
    }

    return SBI_OK;
}

/*
 * Create the Smmpt mappings for the given flatten memory region.
 */
static int sbi_hart_smmpt_map_freg(struct smmpt_state *s,
                struct sbi_domain_flatten_memregion *freg)
{
    unsigned long end = MIN(freg->end, sbi_hart_smmpt_max_addr());

    /*
     * Do not create Smmpt mappings that exceed the maximum
     * physical address space it can support.
     */
    if (freg->base > end)
        return SBI_OK;

    return sbi_hart_smmpt_map_range(s, freg->base, end, freg->region->flags);
}

/*
 * Invalidate or remove the Smmpt mappings for the given flatten memory region.
 */
static int sbi_hart_smmpt_unmap_freg(struct smmpt_state *s,
                struct sbi_domain_flatten_memregion *freg)
{
    unsigned long end = MIN(freg->end, sbi_hart_smmpt_max_addr());

    if (freg->base > end)
        return SBI_OK;

    return sbi_hart_smmpt_unmap_range(s, freg->base, end, true);
}

static int sbi_hart_smmpt_configure(struct sbi_scratch *scratch)
{
    struct sbi_domain_flatten_memregion *freg, *rollback_freg;
    struct sbi_domain *dom = sbi_domain_thishart_ptr();
    struct smmpt_state *s = sbi_domain_data_ptr(dom, &dmspriv);
    int rc, rollback_rc;
    long populate_state;

    if (!s)
        return SBI_EINVAL;

    /*
     * Atomically try to claim the right to populate the MPT.
     * Only transition from NOT_POPULATED -> POPULATING is allowed here.
     */
    populate_state = atomic_cmpxchg(&s->mpt_populate_state,
                                    MPT_STATE_NOT_POPULATED,
                                    MPT_STATE_POPULATING);

    if (populate_state == MPT_STATE_NOT_POPULATED) {
        /* This hart won the race and will populate the MPT. */
        spin_lock(&s->mpt_lock);

        /* Create the Smmpt mappings of the flatten regions for the domain. */
        sbi_list_for_each_entry(freg, &dom->flatten_list, node) {
            rc = sbi_hart_smmpt_map_freg(s, freg);
            if (rc)
                goto rollback;
        }

        spin_unlock(&s->mpt_lock);

        /*
         * Mark as POPULATED with barrier to ensure all writes are visible
         * to other harts.
         */
        smp_wmb();
        atomic_write(&s->mpt_populate_state, MPT_STATE_POPULATED);
    } else if (populate_state == MPT_STATE_POPULATING) {
        /*
         * Another hart is currently populating MPT,
         * wait for MPT to be populated.
         */
        while (atomic_read(&s->mpt_populate_state) == MPT_STATE_POPULATING)
            cpu_relax();

        /* Recheck the state after exiting wait loop. */
        populate_state = atomic_read(&s->mpt_populate_state);
        if (populate_state == MPT_STATE_FAILED) {
            /* Another hart tried and failed - propagate error. */
            sbi_printf("Smmpt: hart%d detected MPT population"
                    " failure for domain '%s' sdid=%u\n",
                    current_hartid(), dom->name, s->sdid);
            return SBI_EFAIL;
        } else if (populate_state != MPT_STATE_POPULATED) {
            /* Unexpected state - should never happen. */
            sbi_printf("Smmpt: hart%d detected unexpected MPT"
                    " state %ld for domain '%s' sdid=%u\n",
                    current_hartid(), populate_state,
                    dom->name, s->sdid);
            return SBI_EFAIL;
        }
    } else if (populate_state == MPT_STATE_FAILED) {
        /* Another hart already tried and failed permanently. */
        sbi_printf("Smmpt: hart%d found domain '%s' sdid=%u"
                " in FAILED state\n",
                current_hartid(), dom->name, s->sdid);
        return SBI_EFAIL;
    }
    /*
     * else populate_state == MPT_STATE_POPULATED,
     * MPT is already populated.
     */

    /* Install the populated MPT on this hart. */
    rc = sbi_hart_smmpt_hart_install_mpt(s);

    return rc;

rollback:
    /* Something goes wrong, rollback the Smmpt mappings we've created. */
    sbi_list_for_each_entry(rollback_freg, &dom->flatten_list, node) {
        if (rollback_freg == freg)
            break;

        rollback_rc = sbi_hart_smmpt_unmap_freg(s, rollback_freg);
        if (rollback_rc)
            sbi_panic("%s: failed to rollback Smmpt mapping "
                "0x%lx-0x%lx (map error %d, rollback error %d)\n",
                __func__, rollback_freg->base, rollback_freg->end, rc,
                rollback_rc);
    }

    /* Mark as FAILED so other harts don't retry the persistent error. */
    smp_wmb();
    atomic_write(&s->mpt_populate_state, MPT_STATE_FAILED);
    sbi_printf("Smmpt: hart%d failed to populate MPT"
            " for domain '%s' sdid=%u (error %d)\n",
            current_hartid(), dom->name, s->sdid, rc);
    spin_unlock(&s->mpt_lock);

    return rc;
}

static void sbi_hart_smmpt_unconfigure(struct sbi_scratch *scratch)
{
    struct sbi_domain *dom = sbi_domain_thishart_ptr();
    struct smmpt_state *s = sbi_domain_data_ptr(dom, &dmspriv);

    sbi_hart_smmpt_hart_uninstall_mpt(s);
}

static struct sbi_hart_protection smmpt_protection = {
    .name = "smmpt",
    .group_id = SBI_HART_PROT_GROUP_SMMPT,
    .rating = 100,
    .configure = sbi_hart_smmpt_configure,
    .unconfigure = sbi_hart_smmpt_unconfigure,
};

int sbi_hart_smmpt_init(struct sbi_scratch *scratch)
{
    int rc;

    if (sbi_hart_has_extension(scratch, SBI_HART_EXT_SMSDID) &&
        sbi_hart_has_extension(scratch, SBI_HART_EXT_SMMPT)) {
        rc = sbi_hart_smmpt_detect();
        if (rc)
            return rc;

        rc = sbi_domain_register_data(&dmspriv);
        if (rc)
            return rc;

        rc = sbi_hart_protection_register(&smmpt_protection);
        if (rc)
            return rc;
    }

    return SBI_OK;
}
