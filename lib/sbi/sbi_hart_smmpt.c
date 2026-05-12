/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 SiFive Inc.
 */

#include <libfdt.h>
#include <sbi/sbi_bitmap.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_domain.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_hart_protection.h>
#include <sbi/sbi_heap.h>
#include <sbi/sbi_math.h>
#include <sbi/sbi_platform.h>
#include <sbi/sbi_types.h>
#include <sbi_utils/fdt/fdt_helper.h>
#include <sbi/riscv_asm.h>
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
    /** Spinlock for accessing MPT tables */
    spinlock_t mpt_lock;
    /** Flag indicates that domain MPT tables have been populated */
    bool mpt_populated;
};

static u32 mpt_sdidlen;
static mpt_mode_t mpt_mode;
static u32 mpt_pg_levels;

static u32 sdid_next = 0;

struct sbi_heap_control *smmpt_hpctrl;

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

    memset(*mpt, 0, pgtable_size);

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
    s->mpt_populated = false;

    rc = domain_smmpt_alloc_root_page(&s->mpt);
    if (rc)
        return rc;

    sbi_dprintf("Smmpt: create root page table dom=%s sdid=%u "
            "mpt=%p size=0x%lx level=%u\n",
            dom->name, s->sdid, s->mpt,
            sbi_hart_smmpt_page_table_size(mpt_pg_levels - 1),
            mpt_pg_levels - 1);

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

/* Note: Must be called with smmpt_state->mpt_lock held. */
static int __sbi_hart_smmpt_hart_install_mpt(struct smmpt_state *s)
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
    mfence_pa_sdid(s->sdid);
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
    u32 num_next_mptes, start_pg, page_order, num_pages;
    bool free_next_pgtable = true;
    int rc;

    if (!mptep || !*mptep) {
        return SBI_EINVAL;
    } else if (sbi_hart_smmpt_is_leaf_mpte(*mptep)) {
        page_order = sbi_hart_smmpt_page_order(current_level);

        if (sbi_hart_smmpt_is_napot_mpte(*mptep)) {
            /* Check if the address is aligned to NAPOT page size. */
            rc = sbi_hart_smmpt_check_addr_size(addr, size,
                page_order + NAPOT_NUM_PAGES_ORDER);
            if (rc)
                return rc;

            *zap_size = BIT(page_order + NAPOT_NUM_PAGES_ORDER);

            /* Clear all NAPOT leaf MPTEs. */
            for (u32 i = 0; i < (1 << (NAPOT_G + 1)); i++)
                mptep[i] = 0;
        } else {
            /* Check if the address is aligned to non-NAPOT page size. */
            rc = sbi_hart_smmpt_check_addr_size(addr, size, page_order);
            if (rc)
                return rc;

            start_pg = sbi_hart_smmpt_start_pg(addr, current_level);
            num_pages = MIN(size >> page_order, PAGES_PER_MPTE - start_pg);
            *zap_size = (unsigned long)num_pages << page_order;

            if (start_pg == 0 && num_pages == PAGES_PER_MPTE) {
                /* Clear the whole leaf MPTE. */
                *mptep = 0;
            } else {
                /* Clear the corresponding MPTE XWR bits. */
                sbi_hart_smmpt_mpte_set_xwr(mptep, false, 0, start_pg, num_pages);
            }
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
 * Resolve one mapping chunk within a single MPTE. The resolved mapping must not
 * cross the address span covered by one MPTE at the selected level.
 *
 * When @force_4k is false, resolve one MPTE-sized mapping from the highest
 * level down. At each level, try NAPOT first, then a non-NAPOT leaf. If neither
 * fits, descend to the next lower level.
 * The returned mapping never crosses the current MPTE span.
 *   - For NAPOT mapping, the address must be aligned to the NAPOT page size.
 *   - For hugepage non-NAPOT mapping, the address must be aligned to the
 *     hugepage size, and cannot be partially mapped within the MPTE span.
 *   - For normal non-NAPOT 4 KiB mapping, the address must be aligned to 4 KiB,
 *     and can be partially mapped within the MPTE span.
 *
 * When @force_4k is true, resolve one MPTE-sized mapping using non-NAPOT
 * 4 KiB mapping only.
 */
static int sbi_hart_smmpt_resolve_map_mpte(unsigned long addr,
                unsigned long size, bool force_4k, u32 *out_level,
                u32 *out_start_pg, u32 *out_num_pages, bool *out_napot)
{
    u32 current_level, num_pages = 0;
    bool napot = false;
    u32 page_order = PAGE_SHIFT;
    u32 mpte_span_order, napot_page_order, start_pg;

    /*
     * current_level (starting from index 0):
     *   Smmpt34 = 1
     *   Smmpt43,52,64 = 2, 3, 4
     */
    current_level = force_4k ? 0 : (mpt_pg_levels - 1);
    page_order = sbi_hart_smmpt_page_order(current_level);
    mpte_span_order = page_order + NUM_PG_BITS_IN_RANGE;
    napot_page_order = page_order + NAPOT_NUM_PAGES_ORDER;

    /* Try to map using hugepage or NAPOT. */
    while (true) {
        /*
         * Check if we could map with NAPOT.
         * It's pointless for Smmpt34 to map with NAPOT at level 1
         * as it creates a 4 GiB mapping.
         */
        if (!force_4k &&
            !(__riscv_xlen == 32 && current_level == (mpt_pg_levels - 1))) {
            /* Check if addr is aligned to NAPOT page size. */
            if (sbi_hart_smmpt_check_addr_size(addr, size,
                    napot_page_order)) {
                goto hugepage;
            }

            /* Map at most one NAPOT. */
            napot = true;
            start_pg = 0;
            /* NAPOT is comprised of 2^(G+1) MPTEs. */
            num_pages = NAPOT_NUM_PAGES;
            goto resolved;
        }

hugepage:
        if (current_level == 0)
            break;

        /*
         * Hugepage MPTEs can be either leaf or non-leaf. If a range
         * starts in the middle of such an MPTE span, use a lower-level
         * table so the same MPTE slot is not used as both leaf and non-leaf.
         * Level-0 has no child table, so partial mapping within the MPTE span
         * is fine.
         */
        if (!sbi_hart_smmpt_check_addr_size(addr, size, mpte_span_order))
            break;

        /* Try to map with next lower-level mapping. */
        page_order -= (current_level == 1) ? mpt_pte_indexes : 9;
        mpte_span_order = page_order + NUM_PG_BITS_IN_RANGE;
        napot_page_order = page_order + NAPOT_NUM_PAGES_ORDER;
        current_level--;
    }

    /* Map within the current MPTE span. */
    start_pg = sbi_hart_smmpt_start_pg(addr, current_level);
    num_pages = MIN(size >> page_order, PAGES_PER_MPTE - start_pg);
    if (!num_pages)
        return SBI_EINVAL;

resolved:
    if (out_level)
        *out_level = current_level;

    if (out_start_pg)
        *out_start_pg = start_pg;

    if (out_num_pages)
        *out_num_pages = num_pages;

    if (out_napot)
        *out_napot = napot;

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
    unsigned long *next_mptep, *mptep, old_mpte;
    unsigned long pgtable_size, ppn, diff;

    if (current_level < target_level) {
        sbi_dprintf("Smmpt: invalid MPTE level sdid=%u addr=0x%lx "
                "root_level=%u target_level=%u new=0x%lx\n",
                sdid, addr, current_level, target_level, new_mpte);
        return SBI_EINVAL;
    }

    next_mptep = mpt;
    mptep = &next_mptep[sbi_hart_smmpt_mpte_pn(addr, current_level)];

    while (current_level != target_level) {
        if (sbi_hart_smmpt_is_leaf_mpte(*mptep)) {
            sbi_dprintf("Smmpt: failed to set non-leaf MPTE sdid=%u "
                    "current_level=%u target_level=%u addr=0x%lx mptep=%p "
                    "mpte=0x%lx reason=leaf-conflict\n",
                    sdid, current_level, target_level, addr, mptep, *mptep);
            return SBI_EALREADY;
        }

        if (!*mptep) {
            /* Allocate child page table. */
            pgtable_size = sbi_hart_smmpt_page_table_size(current_level - 1);
            next_mptep = sbi_aligned_alloc_from(smmpt_hpctrl,
                pgtable_size, pgtable_size);

            if (!next_mptep) {
                sbi_dprintf("Smmpt: failed to set non-leaf MPTE sdid=%u "
                        "current_level=%u target_level=%u addr=0x%lx mptep=%p "
                        "child_size=0x%lx reason=out-of-memory\n",
                        sdid, current_level, target_level, addr, mptep,
                        pgtable_size);
                return SBI_ENOMEM;
            }

            memset(next_mptep, 0, pgtable_size);
            sbi_hart_smmpt_nonleaf_mpte(mptep,
                (unsigned long)next_mptep >> PAGE_SHIFT);
            sbi_dprintf("Smmpt: set non-leaf MPTE sdid=%u current_level=%u "
                    "addr=0x%lx mptep=%p child=%p child_size=0x%lx mpte=0x%lx\n",
                    sdid, current_level, addr, mptep, next_mptep,
                    pgtable_size, *mptep);
        } else {
            ppn = sbi_hart_smmpt_mpte_ppn(*mptep);
            next_mptep = (unsigned long *)(ppn << PAGE_SHIFT);
        }

        mptep = &next_mptep[sbi_hart_smmpt_mpte_pn(addr, --current_level)];
    }

    if (*mptep && !sbi_hart_smmpt_is_leaf_mpte(*mptep)) {
        sbi_dprintf("Smmpt: failed to set leaf MPTE sdid=%u current_level=%u "
                "napot=%u addr=0x%lx mptep=%p old=0x%lx new=0x%lx "
                "reason=non-leaf-conflict\n",
                sdid, current_level, sbi_hart_smmpt_is_napot_mpte(*mptep),
                addr, mptep, *mptep, new_mpte);
        return SBI_EALREADY;
    }

    /*
     * Reject replacing an existing valid leaf MPTE with another valid leaf MPTE
     * that uses a different NAPOT encoding. Clearing a leaf MPTE with zero is
     * allowed, so skip this check when the new MPTE is invalid.
     */
    if (sbi_hart_smmpt_is_valid_mpte(*mptep) &&
        sbi_hart_smmpt_is_valid_mpte(new_mpte) &&
        (sbi_hart_smmpt_is_napot_mpte(*mptep) !=
            sbi_hart_smmpt_is_napot_mpte(new_mpte))) {
        sbi_dprintf("Smmpt: failed to set leaf MPTE sdid=%u current_level=%u "
                "napot=%u addr=0x%lx mptep=%p old=0x%lx new=0x%lx "
                "reason=napot-conflict\n",
                sdid, current_level, sbi_hart_smmpt_is_napot_mpte(*mptep),
                addr, mptep, *mptep, new_mpte);
        return SBI_EALREADY;
    }

    old_mpte = *mptep;
    new_mpte = (*mptep & ~mpte_mask) | (new_mpte & mpte_mask);
    diff = new_mpte ^ *mptep;

    if (diff) {
        *mptep = new_mpte;
        sbi_dprintf("Smmpt: set leaf MPTE sdid=%u current_level=%u napot=%u "
                "addr=0x%lx mptep=%p old=0x%lx new=0x%lx\n",
                sdid, current_level, sbi_hart_smmpt_is_napot_mpte(new_mpte),
                addr, mptep, old_mpte, new_mpte);

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
                unsigned long addr, unsigned long size, unsigned long flags,
                bool force_4k)
{
    unsigned long cur_addr = addr, napot_cur_addr;
    unsigned long remaining = size;
    unsigned long map_size = 0;
    u32 xwr, level, start_pg, num_pages, page_order, i, rollback_i;
    bool napot;
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
        rc = sbi_hart_smmpt_resolve_map_mpte(cur_addr, remaining, force_4k,
                        &level, &start_pg, &num_pages, &napot);
        if (rc)
            return rc;

        page_order = sbi_hart_smmpt_page_order(level);
        pages_size = (unsigned long)num_pages << page_order;

        mpte = 0;
        rc = sbi_hart_smmpt_leaf_mpte(&mpte, napot, xwr, start_pg, num_pages);
        if (rc)
            return rc;

        if (napot) {
            mpte_mask = MPTE_VALID | MPTE_LEAF | MPTE_NAPOT | MPTE_G |
                (MPTE_XWR_MASK << MPTE_XWR_SHIFT);

            /* NAPOT is comprised of 2^(G+1) MPTEs. */
            for (i = 0; i < num_pages; i += PAGES_PER_MPTE) {
                napot_cur_addr = cur_addr + ((unsigned long)i << page_order);

                rc = __sbi_hart_smmpt_set_mpte(mpt, sdid, level,
                        napot_cur_addr, mpte, mpte_mask);
                if (rc) {
                    /*
                     * Rollback only the NAPOT MPTEs installed by this call.
                     * The failed slot may belong to an existing mapping, so
                     * do not zap the whole NAPOT range here.
                     */
                    for (rollback_i = 0; rollback_i < i;
                         rollback_i += PAGES_PER_MPTE) {
                        napot_cur_addr = cur_addr + \
                            ((unsigned long)rollback_i << page_order);

                        rollback_rc = __sbi_hart_smmpt_set_mpte(mpt, sdid, level,
                                        napot_cur_addr, 0, mpte_mask);
                        if (rollback_rc)
                            sbi_panic("%s: failed to rollback Smmpt NAPOT "
                                "MPTE addr=0x%lx (map error %d, "
                                "rollback error %d)\n", __func__,
                                cur_addr + ((unsigned long)rollback_i <<
                                page_order), rc, rollback_rc);
                    }

                    if (i)
                        mfence_pa_sdid(sdid);

                    goto rollback;
                }
            }
        } else {
            /* Mask out the XWR bits that are not being set. */
            mpte_mask = MPTE_VALID | MPTE_LEAF |
                sbi_hart_smmpt_mpte_xwr_mask(false, start_pg, num_pages);
            rc = __sbi_hart_smmpt_set_mpte(mpt, sdid, level, cur_addr, mpte,
                    mpte_mask);
            if (rc)
                goto rollback;
        }

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
                unsigned long base, unsigned long end, unsigned long flags,
                bool force_4k)
{
    unsigned long cur = base, next, size;
    int rc, rollback_rc;

    while (cur <= end) {
        next = sbi_hart_smmpt_range_end(cur, end);
        size = next - cur + 1;

        rc = __sbi_hart_smmpt_map_pages(s->mpt, s->sdid, cur, size,
                        flags, force_4k);
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
     * Do not map Smmpt page-table backing memory through Smmpt itself.
     * This avoids recursive mappings; PMP/Smepmp protects this M-mode-only
     * region from S/U-mode.
     */
    if (freg->region->flags & SBI_DOMAIN_MEMREGION_SMMPT)
        return SBI_OK;

    /*
     * Do not create Smmpt mappings that exceed the maximum
     * physical address space it can support.
     */
    if (freg->base > end)
        return SBI_OK;

    return sbi_hart_smmpt_map_range(s, freg->base, end,
                freg->region->flags, false);
}

/*
 * Invalidate or remove the Smmpt mappings for the given flatten memory region.
 */
static int sbi_hart_smmpt_unmap_freg(struct smmpt_state *s,
                struct sbi_domain_flatten_memregion *freg)
{
    unsigned long end = MIN(freg->end, sbi_hart_smmpt_max_addr());

    if (freg->region->flags & SBI_DOMAIN_MEMREGION_SMMPT)
        return SBI_OK;

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

    if (!s)
        return SBI_EINVAL;

    spin_lock(&s->mpt_lock);

    /* Create the Smmpt mappings of the flatten regions for the domain. */
    if (!s->mpt_populated) {
        sbi_list_for_each_entry(freg, &dom->flatten_list, node) {
            rc = sbi_hart_smmpt_map_freg(s, freg);
            if (rc)
                goto rollback;
        }

        s->mpt_populated = true;
    }

    rc = __sbi_hart_smmpt_hart_install_mpt(s);

    spin_unlock(&s->mpt_lock);
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

    s->mpt_populated = false;
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

static int fdt_setup_smmpt(void)
{
    const void *fdt = fdt_get_address();
    u64 base64, size64;
    unsigned long base, size;
    int node;
    int rc;

    /* Parse the memory region reserved for Smmpt page table. */
    node = fdt_path_offset(fdt, "/reserved-memory");
    if (node < 0)
        return SBI_ENOENT;

    node = fdt_node_offset_by_compatible(fdt, node, "opensbi,smmpt");
    if (node < 0)
        return SBI_ENOENT;

    rc = fdt_get_node_addr_size(fdt, node, 0, &base64, &size64);
    if (rc)
        return rc;

    if (base64 > ~0UL || size64 > ~0UL)
        return SBI_EINVALID_ADDR;

    base = (unsigned long)base64;
    size = (unsigned long)size64;

    if (!size || (base & (PAGE_SIZE - 1)) || (size & (PAGE_SIZE - 1)))
        return SBI_EINVAL;

    rc = sbi_heap_alloc_new(&smmpt_hpctrl);
    if (rc)
        return rc;

    if (!smmpt_hpctrl)
        return SBI_ENOMEM;

    rc = sbi_heap_init_new(smmpt_hpctrl, base, size);
    if (rc) {
        sbi_free(smmpt_hpctrl);
        smmpt_hpctrl = NULL;
        return rc;
    }

    /*
     * Add the Smmpt page table memory region to the root domain.
     * Only M-mode can access this memory region and it is not accessible to
     * S/U-mode at all.
     * Also, mark it as the SMMPT memory region so that it won't be mapped by
     * Smmpt recursively.
     */
    rc = sbi_domain_root_add_memrange(base, size, PAGE_SIZE,
        SBI_DOMAIN_MEMREGION_M_READABLE | SBI_DOMAIN_MEMREGION_M_WRITABLE |
        SBI_DOMAIN_MEMREGION_SMMPT);
    if (rc) {
        sbi_free(smmpt_hpctrl);
        smmpt_hpctrl = NULL;
        return rc;
    }

    return SBI_OK;
}

int sbi_hart_smmpt_init(struct sbi_scratch *scratch)
{
    int rc;

    if (sbi_hart_has_extension(scratch, SBI_HART_EXT_SMSDID) &&
        sbi_hart_has_extension(scratch, SBI_HART_EXT_SMMPT)) {
        rc = sbi_hart_smmpt_detect();
        if (rc)
            return rc;

        rc = fdt_setup_smmpt();
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
