/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 SiFive Inc.
 */

#ifndef __SBI_HART_SMMPT_H__
#define __SBI_HART_SMMPT_H__

#include <sbi/sbi_scratch.h>
#include <sbi/riscv_asm.h>

#define mfence_pa(paddr, sdid) \
    do { \
        __asm__ __volatile__(".insn r 0x73, 0, 0x43, x0, %0, %1" \
            : \
            : "r"(paddr), "r"(sdid) \
            : "memory"); \
    } while (0)

#define mfence_pa_all() \
    do { \
        __asm__ __volatile__(".word 0x86000073" ::: "memory"); \
    } while (0)

#define mfence_pa_sdid(sdid) \
    do { \
        __asm__ __volatile__(".insn r 0x73, 0, 0x43, x0, x0, %0" \
            : \
            : "r"(sdid) \
            : "memory"); \
    } while (0)

#define mfence_pa_paddr(paddr) \
    do { \
        __asm__ __volatile__(".insn r 0x73, 0, 0x43, x0, %0, x0" \
            : \
            : "r"(paddr) \
            : "memory"); \
    } while (0)

#define sfence_w_inval() \
    do { \
        __asm__ __volatile__(".word 0x18000073" ::: "memory"); \
    } while (0)

#define sfence_inval_ir() \
    do { \
        __asm__ __volatile__(".word 0x18100073" ::: "memory"); \
    } while (0)

#define minval_pa(paddr, sdid) \
    do { \
        __asm__ __volatile__(".insn r 0x73, 0, 0x03, x0, %0, %1" \
            : \
            : "r"(paddr), "r"(sdid) \
            : "memory"); \
    } while (0)

#define minval_pa_all() \
    do { \
        __asm__ __volatile__(".word 0x06000073" ::: "memory"); \
    } while (0)

#define minval_pa_sdid(sdid) \
    do { \
        __asm__ __volatile__(".insn r 0x73, 0, 0x03, x0, x0, %0" \
            : \
            : "r"(sdid) \
            : "memory"); \
    } while (0)

#define minval_pa_paddr(paddr) \
    do { \
        __asm__ __volatile__(".insn r 0x73, 0, 0x03, x0, %0, x0" \
            : \
            : "r"(paddr) \
            : "memory"); \
    } while (0)

int sbi_hart_smmpt_init(struct sbi_scratch *scratch);

#endif /* __SBI_HART_SMMPT_H__ */
