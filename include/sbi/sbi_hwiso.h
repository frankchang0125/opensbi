/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * System-level hardware isolation framework
 *
 * Copyright (c) 2026 RISCstar Solutions Corporation.
 *
 * Author: Raymond Mao <raymond.mao@riscstar.com>
 */

#ifndef __SBI_HWISO_H__
#define __SBI_HWISO_H__

#include <sbi/sbi_types.h>

struct sbi_domain;

struct sbi_hwiso_ops {
	const char *name;

	/* Boot-time init */
	int (*init)(void *fdt);

	/* Per-domain init (domain_offset refers to domain instance node) */
	int (*domain_init)(void *fdt, int domain_offset,
			   struct sbi_domain *dom, void **ctx);

	/* Before switching away from a domain */
	void (*domain_exit)(const struct sbi_domain *src,
			    const struct sbi_domain *dst, void *ctx);

	/* After switching into a domain */
	void (*domain_enter)(const struct sbi_domain *dst,
			     const struct sbi_domain *src, void *ctx);

	/* Optional cleanup */
	void (*domain_cleanup)(struct sbi_domain *dom, void *ctx);
};

struct sbi_hwiso_domain_ctx {
	const struct sbi_hwiso_ops *ops;
	void *ctx;
};

int sbi_hwiso_register(const struct sbi_hwiso_ops *ops);

int sbi_hwiso_init(void *fdt);
int sbi_hwiso_domain_init(void *fdt, int domain_offset,
			  struct sbi_domain *dom);

void sbi_hwiso_domain_exit(const struct sbi_domain *src,
			   const struct sbi_domain *dst);
void sbi_hwiso_domain_enter(const struct sbi_domain *dst,
			    const struct sbi_domain *src);
void sbi_hwiso_domain_cleanup(struct sbi_domain *dom);

#endif /* __SBI_HWISO_H__ */
