/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * System-level hardware isolation framework
 *
 * Copyright (c) 2026 RISCstar Solutions Corporation.
 *
 * Author: Raymond Mao <raymond.mao@riscstar.com>
 */

#include <libfdt.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_domain.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_heap.h>
#include <sbi/sbi_hwiso.h>
#include <sbi/sbi_list.h>

struct sbi_hwiso_node {
	const struct sbi_hwiso_ops *ops;
	struct sbi_dlist node;
};

static SBI_LIST_HEAD(hwiso_ops_list);
static u32 hwiso_ops_count;

static bool hwiso_ops_registered(const struct sbi_hwiso_ops *ops)
{
	struct sbi_hwiso_node *entry;

	sbi_list_for_each_entry(entry, &hwiso_ops_list, node) {
		if (entry->ops == ops)
			return true;
	}

	return false;
}

int sbi_hwiso_register(const struct sbi_hwiso_ops *ops)
{
	struct sbi_hwiso_node *node;

	if (!ops || !ops->name)
		return SBI_EINVAL;

	if (hwiso_ops_registered(ops))
		return SBI_EALREADY;

	node = sbi_zalloc(sizeof(*node));
	if (!node)
		return SBI_ENOMEM;

	node->ops = ops;
	SBI_INIT_LIST_HEAD(&node->node);
	sbi_list_add_tail(&node->node, &hwiso_ops_list);
	hwiso_ops_count++;

	return 0;
}

int sbi_hwiso_init(void *fdt)
{
	struct sbi_hwiso_node *entry;
	int rc;

	sbi_list_for_each_entry(entry, &hwiso_ops_list, node) {
		if (!entry->ops->init)
			continue;

		rc = entry->ops->init(fdt);
		if (rc == SBI_ENOMEM)
			return rc;
		if (rc)
			sbi_printf("hwiso: %s init failed (error %d)\n",
				   entry->ops->name, rc);
	}

	return 0;
}

static void hwiso_warn_unknown_nodes(void *fdt, int domain_offset)
{
	int hoff, child;
	struct sbi_hwiso_node *entry;
	bool known;

	if (!fdt || (domain_offset < 0))
		return;

	hoff = fdt_subnode_offset(fdt, domain_offset, "hw-isolation");
	if (hoff < 0)
		return;

	fdt_for_each_subnode(child, fdt, hoff) {
		known = false;
		sbi_list_for_each_entry(entry, &hwiso_ops_list, node) {
			if (!fdt_node_check_compatible(
					fdt, child, entry->ops->name)) {
				known = true;
				break;
			}
		}

		if (!known)
			sbi_printf("hwiso: unknown mechanism at %s\n",
				   fdt_get_name(fdt, child, NULL));
	}
}

int sbi_hwiso_domain_init(void *fdt, int domain_offset,
			  struct sbi_domain *dom)
{
	struct sbi_hwiso_node *entry;
	struct sbi_hwiso_domain_ctx *ctxs;
	void *ctx;
	u32 idx = 0;
	int rc;

	if (!dom)
		return 0;

	if (!hwiso_ops_count) {
		hwiso_warn_unknown_nodes(fdt, domain_offset);
		return 0;
	}

	ctxs = sbi_calloc(sizeof(*ctxs), hwiso_ops_count);
	if (!ctxs)
		return SBI_ENOMEM;

	dom->hwiso_ctxs = ctxs;
	dom->hwiso_ctx_count = hwiso_ops_count;

	sbi_list_for_each_entry(entry, &hwiso_ops_list, node) {
		ctxs[idx].ops = entry->ops;
		ctxs[idx].ctx = NULL;
		ctx = NULL;

		if (entry->ops->domain_init) {
			rc = entry->ops->domain_init(fdt, domain_offset,
						     dom, &ctx);
			if (rc == SBI_ENOMEM) {
				sbi_hwiso_domain_cleanup(dom);
				return rc;
			}
			if (rc) {
				sbi_printf("hwiso: %s domain init failed"
					   " (error %d)\n",
					   entry->ops->name, rc);
				ctx = NULL;
			}
		}

		ctxs[idx].ctx = ctx;
		idx++;
	}

	hwiso_warn_unknown_nodes(fdt, domain_offset);

	return 0;
}

void sbi_hwiso_domain_exit(const struct sbi_domain *src,
			   const struct sbi_domain *dst)
{
	u32 i;

	if (!src || !src->hwiso_ctxs)
		return;

	for (i = 0; i < src->hwiso_ctx_count; i++) {
		if (!src->hwiso_ctxs[i].ops ||
		    !src->hwiso_ctxs[i].ops->domain_exit)
			continue;
		src->hwiso_ctxs[i].ops->domain_exit(
					src, dst, src->hwiso_ctxs[i].ctx);
	}
}

void sbi_hwiso_domain_enter(const struct sbi_domain *dst,
			    const struct sbi_domain *src)
{
	u32 i;

	if (!dst || !dst->hwiso_ctxs)
		return;

	for (i = 0; i < dst->hwiso_ctx_count; i++) {
		if (!dst->hwiso_ctxs[i].ops ||
		    !dst->hwiso_ctxs[i].ops->domain_enter)
			continue;
		dst->hwiso_ctxs[i].ops->domain_enter(
					dst, src, dst->hwiso_ctxs[i].ctx);
	}
}

void sbi_hwiso_domain_cleanup(struct sbi_domain *dom)
{
	u32 i;

	if (!dom || !dom->hwiso_ctxs)
		return;

	for (i = 0; i < dom->hwiso_ctx_count; i++) {
		if (!dom->hwiso_ctxs[i].ops ||
		    !dom->hwiso_ctxs[i].ops->domain_cleanup)
			continue;
		dom->hwiso_ctxs[i].ops->domain_cleanup(
					dom, dom->hwiso_ctxs[i].ctx);
	}

	sbi_free(dom->hwiso_ctxs);
	dom->hwiso_ctxs = NULL;
	dom->hwiso_ctx_count = 0;
}
