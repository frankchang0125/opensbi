/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Ventana Micro Systems Inc.
 */

#include <sbi/sbi_error.h>
#include <sbi/sbi_hart_protection.h>
#include <sbi/sbi_scratch.h>

static SBI_LIST_HEAD(hart_protection_list);

struct sbi_hart_protection *sbi_hart_protection_best(void)
{
	if (sbi_list_empty(&hart_protection_list))
		return NULL;

	return sbi_list_first_entry(&hart_protection_list, struct sbi_hart_protection, head);
}

int sbi_hart_protection_register(struct sbi_hart_protection *hprot)
{
	struct sbi_hart_protection *pos = NULL, *last_same_group = NULL;

	if (!hprot)
		return SBI_EINVAL;

	/*
	 * Keep providers grouped by group_id and sorted by descending rating
	 * within each group. The first provider found for a group is the best.
	 */
	sbi_list_for_each_entry(pos, &hart_protection_list, head) {
		/* Skip different groups. */
		if (pos->group_id != hprot->group_id)
			continue;

		if (hprot->rating > pos->rating)
			goto add_before_pos;

		last_same_group = pos;
	}

	if (last_same_group)
		sbi_list_add(&hprot->head, &last_same_group->head);
	else
		sbi_list_add_tail(&hprot->head, &hart_protection_list);

	return 0;

add_before_pos:
	sbi_list_add_tail(&hprot->head, &pos->head);
	return 0;
}

void sbi_hart_protection_unregister(struct sbi_hart_protection *hprot)
{
	if (!hprot)
		return;

	sbi_list_del(&hprot->head);
}

int sbi_hart_protection_configure(struct sbi_scratch *scratch)
{
	struct sbi_hart_protection *hprot = NULL, *best;
	sbi_hart_prot_group_id group_id;
	int ret;

	/* Find the best hart protection per group. */
	for (group_id = 0; group_id < SBI_HART_PROT_GROUP_MAX; group_id++) {
		best = NULL;

		sbi_list_for_each_entry(hprot, &hart_protection_list, head) {
			if (hprot->group_id != group_id)
				continue;

			best = hprot;
			break;
		}

		if (best) {
			if (!best->configure)
				return SBI_ENOSYS;

			ret = best->configure(scratch);
			if (ret)
				return ret;
		}
	}

	return 0;
}

void sbi_hart_protection_unconfigure(struct sbi_scratch *scratch)
{
	struct sbi_hart_protection *hprot = NULL, *best;
	sbi_hart_prot_group_id group_id;

	/* Find the best hart protection per group. */
	for (group_id = 0; group_id < SBI_HART_PROT_GROUP_MAX; group_id++) {
		best = NULL;

		sbi_list_for_each_entry(hprot, &hart_protection_list, head) {
			if (hprot->group_id != group_id)
				continue;

			best = hprot;
			break;
		}

		if (best) {
			if (best->unconfigure)
				best->unconfigure(scratch);
		}
	}
}

int sbi_hart_protection_map_range(unsigned long base, unsigned long size)
{
	struct sbi_hart_protection *hprot = NULL, *best;
	sbi_hart_prot_group_id group_id;
	int ret;

	/* Find the best hart protection per group. */
	for (group_id = 0; group_id < SBI_HART_PROT_GROUP_MAX; group_id++) {
		best = NULL;

		sbi_list_for_each_entry(hprot, &hart_protection_list, head) {
			if (hprot->group_id != group_id)
				continue;

			best = hprot;
			break;
		}

		if (best) {
			if (best->map_range) {
				ret = best->map_range(sbi_scratch_thishart_ptr(), base, size);
				if (ret)
					return ret;
			}
		}
	}

	return 0;
}

int sbi_hart_protection_unmap_range(unsigned long base, unsigned long size)
{
	struct sbi_hart_protection *hprot = NULL, *best;
	sbi_hart_prot_group_id group_id;
	int ret;

	/* Find the best hart protection per group. */
	for (group_id = 0; group_id < SBI_HART_PROT_GROUP_MAX; group_id++) {
		best = NULL;

		sbi_list_for_each_entry(hprot, &hart_protection_list, head) {
			if (hprot->group_id != group_id)
				continue;

			best = hprot;
			break;
		}

		if (best) {
			if (best->unmap_range) {
				ret = best->unmap_range(sbi_scratch_thishart_ptr(), base, size);
				if (ret)
					return ret;
			}
		}
	}

	return 0;
}
