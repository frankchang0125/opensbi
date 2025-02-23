/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Andes Technology Corporation. All rights reserved.
 */

#include <sbi/sbi_error.h>
#include <sbi/sbi_heap.h>
#include <sbi/sbi_fifo.h>
#include <sbi/sbi_mpxy.h>
#include <libfdt.h>
#include <sbi_utils/fdt/fdt_helper.h>
#include <sbi_utils/mpxy/fdt_mpxy.h>
#include <sbi_utils/mpxy/fdt_mpxy_rpmi_mbox.h>
#include <sbi/sbi_domain.h>
#include <sbi/sbi_console.h>

/**
 * MPXY OP-TEE instance per MPXY channel.
 */
struct mpxy_optee {
	struct mpxy_rpmi_channel_attrs msgprot_attrs;
	struct sbi_mpxy_channel channel;

	/* Owner Hart ID of this channel */
	u32 hartid;
	/* Corresponding Reqfwd channel id */
	u32 reqfwd_channel_id;

	/* TEE domain */
	char optee_domain_name[64];
	struct sbi_domain *optee_domain;
};

/*
 * Setup target domain of this OP-TEE channel.
 * If the target domain has not been registered, the domain will be setup in
 * optee_domain_setup_deferred() when OP-TEE channel is used.
 */
static int optee_domain_setup(const void *fdt, int nodeoff,
			   const struct fdt_match *match,
			   struct mpxy_optee *optee)
{
	struct sbi_domain *dom = NULL;
	const u32 *prop_instance;
	int len, offset;

	prop_instance = fdt_getprop(fdt, nodeoff, "opensbi-domain-instance",
				    &len);
	if (!prop_instance || len < 4)
		return SBI_EINVAL;

	offset = fdt_node_offset_by_phandle(fdt, fdt32_to_cpu(*prop_instance));
	if (offset < 0)
		return SBI_EINVAL;

	strncpy(optee->optee_domain_name, fdt_get_name(fdt, offset, NULL),
		sizeof(optee->optee_domain_name));
	optee->optee_domain_name[sizeof(optee->optee_domain_name) - 1] = '\0';

	sbi_domain_for_each(dom) {
		if (!sbi_strcmp(dom->name, optee->optee_domain_name)) {
			optee->optee_domain = dom;
			break;
		}
	}

	return SBI_OK;
}

/* Setup target domain of this OP-TEE channel */
static int optee_domain_setup_deferred(struct mpxy_optee *optee)
{
	struct sbi_domain *dom = NULL;

	if (optee->optee_domain)
		 return SBI_OK;

	sbi_domain_for_each(dom) {
		if (!sbi_strcmp(dom->name, optee->optee_domain_name)) {
			optee->optee_domain = dom;
			return SBI_OK;
		}
	}

	return SBI_ENOENT;
}

/* Switch to target domain of this OP-TEE channel */
static int optee_domain_enter(struct mpxy_optee *optee)
{
	int rc;

	/* Try to setup OP-TEE domain if it has not been set */
	rc = optee_domain_setup_deferred(optee);
	if (rc)
		return rc;

	return sbi_domain_context_enter(optee->optee_domain);
}

/** Copy attributes word size */
static void mpxy_copy_attrs(u32 *outmem, u32 *inmem, u32 count)
{
	u32 idx;
	for (idx = 0; idx < count; idx++)
		outmem[idx] = cpu_to_le32(inmem[idx]);
}

static int mpxy_optee_read_attributes(struct sbi_mpxy_channel *channel,
				   u32 *outmem, u32 base_attr_id,
				   u32 attr_count)
{
	struct mpxy_optee *optee = container_of(channel, struct mpxy_optee, channel);
	u32 *attr_array = (u32 *)&optee->msgprot_attrs;
	u32 end_id = base_attr_id + attr_count - 1;

	if (end_id >= MPXY_MSGPROT_RPMI_ATTR_MAX_ID)
		return SBI_EBAD_RANGE;

	mpxy_copy_attrs(outmem, &attr_array[attr_id2index(base_attr_id)],
			attr_count);

	return SBI_OK;
}

static int mpxy_optee_send_message_withresp(struct sbi_mpxy_channel *channel,
					 u32 message_id,
					 void *tx, u32 tx_len,
					 void *rx, u32 rx_max_len,
					 unsigned long *ack_len)
{
	struct mpxy_optee *optee = container_of(channel, struct mpxy_optee, channel);
	struct sbi_mpxy_channel *recv_channel;
	struct rpmi_message_header header;
	u32 recv_channel_id = optee->reqfwd_channel_id;
	int rc;

	if (RPMI_OPTEE_SRV_COMMUNICATE == message_id) {
		recv_channel = sbi_mpxy_find_channel(recv_channel_id);
		if (!recv_channel)
			return SBI_ENODEV;

		/* Prepare the header to be written into the slot */
		header.servicegroup_id = cpu_to_le16(RPMI_SRVGRP_OPTEE);
		header.service_id = message_id;
		header.flags = RPMI_MSG_NORMAL_REQUEST;
		header.datalen = cpu_to_le16((u16)tx_len);
		header.token = cpu_to_le16(0);
		/* Forward message to MPXT ReqFwd channel */
		rc = mpxy_reqfwd_forward_message(recv_channel, &header,
						 tx, tx_len, rx, rx_max_len,
						 ack_len);
		if (rc)
			return rc;

		/* Enter OP-TEE domain */
		rc = optee_domain_enter(optee);
		if (rc)
			return rc;
	} else {
		return SBI_EFAIL;
	}

	return SBI_OK;
}

static int mpxy_optee_init(const void *fdt, int nodeoff,
			const struct fdt_match *match)
{
	struct mpxy_optee *optee;
	const fdt32_t *val;
	u32 channel_id, reqfwd_channel_id, hartid;
	int rc, len, cpu_offset, sibling_offset;
	bool found_reqfwd = false;

	/* Allocate context for Request Forward */
	optee = sbi_zalloc(sizeof(*optee));
	if (!optee)
		return SBI_ENOMEM;

	/* DT example:
	 * cpu0: cpu@0 {
	 *     reg = <0x0>;  // hartid = 0
	 *     ...
	 *     rpmi_optee_0 {
	 *         compatible = "riscv,sbi-mpxy-optee";
	 *         riscv,sbi-mpxy-channel-id = <0x0>;
	 *         opensbi-domain-instance = <&tdomain>;
	 *     };
	 *     rpmi_reqfwd_0 {
	 *         compatible = "riscv,sbi-mpxy-reqfwd";
	 *         riscv,sbi-mpxy-channel-id = <0x10>;
	 *     };
	 * };
	 */
	val = fdt_getprop(fdt, nodeoff, "riscv,sbi-mpxy-channel-id", &len);
	if (len > 0 && val)
		channel_id = fdt32_to_cpu(*val);
	else
		sbi_panic("Failed to get riscv,sbi-mpxy-channel-id");

	/* Get parent CPU node to extract hartid from its reg property */
	cpu_offset = fdt_parent_offset(fdt, nodeoff);
	if (cpu_offset < 0)
		sbi_panic("Failed to get parent CPU node");

	rc = fdt_parse_hart_id(fdt, cpu_offset, &hartid);
	if (rc)
		sbi_panic("Failed to parse hartid from parent CPU node");

	/* Find sibling rpmi_reqfwd node to get reqfwd channel id */
	fdt_for_each_subnode(sibling_offset, fdt, cpu_offset) {
		if (!fdt_node_check_compatible(fdt, sibling_offset,
					       "riscv,sbi-mpxy-reqfwd")) {
			val = fdt_getprop(fdt, sibling_offset,
					  "riscv,sbi-mpxy-channel-id", &len);
			if (len > 0 && val) {
				reqfwd_channel_id = fdt32_to_cpu(*val);
				found_reqfwd = true;
				break;
			}
		}
	}

	if (!found_reqfwd)
		sbi_panic("Failed to find reqfwd channel id");

	optee->hartid = hartid;
	optee->reqfwd_channel_id = reqfwd_channel_id;
	optee->channel.channel_id = channel_id;
	optee->channel.read_attributes = mpxy_optee_read_attributes;
	optee->channel.send_message_with_response = mpxy_optee_send_message_withresp;
	optee->channel.attrs.msg_proto_id = SBI_MPXY_MSGPROTO_RPMI_ID;
	optee->channel.attrs.msg_data_maxlen = PAGE_SIZE;

	/* RPMI service group attributes */
	optee->msgprot_attrs.servicegrp_id = RPMI_SRVGRP_OPTEE;
	optee->msgprot_attrs.servicegrp_ver = 1;

	rc = sbi_mpxy_register_channel(&optee->channel);
	if (rc)
		goto fail_free_optee;

	/* Try to setup OP-TEE domain */
	rc = optee_domain_setup(fdt, nodeoff, match, optee);
	if (rc)
		goto fail_free_optee;

	return SBI_SUCCESS;

fail_free_optee:
	sbi_free(optee);
	return rc;
}

static const struct fdt_match mpxy_optee_match[] = {
	{ .compatible = "riscv,sbi-mpxy-optee", .data = NULL },
	{},
};

const struct fdt_driver fdt_mpxy_rpmi_optee = {
	.experimental = true,
	.match_table = mpxy_optee_match,
	.init = mpxy_optee_init,
};
