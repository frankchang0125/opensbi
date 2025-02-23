/*
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2025 Andes Technology Corporation. All rights reserved.
 */

#include <libfdt.h>
#include <sbi/sbi_console.h>
#include <sbi/sbi_domain.h>
#include <sbi/sbi_error.h>
#include <sbi/sbi_fifo.h>
#include <sbi/sbi_hart.h>
#include <sbi/sbi_heap.h>
#include <sbi/sbi_mpxy.h>
#include <sbi/sbi_scratch.h>
#include <sbi/sbi_string.h>
#include <sbi_utils/mpxy/fdt_mpxy_rpmi_mbox.h>
#include <sbi_utils/fdt/fdt_helper.h>

/** RPMI Message */
struct rpmi_message_slot {
	struct rpmi_message_header header;
	u8 data[RPMI_MSG_DATA_SIZE(RPMI_SLOT_SIZE_MIN)];

	/* Sender RX address. Should be MPXY shared memory */
	void *sender_rx;
};

#define REQFWD_MSG_FIFO_ENTRIES		4

/**
 * MPXY ReqFwd instance per MPXY channel.
 */
struct mpxy_reqfwd {
	struct mpxy_rpmi_channel_attrs msgprot_attrs;
	struct sbi_mpxy_channel channel;
	/* Owner Hart ID of this channel */
	u32 hartid;
	/* FIFO to store forwarded RPMI request message */
	struct sbi_fifo msg_fifo;
	/* Current forwarded RPMI request message */
	struct rpmi_message_slot current_msg;

	/* Receiver side is waiting for message */
	bool is_waiting_message;
	/* Receiver RX address. Should be MPXY shared memory */
	void *rx;
	/* Maximum receiver RX length */
	u32 rx_max_len;
	/* Length of responce of current message */
	unsigned long ack_len;
};

static int retrieve_message(struct mpxy_reqfwd *reqfwd,
			    void *rx, u32 rx_max_len, unsigned long *ack_len)
{
	struct rpmi_message_slot *current_msg = &reqfwd->current_msg;
	u32 datalen;
	int rc;

	/* Dequeue oldest forwarded RPMI request message */
	rc = sbi_fifo_dequeue(&reqfwd->msg_fifo, current_msg);
	if (!rc) {
		/* Get data length from RPMI message header */
		datalen = le16_to_cpu(current_msg->header.datalen);
		if (rx_max_len < datalen)
			return SBI_ENOMEM;

		/* STATUS */
		((u32 *)rx)[0] = cpu_to_le32(RPMI_SUCCESS);
		/* REMAINING */
		((u32 *)rx)[1] = cpu_to_le32(0);
		/* RETURNED */
		((u32 *)rx)[2] = cpu_to_le32(datalen);
		/* REQUEST_MESSAGE[N] */
		sbi_memcpy(&((u32 *)rx)[3], current_msg->data, datalen);
		*ack_len = 3 * sizeof(u32) + datalen;

		reqfwd->is_waiting_message = false;
	}

	return rc;
}

int mpxy_reqfwd_forward_message(struct sbi_mpxy_channel *channel,
				struct rpmi_message_header *header,
				void *tx, u32 tx_len,
				void *rx, u32 rx_max_len,
				unsigned long *ack_len)
{
	struct mpxy_reqfwd *reqfwd;
	struct rpmi_message_slot msg;
	int rc;

	if (!tx || tx_len > RPMI_MSG_DATA_SIZE(RPMI_SLOT_SIZE_MIN))
		return SBI_EINVAL;

	reqfwd = container_of(channel, struct mpxy_reqfwd, channel);

	/* Prepare and enqueue message into per-channel FIFO */
	sbi_memset(&msg, 0, sizeof(struct rpmi_message_slot));
	sbi_memcpy(&msg.header, header, RPMI_MSG_HDR_SIZE);
	sbi_memcpy(msg.data, tx, tx_len);
	/* Record RX information so that we can copy response into it later */
	msg.sender_rx = rx;
	sbi_fifo_enqueue(&reqfwd->msg_fifo, &msg, true);

	if (reqfwd->is_waiting_message) {
		/*
		 * The callee domain is waiting for message.
		 * We immediately retrieve message and switch into it.
		 */
		rc = retrieve_message(reqfwd, reqfwd->rx, reqfwd->rx_max_len,
				      ack_len);
		if (rc)
			return rc;
	}

	return SBI_OK;
}

/** Copy attributes word size */
static void mpxy_copy_attrs(u32 *outmem, u32 *inmem, u32 count)
{
	u32 idx;
	for (idx = 0; idx < count; idx++)
		outmem[idx] = cpu_to_le32(inmem[idx]);
}

static int mpxy_reqfwd_read_attributes(struct sbi_mpxy_channel *channel,
				       u32 *outmem, u32 base_attr_id,
				       u32 attr_count)
{
	struct mpxy_reqfwd *reqfwd =
		container_of(channel, struct mpxy_reqfwd, channel);
	u32 *attr_array = (u32 *)&reqfwd->msgprot_attrs;
	u32 end_id = base_attr_id + attr_count - 1;

	if (end_id >= MPXY_MSGPROT_RPMI_ATTR_MAX_ID)
		return SBI_EBAD_RANGE;

	mpxy_copy_attrs(outmem, &attr_array[attr_id2index(base_attr_id)],
			attr_count);

	return SBI_OK;
}

static int mpxy_reqfwd_send_message_withresp(struct sbi_mpxy_channel *channel,
					     u32 message_id,
					     void *tx, u32 tx_len,
					     void *rx, u32 rx_max_len,
					     unsigned long *ack_len)
{
	struct mpxy_reqfwd *reqfwd =
		container_of(channel, struct mpxy_reqfwd, channel);
	struct rpmi_message_slot *current_msg = &reqfwd->current_msg;
	int rc;

	if (RPMI_REQFWD_SRV_RETRIEVE_CURRENT_MESSAGE == message_id) {
		/* Dequeue oldest forwarded RPMI request message */
		rc = retrieve_message(reqfwd, rx, rx_max_len, ack_len);
		if (rc == SBI_OK || rc == SBI_EINVAL)
			return rc;

		/* No more message. Switch back to caller domain */
		*ack_len = reqfwd->ack_len;
		reqfwd->ack_len = 0;

		/* Record this domain is waiting for message */
		reqfwd->is_waiting_message = true;
		reqfwd->rx = rx;
		reqfwd->rx_max_len = rx_max_len;

		/* Switch to other domain */
		sbi_domain_context_exit();
	} else if (RPMI_REQFWD_SRV_COMPLETE_CURRENT_MESSAGE == message_id) {
		if (current_msg->header.servicegroup_id) {
			/* Fill response data into RX of sender */
			/* tx has a0~a4. Just skip a0 and copy a1~a4 here */
			sbi_memcpy(current_msg->sender_rx, &(((ulong *)tx)[1]),
				   tx_len - sizeof(ulong));
			reqfwd->ack_len = tx_len - sizeof(ulong);
			/* Clear cerrent message */
			memset(&current_msg, 0, sizeof(current_msg));
			/* STATUS */
			((u32 *)rx)[0] = cpu_to_le32(RPMI_SUCCESS);
		} else {
			/* STATUS */
			((u32 *)rx)[0] = cpu_to_le32(RPMI_ERR_NO_DATA);
		}
		*ack_len = sizeof(u32);
	} else {
		return SBI_EFAIL;
	}

	return SBI_OK;
}

static int mpxy_reqfwd_init(const void *fdt, int nodeoff,
			    const struct fdt_match *match)
{
	struct rpmi_message_slot *msg_buf;
	struct mpxy_reqfwd *reqfwd;
	const fdt32_t *val;
	u32 channel_id, hartid;
	int rc, len, cpu_offset;

	/* Allocate context for Request Forward */
	reqfwd = sbi_zalloc(sizeof(*reqfwd));
	if (!reqfwd)
		return SBI_ENOMEM;

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

	reqfwd->hartid = hartid;
	reqfwd->channel.channel_id = channel_id;
	reqfwd->channel.read_attributes = mpxy_reqfwd_read_attributes;
	reqfwd->channel.send_message_with_response =
		mpxy_reqfwd_send_message_withresp;
	reqfwd->channel.attrs.msg_data_maxlen = PAGE_SIZE;

	/* RPMI service group attributes */
	reqfwd->msgprot_attrs.servicegrp_id = RPMI_SRVGRP_REQFWD;
	reqfwd->msgprot_attrs.servicegrp_ver = 1;

	/* Allocate per-channel FIFO */
	msg_buf = sbi_calloc(REQFWD_MSG_FIFO_ENTRIES, sizeof(*msg_buf));
	if (!msg_buf) {
		sbi_free(reqfwd);
		return SBI_ENOMEM;
	}

	sbi_fifo_init(&reqfwd->msg_fifo, msg_buf, REQFWD_MSG_FIFO_ENTRIES,
		      sizeof(struct rpmi_message_slot));

	rc = sbi_mpxy_register_channel(&reqfwd->channel);
	if (rc) {
		sbi_free(reqfwd);
		return rc;
	}

	return SBI_OK;
}

static const struct fdt_match mpxy_reqfwd_match[] = {
	{ .compatible = "riscv,sbi-mpxy-reqfwd", .data = NULL },
	{},
};

const struct fdt_driver fdt_mpxy_reqfwd = {
	.match_table = mpxy_reqfwd_match,
	.init = mpxy_reqfwd_init,
	.experimental = true,
};
