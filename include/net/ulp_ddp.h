/* SPDX-License-Identifier: GPL-2.0
 *
 * ulp_ddp.h
 *	Author:	Boris Pismenny <borisp@nvidia.com>
 *	Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES.  All rights reserved.
 */
#ifndef _ULP_DDP_H
#define _ULP_DDP_H

#include <linux/netdevice.h>
#include <net/inet_connection_sock.h>
#include <net/sock.h>

enum ulp_ddp_type {
	ULP_DDP_NVME = 1,
};

enum ulp_ddp_offload_capabilities {
	ULP_DDP_C_NVME_TCP = 1,
	ULP_DDP_C_NVME_TCP_DDGST_RX = 2,
};

/**
 * struct ulp_ddp_limits - Generic ulp ddp limits: tcp ddp
 * protocol limits.
 * Protocol implementations must use this as the first member.
 * Add new instances of ulp_ddp_limits below (nvme-tcp, etc.).
 *
 * @type:		type of this limits struct
 * @offload_capabilities:bitmask of supported offload types
 * @max_ddp_sgl_len:	maximum sgl size supported (zero means no limit)
 * @io_threshold:	minimum payload size required to offload
 * @buf:		protocol-specific limits struct (if any)
 */
struct ulp_ddp_limits {
	enum ulp_ddp_type	type;
	u64			offload_capabilities;
	int			max_ddp_sgl_len;
	int			io_threshold;
	unsigned char		buf[];
};

/**
 * struct nvme_tcp_ddp_limits - nvme tcp driver limitations
 *
 * @lmt:		generic ULP limits struct
 * @full_ccid_range:	true if the driver supports the full CID range
 */
struct nvme_tcp_ddp_limits {
	struct ulp_ddp_limits	lmt;

	bool			full_ccid_range;
};

/**
 * struct ulp_ddp_config - Generic ulp ddp configuration: tcp ddp IO queue
 * config implementations must use this as the first member.
 * Add new instances of ulp_ddp_config below (nvme-tcp, etc.).
 *
 * @type:	type of this config struct
 * @buf:	protocol-specific config struct
 */
struct ulp_ddp_config {
	enum ulp_ddp_type    type;
	unsigned char        buf[];
};

/**
 * struct nvme_tcp_ddp_config - nvme tcp ddp configuration for an IO queue
 *
 * @cfg:	generic ULP config struct
 * @pfv:	pdu version (e.g., NVME_TCP_PFV_1_0)
 * @cpda:	controller pdu data alignment (dwords, 0's based)
 * @dgst:	digest types enabled (header or data, see enum nvme_tcp_digest_option).
 *		The netdev will offload crc if it is supported.
 * @queue_size: number of nvme-tcp IO queue elements
 * @queue_id:	queue identifier
 * @io_cpu:	cpu core running the IO thread for this queue
 */
struct nvme_tcp_ddp_config {
	struct ulp_ddp_config	cfg;

	u16			pfv;
	u8			cpda;
	u8			dgst;
	int			queue_size;
	int			queue_id;
	int			io_cpu;
};

/**
 * struct ulp_ddp_io - ulp ddp configuration for an IO request.
 *
 * @command_id: identifier on the wire associated with these buffers
 * @nents:	number of entries in the sg_table
 * @sg_table:	describing the buffers for this IO request
 * @first_sgl:	first SGL in sg_table
 */
struct ulp_ddp_io {
	u32			command_id;
	int			nents;
	struct sg_table		sg_table;
	struct scatterlist	first_sgl[SG_CHUNK_SIZE];
};

/* struct ulp_ddp_dev_ops - operations used by an upper layer protocol
 *                          to configure ddp offload
 *
 * @ulp_ddp_limits:    query ulp driver limitations and quirks.
 * @ulp_ddp_sk_add:    add offload for the queue represented by socket+config
 *                     pair. this function is used to configure either copy, crc
 *                     or both offloads.
 * @ulp_ddp_sk_del:    remove offload from the socket, and release any device
 *                     related resources.
 * @ulp_ddp_setup:     request copy offload for buffers associated with a
 *                     command_id in ulp_ddp_io.
 * @ulp_ddp_teardown:  release offload resources association between buffers
 *                     and command_id in ulp_ddp_io.
 * @ulp_ddp_resync:    respond to the driver's resync_request. Called only if
 *                     resync is successful.
 */
struct ulp_ddp_dev_ops {
	int (*ulp_ddp_limits)(struct net_device *netdev,
			      struct ulp_ddp_limits *limits);
	int (*ulp_ddp_sk_add)(struct net_device *netdev,
			      struct sock *sk,
			      struct ulp_ddp_config *config);
	void (*ulp_ddp_sk_del)(struct net_device *netdev,
			       struct sock *sk);
	int (*ulp_ddp_setup)(struct net_device *netdev,
			     struct sock *sk,
			     struct ulp_ddp_io *io);
	int (*ulp_ddp_teardown)(struct net_device *netdev,
				struct sock *sk,
				struct ulp_ddp_io *io,
				void *ddp_ctx);
	void (*ulp_ddp_resync)(struct net_device *netdev,
			       struct sock *sk, u32 seq);
};

#define ULP_DDP_RESYNC_PENDING BIT(0)

/**
 * struct ulp_ddp_ulp_ops - Interface to register uppper layer
 *                          Direct Data Placement (DDP) TCP offload.
 * @resync_request:         NIC requests ulp to indicate if @seq is the start
 *                          of a message.
 * @ddp_teardown_done:      NIC driver informs the ulp that teardown is done,
 *                          used for async completions.
 */
struct ulp_ddp_ulp_ops {
	bool (*resync_request)(struct sock *sk, u32 seq, u32 flags);
	void (*ddp_teardown_done)(void *ddp_ctx);
};

/**
 * struct ulp_ddp_ctx - Generic ulp ddp context: device driver per queue contexts must
 * use this as the first member.
 *
 * @type:	type of this context struct
 * @buf:	protocol-specific context struct
 */
struct ulp_ddp_ctx {
	enum ulp_ddp_type	type;
	unsigned char		buf[];
};

static inline struct ulp_ddp_ctx *ulp_ddp_get_ctx(const struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	return (__force struct ulp_ddp_ctx *)icsk->icsk_ulp_ddp_data;
}

static inline void ulp_ddp_set_ctx(struct sock *sk, void *ctx)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	rcu_assign_pointer(icsk->icsk_ulp_ddp_data, ctx);
}

#endif	/* _ULP_DDP_H */
