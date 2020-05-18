// SPDX-License-Identifier: GPL-2.0
/*
 *
 * ulp_ddp.c
 *   Author:	Aurelien Aptel <aaptel@nvidia.com>
 *   Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES.  All rights reserved.
 */

#include <net/ulp_ddp.h>

int ulp_ddp_sk_add(struct net_device *netdev,
		   struct sock *sk,
		   struct ulp_ddp_config *config,
		   const struct ulp_ddp_ulp_ops *ops)
{
	int ret;

	/* put in ulp_ddp_sk_del() */
	dev_hold(netdev);

	config->io_cpu = sk->sk_incoming_cpu;
	ret = netdev->netdev_ops->ulp_ddp_ops->sk_add(netdev, sk, config);
	if (ret) {
		dev_put(netdev);
		return ret;
	}

	inet_csk(sk)->icsk_ulp_ddp_ops = ops;

	return 0;
}
EXPORT_SYMBOL_GPL(ulp_ddp_sk_add);

void ulp_ddp_sk_del(struct net_device *netdev,
		    struct sock *sk)
{
	netdev->netdev_ops->ulp_ddp_ops->sk_del(netdev, sk);
	inet_csk(sk)->icsk_ulp_ddp_ops = NULL;
	dev_put(netdev);
}
EXPORT_SYMBOL_GPL(ulp_ddp_sk_del);

bool ulp_ddp_is_cap_active(struct net_device *netdev, int cap_bit_nr)
{
	struct ulp_ddp_dev_caps caps;

	if (!netdev->netdev_ops->ulp_ddp_ops->get_caps)
		return false;
	netdev->netdev_ops->ulp_ddp_ops->get_caps(netdev, &caps);
	return test_bit(cap_bit_nr, caps.active);
}
EXPORT_SYMBOL_GPL(ulp_ddp_is_cap_active);
