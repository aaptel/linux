// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES.

#include <linux/netdevice.h>
#include <linux/idr.h>
#include "en_accel/nvmeotcp.h"
#include "en_accel/fs_tcp.h"
#include "en/txrx.h"

#define MAX_NUM_NVMEOTCP_QUEUES	(512)
#define MIN_NUM_NVMEOTCP_QUEUES	(1)

static const struct rhashtable_params rhash_queues = {
	.key_len = sizeof(int),
	.key_offset = offsetof(struct mlx5e_nvmeotcp_queue, id),
	.head_offset = offsetof(struct mlx5e_nvmeotcp_queue, hash),
	.automatic_shrinking = true,
	.min_size = MIN_NUM_NVMEOTCP_QUEUES,
	.max_size = MAX_NUM_NVMEOTCP_QUEUES,
};

static int
mlx5e_nvmeotcp_offload_limits(struct net_device *netdev,
			      struct ulp_ddp_limits *ulp_limits)
{
	return 0;
}

static int
mlx5e_nvmeotcp_queue_init(struct net_device *netdev,
			  struct sock *sk,
			  struct ulp_ddp_config *tconfig)
{
	return 0;
}

static void
mlx5e_nvmeotcp_queue_teardown(struct net_device *netdev,
			      struct sock *sk)
{
}

static int
mlx5e_nvmeotcp_ddp_setup(struct net_device *netdev,
			 struct sock *sk,
			 struct ulp_ddp_io *ddp)
{
	return 0;
}

static int
mlx5e_nvmeotcp_ddp_teardown(struct net_device *netdev,
			    struct sock *sk,
			    struct ulp_ddp_io *ddp,
			    void *ddp_ctx)
{
	return 0;
}

static void
mlx5e_nvmeotcp_ddp_resync(struct net_device *netdev,
			  struct sock *sk, u32 seq)
{
}

static const struct ulp_ddp_dev_ops mlx5e_nvmeotcp_ops = {
	.ulp_ddp_limits = mlx5e_nvmeotcp_offload_limits,
	.ulp_ddp_sk_add = mlx5e_nvmeotcp_queue_init,
	.ulp_ddp_sk_del = mlx5e_nvmeotcp_queue_teardown,
	.ulp_ddp_setup = mlx5e_nvmeotcp_ddp_setup,
	.ulp_ddp_teardown = mlx5e_nvmeotcp_ddp_teardown,
	.ulp_ddp_resync = mlx5e_nvmeotcp_ddp_resync,
};

int set_feature_nvme_tcp(struct net_device *netdev, bool enable)
{
	struct mlx5e_priv *priv = netdev_priv(netdev);
	struct mlx5e_params new_params;
	int err = 0;

	/* There may be offloaded queues when an ethtool callback to disable the feature is made.
	 * Hence, we can't destroy the tcp flow-table since it may be referenced by the offload
	 * related flows and we'll keep the 128B CQEs on the channel RQs. Also, since we don't
	 * deref/destroy the fs tcp table when the feature is disabled, we don't ref it again
	 * if the feature is enabled multiple times.
	 */
	if (!enable || priv->nvmeotcp->enabled)
		return 0;

	mutex_lock(&priv->state_lock);

	err = mlx5e_accel_fs_tcp_create(priv->fs);
	if (err)
		goto out_err;

	new_params = priv->channels.params;
	new_params.nvmeotcp = enable;
	err = mlx5e_safe_switch_params(priv, &new_params, NULL, NULL, true);
	if (err)
		goto fs_tcp_destroy;

	priv->nvmeotcp->enabled = true;

	mutex_unlock(&priv->state_lock);
	return 0;

fs_tcp_destroy:
	mlx5e_accel_fs_tcp_destroy(priv->fs);
out_err:
	mutex_unlock(&priv->state_lock);
	return err;
}

void mlx5e_nvmeotcp_build_netdev(struct mlx5e_priv *priv)
{
	struct net_device *netdev = priv->netdev;
	struct mlx5_core_dev *mdev = priv->mdev;

	if (!(MLX5_CAP_GEN(mdev, nvmeotcp) &&
	      MLX5_CAP_DEV_NVMEOTCP(mdev, zerocopy) &&
	      MLX5_CAP_DEV_NVMEOTCP(mdev, crc_rx) && MLX5_CAP_GEN(mdev, cqe_128_always)))
		return;

	/* report ULP DPP as supported, but don't enable it by default */
	netdev->hw_features |= NETIF_F_HW_ULP_DDP;
	netdev->ulp_ddp_ops = &mlx5e_nvmeotcp_ops;
}

void mlx5e_nvmeotcp_cleanup_rx(struct mlx5e_priv *priv)
{
	if (priv->nvmeotcp && priv->nvmeotcp->enabled)
		mlx5e_accel_fs_tcp_destroy(priv->fs);
}

int mlx5e_nvmeotcp_init(struct mlx5e_priv *priv)
{
	struct mlx5e_nvmeotcp *nvmeotcp = NULL;
	int ret = 0;

	if (!MLX5_CAP_GEN(priv->mdev, nvmeotcp))
		return 0;

	nvmeotcp = kzalloc(sizeof(*nvmeotcp), GFP_KERNEL);

	if (!nvmeotcp)
		return -ENOMEM;

	ida_init(&nvmeotcp->queue_ids);
	ret = rhashtable_init(&nvmeotcp->queue_hash, &rhash_queues);
	if (ret)
		goto err_ida;

	nvmeotcp->enabled = false;

	priv->nvmeotcp = nvmeotcp;
	return 0;

err_ida:
	ida_destroy(&nvmeotcp->queue_ids);
	kfree(nvmeotcp);
	return ret;
}

void mlx5e_nvmeotcp_cleanup(struct mlx5e_priv *priv)
{
	struct mlx5e_nvmeotcp *nvmeotcp = priv->nvmeotcp;

	if (!nvmeotcp)
		return;

	rhashtable_destroy(&nvmeotcp->queue_hash);
	ida_destroy(&nvmeotcp->queue_ids);
	kfree(nvmeotcp);
	priv->nvmeotcp = NULL;
}
