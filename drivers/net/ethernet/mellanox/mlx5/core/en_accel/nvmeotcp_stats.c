// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2022, NVIDIA CORPORATION & AFFILIATES.

#include "en_accel/nvmeotcp.h"

static const struct counter_desc mlx5e_nvmeotcp_sw_stats_desc[] = {
	{ MLX5E_DECLARE_STAT(struct mlx5e_nvmeotcp_sw_stats, rx_nvmeotcp_sk_add) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_nvmeotcp_sw_stats, rx_nvmeotcp_sk_add_fail) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_nvmeotcp_sw_stats, rx_nvmeotcp_sk_del) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_nvmeotcp_sw_stats, rx_nvmeotcp_ddp_setup) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_nvmeotcp_sw_stats, rx_nvmeotcp_ddp_setup_fail) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_nvmeotcp_sw_stats, rx_nvmeotcp_ddp_teardown) },
};

#define MLX5E_READ_CTR_ATOMIC64(ptr, dsc, i) \
	atomic64_read((atomic64_t *)((char *)(ptr) + (dsc)[i].offset))

static const struct counter_desc *get_nvmeotcp_atomic_stats(struct mlx5e_priv *priv)
{
	if (!priv->nvmeotcp)
		return NULL;
	return mlx5e_nvmeotcp_sw_stats_desc;
}

int mlx5e_nvmeotcp_get_count(struct mlx5e_priv *priv)
{
	if (!priv->nvmeotcp)
		return 0;
	return ARRAY_SIZE(mlx5e_nvmeotcp_sw_stats_desc);
}

int mlx5e_nvmeotcp_get_strings(struct mlx5e_priv *priv, uint8_t *data)
{
	const struct counter_desc *stats_desc;
	unsigned int i, n, idx = 0;

	stats_desc = get_nvmeotcp_atomic_stats(priv);
	n = mlx5e_nvmeotcp_get_count(priv);

	for (i = 0; i < n; i++)
		strcpy(data + (idx++) * ETH_GSTRING_LEN,
		       stats_desc[i].format);

	return n;
}

int mlx5e_nvmeotcp_get_stats(struct mlx5e_priv *priv, u64 *data)
{
	const struct counter_desc *stats_desc;
	unsigned int i, n, idx = 0;

	stats_desc = get_nvmeotcp_atomic_stats(priv);
	n = mlx5e_nvmeotcp_get_count(priv);

	for (i = 0; i < n; i++)
		data[idx++] =
		    MLX5E_READ_CTR_ATOMIC64(&priv->nvmeotcp->sw_stats,
					    stats_desc, i);

	return n;
}
