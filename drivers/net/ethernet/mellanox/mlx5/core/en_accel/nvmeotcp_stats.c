// SPDX-License-Identifier: GPL-2.0 OR Linux-OpenIB
// Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES.

#include "en_accel/nvmeotcp.h"

/* Global counters */
static const struct counter_desc nvmeotcp_sw_stats_desc[] = {
	{ MLX5E_DECLARE_STAT(struct mlx5e_nvmeotcp_sw_stats, rx_nvmeotcp_sk_add) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_nvmeotcp_sw_stats, rx_nvmeotcp_sk_add_fail) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_nvmeotcp_sw_stats, rx_nvmeotcp_sk_del) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_nvmeotcp_sw_stats, rx_nvmeotcp_ddp_setup) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_nvmeotcp_sw_stats, rx_nvmeotcp_ddp_setup_fail) },
	{ MLX5E_DECLARE_STAT(struct mlx5e_nvmeotcp_sw_stats, rx_nvmeotcp_ddp_teardown) },
};

/* Per-rx-queue counters */
static const struct counter_desc nvmeotcp_rq_stats_desc[] = {
	{ MLX5E_DECLARE_RX_STAT(struct mlx5e_rq_stats, nvmeotcp_drop) },
	{ MLX5E_DECLARE_RX_STAT(struct mlx5e_rq_stats, nvmeotcp_resync) },
	{ MLX5E_DECLARE_RX_STAT(struct mlx5e_rq_stats, nvmeotcp_offload_packets) },
	{ MLX5E_DECLARE_RX_STAT(struct mlx5e_rq_stats, nvmeotcp_offload_bytes) },
};

/* Names of sums of the per-rx-queue counters
 *
 * The per-queue desc have the queue number in their name, so we
 * cannot use them for the sums. We don't store the sums in sw_stats
 * so there are no struct offsets to specify.
 */
static const char *const nvmeotcp_rq_sum_names[] = {
	"rx_nvmeotcp_drop",
	"rx_nvmeotcp_resync",
	"rx_nvmeotcp_offload_packets",
	"rx_nvmeotcp_offload_bytes",
};

static_assert(ARRAY_SIZE(nvmeotcp_rq_stats_desc) == ARRAY_SIZE(nvmeotcp_rq_sum_names));

#define MLX5E_READ_CTR_ATOMIC64(ptr, dsc, i) \
	atomic64_read((atomic64_t *)((char *)(ptr) + (dsc)[i].offset))

int mlx5e_nvmeotcp_get_count(struct mlx5e_priv *priv)
{
	int max_nch = priv->stats_nch;

	if (!priv->nvmeotcp)
		return 0;

	return ARRAY_SIZE(nvmeotcp_sw_stats_desc) +
		ARRAY_SIZE(nvmeotcp_rq_stats_desc) +
		(max_nch * ARRAY_SIZE(nvmeotcp_rq_stats_desc));
}

int mlx5e_nvmeotcp_get_strings(struct mlx5e_priv *priv, uint8_t *data)
{
	unsigned int i, ch, n = 0, idx = 0;

	if (!priv->nvmeotcp)
		return 0;

	/* global counters */
	for (i = 0; i < ARRAY_SIZE(nvmeotcp_sw_stats_desc); i++, n++)
		strcpy(data + (idx++) * ETH_GSTRING_LEN,
		       nvmeotcp_sw_stats_desc[i].format);

	/* summed per-rx-queue counters */
	for (i = 0; i < ARRAY_SIZE(nvmeotcp_rq_stats_desc); i++, n++)
		strcpy(data + (idx++) * ETH_GSTRING_LEN,
		       nvmeotcp_rq_sum_names[i]);

	/* per-rx-queue counters */
	for (ch = 0; ch < priv->stats_nch; ch++)
		for (i = 0; i < ARRAY_SIZE(nvmeotcp_rq_stats_desc); i++, n++)
			sprintf(data + (idx++) * ETH_GSTRING_LEN,
				nvmeotcp_rq_stats_desc[i].format, ch);

	return n;
}

int mlx5e_nvmeotcp_get_stats(struct mlx5e_priv *priv, u64 *data)
{
	unsigned int i, ch, n = 0, idx = 0, sum_start = 0;

	if (!priv->nvmeotcp)
		return 0;

	/* global counters */
	for (i = 0; i < ARRAY_SIZE(nvmeotcp_sw_stats_desc); i++, n++)
		data[idx++] = MLX5E_READ_CTR_ATOMIC64(&priv->nvmeotcp->sw_stats,
						      nvmeotcp_sw_stats_desc, i);

	/* summed per-rx-queue counters */
	sum_start = idx;
	for (i = 0; i < ARRAY_SIZE(nvmeotcp_rq_stats_desc); i++, n++)
		data[idx++] = 0;

	/* per-rx-queue counters */
	for (ch = 0; ch < priv->stats_nch; ch++) {
		for (i = 0; i < ARRAY_SIZE(nvmeotcp_rq_stats_desc); i++, n++) {
			u64 v = MLX5E_READ_CTR64_CPU(&priv->channel_stats[ch]->rq,
						     nvmeotcp_rq_stats_desc, i);
			data[idx++] = v;
			data[sum_start + i] += v;
		}
	}

	return n;
}
