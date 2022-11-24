// SPDX-License-Identifier: GPL-2.0
/*
 *
 * ulp_ddp.c
 *     Author: Aurelien Aptel <aaptel@nvidia.com>
 *     Copyright (c) 2023, NVIDIA CORPORATION & AFFILIATES.  All rights reserved.
 */

#include "netlink.h"
#include "common.h"
#include "bitset.h"
#include <net/ulp_ddp.h>

#define ETHTOOL_ULP_DDP_STATS_CNT \
	(__ETHTOOL_A_ULP_DDP_STATS_CNT - (ETHTOOL_A_ULP_DDP_STATS_PAD + 1))

static struct ulp_ddp_netdev_caps *netdev_ulp_ddp_caps(struct net_device *dev)
{
#ifdef CONFIG_ULP_DDP
	return &dev->ulp_ddp_caps;
#else
	return NULL;
#endif
}

static const struct ulp_ddp_dev_ops *netdev_ulp_ddp_ops(struct net_device *dev)
{
#ifdef CONFIG_ULP_DDP
	return dev->netdev_ops->ulp_ddp_ops;
#else
	return NULL;
#endif
}

/* ULP_DDP_GET */

struct ulp_ddp_req_info {
	struct ethnl_req_info	base;
};

struct ulp_ddp_reply_data {
	struct ethnl_reply_data	base;
	DECLARE_BITMAP(hw, ULP_DDP_C_COUNT);
	DECLARE_BITMAP(active, ULP_DDP_C_COUNT);
	struct ethtool_ulp_ddp_stats stats;
};

#define ULP_DDP_REPDATA(__reply_base) \
	container_of(__reply_base, struct ulp_ddp_reply_data, base)

const struct nla_policy ethnl_ulp_ddp_get_policy[] = {
	[ETHTOOL_A_ULP_DDP_HEADER] = NLA_POLICY_NESTED(ethnl_header_policy_stats),
};

static int ulp_ddp_put_stats64(struct sk_buff *skb, int attrtype, const u64 *val,
			       unsigned int count)
{
	struct nlattr *nest;
	unsigned int i, attr;

	nest = nla_nest_start(skb, attrtype);
	if (!nest)
		return -EMSGSIZE;

	/* skip attributes unspec & pad */
	attr = ETHTOOL_A_ULP_DDP_STATS_PAD + 1;
	for (i = 0 ; i < count; i++, attr++)
		if (nla_put_u64_64bit(skb, attr, val[i], ETHTOOL_A_ULP_DDP_STATS_PAD))
			goto nla_put_failure;

	nla_nest_end(skb, nest);
	return 0;

nla_put_failure:
	nla_nest_cancel(skb, nest);
	return -EMSGSIZE;
}

static int ulp_ddp_prepare_data(const struct ethnl_req_info *req_base,
				struct ethnl_reply_data *reply_base,
				struct genl_info *info)
{
	const struct ulp_ddp_dev_ops *ops = netdev_ulp_ddp_ops(reply_base->dev);
	struct ulp_ddp_netdev_caps *caps = netdev_ulp_ddp_caps(reply_base->dev);
	struct ulp_ddp_reply_data *data = ULP_DDP_REPDATA(reply_base);

	if (!caps || !ops)
		return -EOPNOTSUPP;

	bitmap_copy(data->hw, caps->hw, ULP_DDP_C_COUNT);
	bitmap_copy(data->active, caps->active, ULP_DDP_C_COUNT);

	if (req_base->flags & ETHTOOL_FLAG_STATS) {
		if (!ops->get_stats)
			return -EOPNOTSUPP;
		ops->get_stats(reply_base->dev, &data->stats);
	}
	return 0;
}

static int ulp_ddp_reply_size(const struct ethnl_req_info *req_base,
			      const struct ethnl_reply_data *reply_base)
{
	const struct ulp_ddp_reply_data *data = ULP_DDP_REPDATA(reply_base);
	bool compact = req_base->flags & ETHTOOL_FLAG_COMPACT_BITSETS;
	unsigned int len = 0;
	int ret;

	ret = ethnl_bitset_size(data->hw, NULL, ULP_DDP_C_COUNT,
				ulp_ddp_caps_names, compact);
	if (ret < 0)
		return ret;
	len += ret;
	ret = ethnl_bitset_size(data->active, NULL, ULP_DDP_C_COUNT,
				ulp_ddp_caps_names, compact);
	if (ret < 0)
		return ret;
	len += ret;

	if (req_base->flags & ETHTOOL_FLAG_STATS) {
		len += nla_total_size_64bit(sizeof(u64)) * ETHTOOL_ULP_DDP_STATS_CNT;
		len += nla_total_size(0); /* nest */
	}
	return len;
}

static int ulp_ddp_fill_reply(struct sk_buff *skb,
			      const struct ethnl_req_info *req_base,
			      const struct ethnl_reply_data *reply_base)
{
	const struct ulp_ddp_reply_data *data = ULP_DDP_REPDATA(reply_base);
	bool compact = req_base->flags & ETHTOOL_FLAG_COMPACT_BITSETS;
	int ret;

	ret = ethnl_put_bitset(skb, ETHTOOL_A_ULP_DDP_HW, data->hw,
			       NULL, ULP_DDP_C_COUNT,
			       ulp_ddp_caps_names, compact);
	if (ret < 0)
		return ret;

	ret = ethnl_put_bitset(skb, ETHTOOL_A_ULP_DDP_ACTIVE, data->active,
			       NULL, ULP_DDP_C_COUNT,
			       ulp_ddp_caps_names, compact);
	if (ret < 0)
		return ret;

	if (req_base->flags & ETHTOOL_FLAG_STATS) {
		ret = ulp_ddp_put_stats64(skb, ETHTOOL_A_ULP_DDP_STATS,
					  (u64 *)&data->stats,
					  ETHTOOL_ULP_DDP_STATS_CNT);
		if (ret < 0)
			return ret;
	}
	return ret;
}

/* ULP_DDP_SET */

const struct nla_policy ethnl_ulp_ddp_set_policy[] = {
	[ETHTOOL_A_ULP_DDP_HEADER] = NLA_POLICY_NESTED(ethnl_header_policy),
	[ETHTOOL_A_ULP_DDP_WANTED] = NLA_POLICY_NESTED(ethnl_bitset_policy),
};

static int ulp_ddp_send_reply(struct net_device *dev, struct genl_info *info,
			      const unsigned long *wanted,
			      const unsigned long *wanted_mask,
			      const unsigned long *active,
			      const unsigned long *active_mask, bool compact)
{
	struct sk_buff *rskb;
	void *reply_payload;
	int reply_len = 0;
	int ret;

	reply_len = ethnl_reply_header_size();
	ret = ethnl_bitset_size(wanted, wanted_mask, ULP_DDP_C_COUNT,
				ulp_ddp_caps_names, compact);
	if (ret < 0)
		goto err;
	reply_len += ret;
	ret = ethnl_bitset_size(active, active_mask, ULP_DDP_C_COUNT,
				ulp_ddp_caps_names, compact);
	if (ret < 0)
		goto err;
	reply_len += ret;

	rskb = ethnl_reply_init(reply_len, dev, ETHTOOL_MSG_ULP_DDP_SET_REPLY,
				ETHTOOL_A_ULP_DDP_HEADER, info,
				&reply_payload);
	if (!rskb) {
		ret = -ENOMEM;
		goto err;
	}

	ret = ethnl_put_bitset(rskb, ETHTOOL_A_ULP_DDP_WANTED, wanted,
			       wanted_mask, ULP_DDP_C_COUNT,
			       ulp_ddp_caps_names, compact);
	if (ret < 0)
		goto nla_put_failure;
	ret = ethnl_put_bitset(rskb, ETHTOOL_A_ULP_DDP_ACTIVE, active,
			       active_mask, ULP_DDP_C_COUNT,
			       ulp_ddp_caps_names, compact);
	if (ret < 0)
		goto nla_put_failure;

	genlmsg_end(rskb, reply_payload);
	ret = genlmsg_reply(rskb, info);
	return ret;

nla_put_failure:
	nlmsg_free(rskb);
	WARN_ONCE(1, "calculated message payload length (%d) not sufficient\n",
		  reply_len);
err:
	GENL_SET_ERR_MSG(info, "failed to send reply message");
	return ret;
}

static int ulp_ddp_set_validate(struct ethnl_req_info *req_info, struct genl_info *info)
{
	const struct ulp_ddp_dev_ops *ops;

	if (GENL_REQ_ATTR_CHECK(info, ETHTOOL_A_ULP_DDP_WANTED))
		return -EINVAL;

	ops = netdev_ulp_ddp_ops(req_info->dev);
	if (!ops || !ops->set_caps || !netdev_ulp_ddp_caps(req_info->dev))
		return -EOPNOTSUPP;

	return 1;
}

static int ulp_ddp_set(struct ethnl_req_info *req_info, struct genl_info *info)
{
	DECLARE_BITMAP(old_active, ULP_DDP_C_COUNT);
	DECLARE_BITMAP(new_active, ULP_DDP_C_COUNT);
	DECLARE_BITMAP(req_wanted, ULP_DDP_C_COUNT);
	DECLARE_BITMAP(req_mask, ULP_DDP_C_COUNT);
	DECLARE_BITMAP(all_bits, ULP_DDP_C_COUNT);
	DECLARE_BITMAP(tmp, ULP_DDP_C_COUNT);
	const struct ulp_ddp_dev_ops *ops;
	struct ulp_ddp_netdev_caps *caps;
	int ret;

	caps = netdev_ulp_ddp_caps(req_info->dev);
	ops = netdev_ulp_ddp_ops(req_info->dev);
	ret = ethnl_parse_bitset(req_wanted, req_mask, ULP_DDP_C_COUNT,
				 info->attrs[ETHTOOL_A_ULP_DDP_WANTED],
				 ulp_ddp_caps_names, info->extack);
	if (ret < 0)
		return ret;

	/* if (req_mask & ~all_bits) */
	bitmap_fill(all_bits, ULP_DDP_C_COUNT);
	bitmap_andnot(tmp, req_mask, all_bits, ULP_DDP_C_COUNT);
	if (!bitmap_empty(tmp, ULP_DDP_C_COUNT))
		return -EINVAL;

	/* new_active = (old_active & ~req_mask) | (wanted & req_mask)
	 * new_active &= caps_hw
	 */
	bitmap_copy(old_active, caps->active, ULP_DDP_C_COUNT);
	bitmap_and(req_wanted, req_wanted, req_mask, ULP_DDP_C_COUNT);
	bitmap_andnot(new_active, old_active, req_mask, ULP_DDP_C_COUNT);
	bitmap_or(new_active, new_active, req_wanted, ULP_DDP_C_COUNT);
	bitmap_and(new_active, new_active, caps->hw, ULP_DDP_C_COUNT);
	if (!bitmap_equal(old_active, new_active, ULP_DDP_C_COUNT)) {
		ret = ops->set_caps(req_info->dev, new_active, info->extack);
		if (ret < 0)
			return ret;
		bitmap_copy(new_active, caps->active, ULP_DDP_C_COUNT);
	}

	if (!(req_info->flags & ETHTOOL_FLAG_OMIT_REPLY)) {
		bool compact = req_info->flags & ETHTOOL_FLAG_COMPACT_BITSETS;
		DECLARE_BITMAP(wanted_diff_mask, ULP_DDP_C_COUNT);
		DECLARE_BITMAP(active_diff_mask, ULP_DDP_C_COUNT);

		/* wanted_diff_mask = req_wanted ^ new_active
		 * active_diff_mask = old_active ^ new_active -> mask of bits that have changed
		 * wanted_diff_mask &= req_mask    -> mask of bits that have diff value than wanted
		 * req_wanted &= wanted_diff_mask  -> bits that have diff value than wanted
		 * new_active &= active_diff_mask  -> bits that have changed
		 */
		bitmap_xor(wanted_diff_mask, req_wanted, new_active, ULP_DDP_C_COUNT);
		bitmap_xor(active_diff_mask, old_active, new_active, ULP_DDP_C_COUNT);
		bitmap_and(wanted_diff_mask, wanted_diff_mask, req_mask, ULP_DDP_C_COUNT);
		bitmap_and(req_wanted, req_wanted, wanted_diff_mask,  ULP_DDP_C_COUNT);
		bitmap_and(new_active, new_active, active_diff_mask,  ULP_DDP_C_COUNT);
		ret = ulp_ddp_send_reply(req_info->dev, info,
					 req_wanted, wanted_diff_mask,
					 new_active, active_diff_mask,
					 compact);
		if (ret < 0)
			return ret;
	}

	/* return 1 to notify */
	return bitmap_equal(old_active, new_active, ULP_DDP_C_COUNT);
}

const struct ethnl_request_ops ethnl_ulp_ddp_request_ops = {
	.request_cmd		= ETHTOOL_MSG_ULP_DDP_GET,
	.reply_cmd		= ETHTOOL_MSG_ULP_DDP_GET_REPLY,
	.hdr_attr		= ETHTOOL_A_ULP_DDP_HEADER,
	.req_info_size		= sizeof(struct ulp_ddp_req_info),
	.reply_data_size	= sizeof(struct ulp_ddp_reply_data),

	.prepare_data		= ulp_ddp_prepare_data,
	.reply_size		= ulp_ddp_reply_size,
	.fill_reply		= ulp_ddp_fill_reply,

	.set_validate		= ulp_ddp_set_validate,
	.set			= ulp_ddp_set,
	.set_ntf_cmd		= ETHTOOL_MSG_ULP_DDP_NTF,
};
