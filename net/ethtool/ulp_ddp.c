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
	[ETHTOOL_A_ULP_DDP_HEADER]	=
		NLA_POLICY_NESTED(ethnl_header_policy_stats),
};

static int ulp_ddp_stats64_size(unsigned int count)
{
	unsigned int len = 0;
	unsigned int i;

	for (i = 0; i < count; i++)
		len += nla_total_size(sizeof(u64));

	/* outermost nest */
	return nla_total_size(len);
}

static int ulp_ddp_put_stats64(struct sk_buff *skb, int attrtype, const u64 *val,
			       unsigned int count)
{
	struct nlattr *nest;
	unsigned int i;

	nest = nla_nest_start(skb, attrtype);
	if (!nest)
		return -EMSGSIZE;

	/* skip attribute 0 (unspec) */
	for (i = 0 ; i < count; i++)
		if (nla_put_64bit(skb, i+1, sizeof(u64), &val[i], 0))
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
		/* When requested (ETHTOOL_FLAG_STATS) ULP DDP stats
		 * are appended to the response.
		 */
		ret = ulp_ddp_stats64_size(__ETHTOOL_A_ULP_DDP_STATS_CNT-1);
		if (ret < 0)
			return ret;
		len += ret;
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
					  __ETHTOOL_A_ULP_DDP_STATS_CNT-1);
		if (ret < 0)
			return ret;
	}
	return ret;
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
};

/* ULP_DDP_SET */

const struct nla_policy ethnl_ulp_ddp_set_policy[] = {
	[ETHTOOL_A_ULP_DDP_HEADER]	=
		NLA_POLICY_NESTED(ethnl_header_policy),
	[ETHTOOL_A_ULP_DDP_WANTED]	= { .type = NLA_NESTED },
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

	ret = -ENOMEM;
	rskb = ethnl_reply_init(reply_len, dev, ETHTOOL_MSG_ULP_DDP_SET_REPLY,
				ETHTOOL_A_ULP_DDP_HEADER, info,
				&reply_payload);
	if (!rskb)
		goto err;

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

int ethnl_set_ulp_ddp(struct sk_buff *skb, struct genl_info *info)
{
	DECLARE_BITMAP(old_active, ULP_DDP_C_COUNT);
	DECLARE_BITMAP(new_active, ULP_DDP_C_COUNT);
	DECLARE_BITMAP(req_wanted, ULP_DDP_C_COUNT);
	DECLARE_BITMAP(req_mask, ULP_DDP_C_COUNT);
	DECLARE_BITMAP(all_bits, ULP_DDP_C_COUNT);
	DECLARE_BITMAP(tmp, ULP_DDP_C_COUNT);
	struct ethnl_req_info req_info = {};
	const struct ulp_ddp_dev_ops *ops;
	struct nlattr **tb = info->attrs;
	struct ulp_ddp_netdev_caps *caps;
	struct net_device *dev;
	int ret;

	if (!tb[ETHTOOL_A_ULP_DDP_WANTED])
		return -EINVAL;
	ret = ethnl_parse_header_dev_get(&req_info,
					 tb[ETHTOOL_A_ULP_DDP_HEADER],
					 genl_info_net(info), info->extack,
					 true);
	if (ret < 0)
		return ret;

	dev = req_info.dev;
	rtnl_lock();
	caps = netdev_ulp_ddp_caps(dev);
	ops = netdev_ulp_ddp_ops(dev);
	if (!caps || !ops || !ops->set_caps) {
		ret = -EOPNOTSUPP;
		goto out_rtnl;
	}

	ret = ethnl_parse_bitset(req_wanted, req_mask, ULP_DDP_C_COUNT,
				 tb[ETHTOOL_A_ULP_DDP_WANTED],
				 ulp_ddp_caps_names, info->extack);
	if (ret < 0)
		goto out_rtnl;

	/* if (req_mask & ~all_bits) */
	bitmap_fill(all_bits, ULP_DDP_C_COUNT);
	bitmap_andnot(tmp, req_mask, all_bits, ULP_DDP_C_COUNT);
	if (!bitmap_empty(tmp, ULP_DDP_C_COUNT)) {
		ret = -EINVAL;
		goto out_rtnl;
	}

	/* new_active = (old_active & ~req_mask) | (wanted & req_mask)
	 * new_active &= caps_hw
	 */
	bitmap_copy(old_active, caps->active, ULP_DDP_C_COUNT);
	bitmap_and(req_wanted, req_wanted, req_mask, ULP_DDP_C_COUNT);
	bitmap_andnot(new_active, old_active, req_mask, ULP_DDP_C_COUNT);
	bitmap_or(new_active, new_active, req_wanted, ULP_DDP_C_COUNT);
	bitmap_and(new_active, new_active, caps->hw, ULP_DDP_C_COUNT);
	if (!bitmap_equal(old_active, new_active, ULP_DDP_C_COUNT)) {
		ret = ops->set_caps(dev, new_active);
		if (ret)
			netdev_err(dev, "set_ulp_ddp_capabilities() returned error %d\n", ret);
		bitmap_copy(new_active, caps->active, ULP_DDP_C_COUNT);
	}

	ret = 0;
	if (!(req_info.flags & ETHTOOL_FLAG_OMIT_REPLY)) {
		DECLARE_BITMAP(wanted_diff_mask, ULP_DDP_C_COUNT);
		DECLARE_BITMAP(active_diff_mask, ULP_DDP_C_COUNT);
		bool compact = req_info.flags & ETHTOOL_FLAG_COMPACT_BITSETS;

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
		ret = ulp_ddp_send_reply(dev, info,
					 req_wanted, wanted_diff_mask,
					 new_active, active_diff_mask,
					 compact);
	}

out_rtnl:
	rtnl_unlock();
	ethnl_parse_header_dev_put(&req_info);
	return ret;
}
