/*
 * TCP window modification target for IP tables
 * (C) 2015 by Sergej Pupykin <sergej@p5n.pp.ru>
 * (C) 2017 fixes by Vadim Fedorenko <junjunk@fromru.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#include <linux/version.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <net/checksum.h>
#include <net/ip.h>
#include <net/netfilter/nf_conntrack.h>

#include <linux/netfilter/x_tables.h>
#include "xt_TCPWIN.h"

MODULE_AUTHOR("Harald Welte <laforge@netfilter.org>");
MODULE_AUTHOR("Vadim Fedorenko <junjunk@fromru.com>");
MODULE_DESCRIPTION("Xtables: TCPWIN field modification target");
MODULE_LICENSE("GPL");

static unsigned int
twin_tg(struct sk_buff *skb, const struct xt_action_param *par)
{
	struct tcphdr *tcph, tcpbuf;
	__u32 win;
	const struct ipt_TWIN_info *info = par->targinfo;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct ip_ct_tcp *tcpinfo;

	/* This is a fragment, no TCP header is available */
	if (unlikely(par->fragoff != 0))
		return XT_CONTINUE;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 19, 0)
	if (skb_ensure_writable(skb, par->thoff + sizeof(struct tcphdr)))
#else
	if (!skb_make_writable(skb, par->thoff + sizeof(struct tcphdr)))
#endif
		return XT_CONTINUE;

	tcph = skb_header_pointer(skb, par->thoff, sizeof(struct tcphdr), &tcpbuf);
	if (tcph == NULL)
		return XT_CONTINUE;

	win = info->win;
	if (!tcph->syn && info->wscale) {
		ct = nf_ct_get(skb, &ctinfo);
		tcpinfo = &ct->proto.tcp;
		if (ctinfo == IP_CT_ESTABLISHED_REPLY) {
			win >>= tcpinfo->seen[IP_CT_DIR_REPLY].td_scale;
		} else if (ctinfo == IP_CT_ESTABLISHED) {
			win >>= tcpinfo->seen[IP_CT_DIR_ORIGINAL].td_scale;
		}
	}

	if (win >= 0xFFFF)
		win = 0xFFFF;
	else
		win = htons(win);

	csum_replace2(&tcph->check, tcph->window, (__be16)win);
	tcph->window = win;

	return XT_CONTINUE;
}

static int twin_tg_check(const struct xt_tgchk_param *par)
{
	const struct ipt_TWIN_info *info = par->targinfo;
	if (info->wscale)
		return nf_ct_netns_get(par->net, par->family);
	return 0;
}

static void twin_tg_destroy(const struct xt_tgdtor_param *par)
{
	const struct ipt_TWIN_info *info = par->targinfo;
	if (info->wscale)
		nf_ct_netns_put(par->net, par->family);
}

static struct xt_target hl_tg_regs[] __read_mostly = {
	{
		.name       = "TCPWIN",
		.revision   = 0,
		.family     = NFPROTO_IPV4,
		.target     = twin_tg,
		.targetsize = sizeof(struct ipt_TWIN_info),
		.table      = "mangle",
		.proto      = IPPROTO_TCP,
		.checkentry = twin_tg_check,
		.destroy    = twin_tg_destroy,
		.me         = THIS_MODULE,
	},
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
	{
		.name       = "TCPWIN",
		.revision   = 0,
		.family     = NFPROTO_IPV6,
		.target     = twin_tg,
		.targetsize = sizeof(struct ipt_TWIN_info),
		.table      = "mangle",
		.proto      = IPPROTO_TCP,
		.checkentry = twin_tg_check,
		.destroy    = twin_tg_destroy,
		.me         = THIS_MODULE,
	},
#endif
};

static int __init tcpwin_init(void)
{
	return xt_register_targets(hl_tg_regs, ARRAY_SIZE(hl_tg_regs));
}

static void __exit tcpwin_exit(void)
{
	xt_unregister_targets(hl_tg_regs, ARRAY_SIZE(hl_tg_regs));
}

module_init(tcpwin_init);
module_exit(tcpwin_exit);
MODULE_ALIAS("ipt_TCPWIN");
#if IS_ENABLED(CONFIG_IP6_NF_IPTABLES)
MODULE_ALIAS("ip6t_TCPWIN");
#endif
