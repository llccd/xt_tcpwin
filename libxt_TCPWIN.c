/* Shared library add-on to iptables for the TCP window target
 * (C) 2015 by Sergej Pupykin <sergej@p5n.pp.ru>
 *
 * This program is distributed under the terms of GNU GPL
 */
#include <stdio.h>
#include <xtables.h>
#include "xt_TCPWIN.h"

enum {
	O_TCPWIN = 0,
	O_WSCALE,
};

static const struct xt_option_entry TWIN_opts[] = {
	{.name = "tcpwin-set", .type = XTTYPE_UINT32, .id = O_TCPWIN, .flags = XTOPT_PUT, XTOPT_POINTER(struct ipt_TWIN_info, win)},
	{.name = "wscale", .id = O_WSCALE, .type = XTTYPE_NONE},
	XTOPT_TABLEEND,
};

static void TWIN_help(void)
{
	printf("TCP window target options\n"
		"  --tcpwin-set value		Set TCP window to <value>\n"
		"  --wscale			Get TCP wscale from conntrack\n");
}

static void TWIN_parse(struct xt_option_call *cb)
{
	struct ipt_TWIN_info *info = (struct ipt_TWIN_info *) cb->data;
	xtables_option_parse(cb);
	if(cb->entry->id == O_WSCALE)
		info->wscale = true;
}

static void TWIN_save(const void *ip, const struct xt_entry_target *target)
{
	const struct ipt_TWIN_info *info = (struct ipt_TWIN_info *) target->data;
	printf(" --tcpwin-set %u", ntohs(info->win));
	if(info->wscale)
		printf(" --wscale");
}

static void TWIN_print(const void *ip, const struct xt_entry_target *target, int numeric)
{
	const struct ipt_TWIN_info *info = (struct ipt_TWIN_info *) target->data;
	printf(" TCP window %u", ntohs(info->win));
	if(info->wscale)
		printf(" with wscale");
}

static struct xtables_target twin_tg_reg = {
	.name		= "TCPWIN",
	.version	= XTABLES_VERSION,
	.family		= NFPROTO_UNSPEC,
	.size		= XT_ALIGN(sizeof(struct ipt_TWIN_info)),
	.userspacesize	= XT_ALIGN(sizeof(struct ipt_TWIN_info)),
	.help		= TWIN_help,
	.print		= TWIN_print,
	.save		= TWIN_save,
	.x6_parse	= TWIN_parse,
	.x6_options	= TWIN_opts,
};

void _init(void)
{
	xtables_register_target(&twin_tg_reg);
}
