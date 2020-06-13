/* TCP window modification module for IP tables
 * (C) 2015 by Sergej Pupykin <sergej@p5n.pp.ru> */

#ifndef _XT_TCPWIN_H
#define _XT_TCPWIN_H

#include <linux/types.h>

struct ipt_TWIN_info {
	__u32	win;
	__u8	wscale;
};

#endif
