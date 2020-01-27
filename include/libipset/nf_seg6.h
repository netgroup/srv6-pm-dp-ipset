/* SPDX-License-Identifier: GPL-2.0+ WITH Linux-syscall-note */
/*
 *  SR-IPv6 implementation
 *
 *  Author:
 *  David Lebrun <david.lebrun@uclouvain.be>
 *
 *
 *  This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#ifndef _UAPI_LINUX_SEG6_H
#define _UAPI_LINUX_SEG6_H

#include <linux/types.h>
#include <linux/in6.h>		/* For struct in6_addr. */

#include <arpa/inet.h>

/*
 * SRH
 */
struct ipv6_sr_hdr {
	__u8	nexthdr;
	__u8	hdrlen;
	__u8	type;
	__u8	segments_left;
	__u8	first_segment;
	__u8	flags;
	__u16	reserved;

	struct in6_addr segments[0];
};

#define SR6_FLAG1_PROTECTED	(1 << 6)
#define SR6_FLAG1_OAM		(1 << 5)
#define SR6_FLAG1_ALERT		(1 << 4)
#define SR6_FLAG1_HMAC		(1 << 3)

#define SR6_TLV_INGRESS		1
#define SR6_TLV_EGRESS		2
#define SR6_TLV_OPAQUE		3
#define SR6_TLV_PADDING		4
#define SR6_TLV_HMAC		5

#define sr_has_hmac(srh) ((srh)->flags & SR6_FLAG1_HMAC)

struct sr6_tlv {
	__u8 type;
	__u8 len;
	__u8 data[0];
};


/* Currently, nf_srh support 16 segments at least. If you want to change this
 * limit, please update also the NF_SRH_SEGS_MAX macro declared in
 * ip_set_hash_sr6.c.  This limitation will be solved in the next release, but
 * in the meanwhile this could be a starting point :)
 */
#define NF_SRH_SEGS_MAX 16

/* For evaluating the size of member inside the structure type */
#define sizeof_member(__type, __member) sizeof(((__type *) 0)->__member)

/* We evaluate the size of the NF_SRH in bytes */
#define __NF_SRH_SIZE 	(sizeof(struct ipv6_sr_hdr) + NF_SRH_SEGS_MAX *	\
			 sizeof_member(struct ipv6_sr_hdr, 		\
			 segments[0]))

/* @Andrea */
struct nf_srh {
	union {
		struct ipv6_sr_hdr __srh;
		__u8   __data[__NF_SRH_SIZE];
	}__hdr;

#define nf_srv6_hdr(__h) (&((__h)->__hdr.__srh))
};

#endif
