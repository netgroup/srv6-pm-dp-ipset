/* Copyright 2007-2010 Jozsef Kadlecsik (kadlec@blackhole.kfki.hu)
 *
 * This program is free software; you can redistribute it and/or modify   
 * it under the terms of the GNU General Public License version 2 as 
 * published by the Free Software Foundation.
 */
#ifndef LIBIPSET_PARSE_H
#define LIBIPSET_PARSE_H

#include <libipset/data.h>			/* enum ipset_opt */

/* For parsing/printing data */
#define IPSET_CIDR_SEPARATOR	"/"
#define IPSET_RANGE_SEPARATOR	"-"
#define IPSET_ELEM_SEPARATOR	","
#define IPSET_NAME_SEPARATOR	","

struct ipset_session;

typedef int (*ipset_parsefn)(struct ipset_session *s,
			     enum ipset_opt opt, const char *str);

extern int ipset_parse_ether(struct ipset_session *session,
                             enum ipset_opt opt, const char *str);
extern int ipset_parse_single_port(struct ipset_session *session,
				   enum ipset_opt opt, const char *str);
extern int ipset_parse_port(struct ipset_session *session,
                            enum ipset_opt opt, const char *str);
extern int ipset_parse_family(struct ipset_session *session,
                              enum ipset_opt opt, const char *str);
extern int ipset_parse_ip(struct ipset_session *session,
                          enum ipset_opt opt, const char *str);
extern int ipset_parse_single_ip(struct ipset_session *session,
				 enum ipset_opt opt, const char *str);
extern int ipset_parse_net(struct ipset_session *session,
                           enum ipset_opt opt, const char *str);
extern int ipset_parse_range(struct ipset_session *session,
                             enum ipset_opt opt, const char *str);
extern int ipset_parse_netrange(struct ipset_session *session,
				enum ipset_opt opt, const char *str);
extern int ipset_parse_iprange(struct ipset_session *session,
			       enum ipset_opt opt, const char *str);
extern int ipset_parse_ipnet(struct ipset_session *session,
			     enum ipset_opt opt, const char *str);
extern int ipset_parse_name(struct ipset_session *session,
                            enum ipset_opt opt, const char *str);
extern int ipset_parse_before(struct ipset_session *session,
                              enum ipset_opt opt, const char *str);
extern int ipset_parse_after(struct ipset_session *session,
                             enum ipset_opt opt, const char *str);
extern int ipset_parse_setname(struct ipset_session *session,
                               enum ipset_opt opt, const char *str);
extern int ipset_parse_uint32(struct ipset_session *session,
                              enum ipset_opt opt, const char *str);
extern int ipset_parse_uint8(struct ipset_session *session,
                             enum ipset_opt opt, const char *str);
extern int ipset_parse_netmask(struct ipset_session *session,
                               enum ipset_opt opt, const char *str);
extern int ipset_parse_flag(struct ipset_session *session,
                            enum ipset_opt opt, const char *str);
extern int ipset_parse_typename(struct ipset_session *session,
				enum ipset_opt opt, const char *str);
extern int ipset_parse_output(struct ipset_session *session,
                              int opt, const char *str);
extern int ipset_parse_ignored(struct ipset_session *session,
                               enum ipset_opt opt, const char *str);
extern int ipset_parse_elem(struct ipset_session *session,
                            enum ipset_opt opt, const char *str);
extern int ipset_call_parser(struct ipset_session *session,
			     ipset_parsefn parse, const char *optstr,
			     enum ipset_opt optional, const char *str);

/* Compatibility parser functions */
extern int ipset_parse_iptimeout(struct ipset_session *session,
				 enum ipset_opt opt, const char *str);
extern int ipset_parse_name_compat(struct ipset_session *session,
				   enum ipset_opt opt, const char *str);

#endif /* LIBIPSET_PARSE_H */