
#include <libipset/data.h>			/* IPSET_OPT_* */
#include <libipset/parse.h>			/* parser functions */
#include <libipset/print.h>			/* printing functions */
#include <libipset/types.h>			/* prototypes */


static int
ipset_custom_arg_parser(struct ipset_session *s,
			enum ipset_opt opt, const char *str)
{
	return ipset_parse_srh(s, opt, str);
}

/* Initial revision */
static struct ipset_type ipset_hash_sr6 = {
	.name = "hash:sr6",
	.alias = { "sr6hash", NULL },
	.revision = 0,
	.family = NFPROTO_IPV6,
	.dimension = IPSET_DIM_ONE,
	.elem = {
		[IPSET_DIM_ONE - 1] = {
			.parse = ipset_parse_srh,
			.print = ipset_print_srh,
			.opt = IPSET_OPT_SRH
		},
	},
	.compat_parse_elem = ipset_custom_arg_parser,
	.cmd = {
		[IPSET_CREATE] = {
			.args = {
				IPSET_ARG_HASHSIZE,
				IPSET_ARG_MAXELEM,
				IPSET_ARG_TIMEOUT,
				IPSET_ARG_COUNTERS,
				IPSET_ARG_COMMENT,
				IPSET_ARG_FORCEADD,
				IPSET_ARG_SKBINFO,
				IPSET_ARG_NONE,
			},
			.need = 0,
			.full = 0,
			.help = "",
		},
		[IPSET_ADD] = {
			.args = {
				IPSET_ARG_TIMEOUT,
				IPSET_ARG_PACKETS,
				IPSET_ARG_BYTES,
				IPSET_ARG_ADT_COMMENT,
				IPSET_ARG_SKBMARK,
				IPSET_ARG_SKBPRIO,
				IPSET_ARG_SKBQUEUE,
				IPSET_ARG_NONE,
			},
			.need = IPSET_FLAG(IPSET_OPT_SRH),
			.full = IPSET_FLAG(IPSET_OPT_SRH),
			.help = "SRH",
		},
		[IPSET_DEL] = {
			.args = {
				IPSET_ARG_NONE,
			},
			.need = IPSET_FLAG(IPSET_OPT_SRH),
			.full = IPSET_FLAG(IPSET_OPT_SRH),
			.help = "SRH",
		},
		[IPSET_TEST] = {
			.args = {
				IPSET_ARG_NONE,
			},
			.need = IPSET_FLAG(IPSET_OPT_SRH),
			.full = IPSET_FLAG(IPSET_OPT_SRH),
			.help = "SRH",
		},
	},
	.usage = "",
	.description = "Initial revision",
};

void _init(void);
void _init(void)
{
	ipset_type_add(&ipset_hash_sr6);
}
