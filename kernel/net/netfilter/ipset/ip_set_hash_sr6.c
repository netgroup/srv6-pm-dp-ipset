
#include <linux/jhash.h>
#include <linux/module.h>
#include <linux/etherdevice.h>
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <linux/if_ether.h>
#include <net/ipv6.h>
#include <linux/seg6.h>
#include <net/seg6.h>
#include <net/netlink.h>
#include <linux/slab.h>

#include <linux/netfilter.h>
#include <linux/netfilter/ipset/ip_set.h>
#include <linux/netfilter/ipset/ip_set_hash.h>

#define IPSET_TYPE_REV_MIN	0
#define IPSET_TYPE_REV_MAX	0

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrea Mayer <andrea.mayer@uniroma2.it>");
IP_SET_MODULE_DESC("hash:sr6", IPSET_TYPE_REV_MIN, IPSET_TYPE_REV_MAX);
MODULE_ALIAS("ip_set_hash:sr6");
MODULE_VERSION("1.1");

#define ipv6srh(__ptr, __off) ((struct ipv6_sr_hdr *)((__ptr) + (__off)))

/* Type specific function prefix */
#define HTYPE			hash_sr

/* IPv4 variant. Fake variant just to let the compiler be happy. */
/* Member elements */
struct hash_sr4_elem { /* dummy */ };

/* Common functions */
static inline bool
hash_sr4_data_equal(const struct hash_sr4_elem *e1,
		    const struct hash_sr4_elem *e2,
		    u32 *multi)
{
	return -EOPNOTSUPP;
}

static inline bool
hash_sr4_data_list(struct sk_buff *skb, const struct hash_sr4_elem *e)
{
	return -EOPNOTSUPP;
}

static inline void
hash_sr4_data_next(struct hash_sr4_elem *next,
		   const struct hash_sr4_elem *e)
{
}

#define MTYPE		hash_sr4
#define HOST_MASK	32
#include "ip_set_hash_gen.h"

static int
hash_sr4_kadt(struct ip_set *set, const struct sk_buff *skb,
	      const struct xt_action_param *par,
	      enum ipset_adt adt, struct ip_set_adt_opt *opt)
{
	return -EOPNOTSUPP;
}

static int
hash_sr4_uadt(struct ip_set *set, struct nlattr *tb[],
	      enum ipset_adt adt, u32 *lineno, u32 flags, bool retried)
{
	return -EOPNOTSUPP;
}


/* IPv6 Variant (the only one that is supported) */

/* please, keep this macro aligned with the one declared in
 * libipset/nf_seg6.h.  This limitation will be solved in the next
 * release.
 */
#define NF_SRH_SEGS_MAX 16

/* for evaluating the size of member inside the structure type */
#define sizeof_member(__type, __member) sizeof(((__type *) 0)->__member)

/* ee evaluate the size of the NF_SRH in bytes */
#define __NF_SRH_SIZE 	(sizeof(struct ipv6_sr_hdr) + NF_SRH_SEGS_MAX *	\
			 sizeof_member(struct ipv6_sr_hdr, 		\
			 segments[0]))

/* @Andrea */
struct nf_srh {
	union {
		struct ipv6_sr_hdr __srh;
		__u8   __data[__NF_SRH_SIZE];
	}__hdr;
};

#define nf_srv6_hdr(__h) (&((__h)->__hdr.__srh))

/* member elements */
struct hash_sr6_elem {
	struct nf_srh srh;

	/* here fields that MUST NOT be considered by the hashing function */
};

#define srv6hdr(__e)  							\
	((struct ipv6_sr_hdr *) 					\
	 nf_srv6_hdr(&(((struct hash_sr6_elem *) __e)->srh)))

/* we (re)define the HKEY_DATALEN that is used in macro HKEY for evaluating
 * the hash of an hash_sr6_elem element. Hash is done only on the
 * [0,sizeof(struct nf_srh)] bytes of hash_sr6_elem so that we can put
 * other fields after @srh and they will not be considered during the
 * operation.
 */
#ifdef HKEY_DATALEN
	#undef HKEY_DATALEN
#endif
#define HKEY_DATALEN	sizeof(struct nf_srh)

#ifdef HKEY
	#undef HKEY
#endif
#define HKEY(data, initval, htable_bits)				\
({									\
	const struct ipv6_sr_hdr *__srh = srv6hdr(data);		\
	const u32 *__k = (const u32 *) &(__srh->segments[0]);		\
	u32 __l = ((__srh->first_segment + 1) *				\
		   sizeof(__srh->segments[0])) / sizeof(u32);		\
									\
	BUILD_BUG_ON(HKEY_DATALEN % sizeof(u32) != 0);			\
									\
	jhash2(__k, __l, initval) & jhash_mask(htable_bits);		\
})

/*
 * This structure is used to hold temporary data during kadt and uadt
 * operations. Indeed, is not safe to store huge structures into the kernel
 * stack.
 */
#define HASH_SR6_ELEM_CACHE_NAME "hash_sr6_elem_cache"

static struct kmem_cache *hash_sr6_elem_cache;

/* return a fresh element from the cache that could be zero initialized on
 * the basis of @zeros parameter. Returns the address of the element in
 * case of success, NULL otherwise.
 */
static inline struct
hash_sr6_elem *const hash_sr6_elem_alloc(bool zeros)
{
	return kmem_cache_alloc(hash_sr6_elem_cache,
			        (GFP_ATOMIC | (zeros ? __GFP_ZERO : 0x0u)));
}

/* free a cache element so that it could be reused after */
static inline void
hash_sr6_element_destroy(struct hash_sr6_elem *const e)
{
	kmem_cache_free(hash_sr6_elem_cache, e);
}

static inline int
hash_sr6_elem_init(struct hash_sr6_elem *const e)
{
	if (unlikely(!e))
		return -EINVAL;

	memset((void *const) e, 0, sizeof(*e));

	return 0;
}

/* Common functions */

static inline bool
hash_sr6_data_equal(const struct hash_sr6_elem *e1,
		    const struct hash_sr6_elem *e2,
		    u32 *multi)
{
	const int nsegs_e1 = srv6hdr(e1)->first_segment + 1;
	const int nsegs_e2 = srv6hdr(e2)->first_segment + 1;

	if (nsegs_e1 != nsegs_e2)
		return false;

	return !memcmp(srv6hdr(e1)->segments,
		       srv6hdr(e2)->segments,
		       nsegs_e1 * sizeof(srv6hdr(e1)->segments[0]));
}

static inline bool
hash_sr6_data_list(struct sk_buff *skb, const struct hash_sr6_elem *e)
{
	int srhlen = (srv6hdr(e)->hdrlen + 1) << 3;

	if (nla_put(skb, IPSET_ATTR_SRH, srhlen, srv6hdr(e)))
		goto nla_put_failure;

	return false;

nla_put_failure:
	return true;
}

static inline int
hash_sr6_data_memcpy(struct hash_sr6_elem *const dst,
		     const struct ipv6_sr_hdr *const src)
{
	struct ipv6_sr_hdr *sr_dst;
	int nsegs;

	sr_dst = (struct ipv6_sr_hdr *) srv6hdr(dst);
	nsegs = src->first_segment + 1;

	if (unlikely(nsegs > NF_SRH_SEGS_MAX))
		return -ENOMEM;

	/* we start to copy data */
	sr_dst->first_segment = nsegs - 1;
	sr_dst->hdrlen = src->hdrlen;
	memcpy(sr_dst->segments, src->segments,
	       nsegs * sizeof(sr_dst->segments[0]));

	return 0;
}

static inline void
hash_sr6_data_next(struct hash_sr6_elem *next,
		   const struct hash_sr6_elem *e)
{
	hash_sr6_elem_init(next);
	hash_sr6_data_memcpy(next, srv6hdr(e));
}

static inline int
hash_sr6_srh_uval(const struct ipv6_sr_hdr *const srh)
{
	int nsegs, srhlen;

	if (srh->type != IPV6_SRCRT_TYPE_4)
		return -EINVAL;

	srhlen = (srh->hdrlen + 1) << 3;
	nsegs = srh->first_segment + 1;

	if (unlikely(1 > nsegs || 8 > srhlen))
		return -EINVAL;

	if (unlikely((sizeof(srh->segments[0]) * nsegs +
		     sizeof(*srh)) != srhlen))
		return -EINVAL;

	/* note: we do not validate segment_left field because it is not
	 * considered into the hasing operation yet. This means that we
	 * consider ALWAYS segment_left equals to 0.
	 */

	return 0;
}

static inline int
hash_sr6_srh_kval(struct sk_buff *const skb,
		  struct ipv6_sr_hdr **srv6hdr)
{
	struct ipv6_sr_hdr *srh;
	int len, srhoff = 0;
	int ret;

	if (ipv6_find_hdr(skb, &srhoff, IPPROTO_ROUTING, NULL, NULL) < 0)
		return -ENOENT;

	if (!pskb_may_pull(skb, srhoff + sizeof(*srh)))
		return -ENOENT;

	srh = ipv6srh(skb->data, srhoff);
	len = (srh->hdrlen + 1) << 3;

	if (!pskb_may_pull(skb, srhoff + len))
		return -ENOENT;

	/* all the pointers pointing into skb header may change after
	 * pskb_may_pull() and must be reloaded after call to this
	 * funciton.
	 *
	 * note: srhoff is still valid because it is a relative offset with
	 * respect to the position of the outer ipv6hdr.
	 */
	srh = ipv6srh(skb->data, srhoff);

	/* we check for the internal structure of srh */
	if ((ret = hash_sr6_srh_uval(srh)))
		return ret;

	if (srv6hdr)
		*srv6hdr = srh;

	return 0;
}

#undef MTYPE
#undef HOST_MASK

#define MTYPE		hash_sr6
#define HOST_MASK	128
#define IP_SET_EMIT_CREATE
#include "ip_set_hash_gen.h"

static inline int
hash_sr6_elem_alloc_manager(enum ipset_adt adt, struct hash_sr6_elem **e,
			    struct ipv6_sr_hdr *srh, bool zeros, bool *cached)
{
	struct hash_sr6_elem *sr6_elem = NULL;
	bool release_cache = false;
	int ret = -EINVAL;
	int nsegs;

	switch(adt) {
	case IPSET_ADD:
		/* fall through  */
	case IPSET_CREATE:
		/* we create a temporary element into the cache */
		if (unlikely(!(sr6_elem = hash_sr6_elem_alloc(zeros))))
			return -ENOMEM;

		release_cache = true;

		/* we copy the relevant part of SRH for doing the hash in
		 * the right way. Indeed we mask all those fields that are
		 * not used in order to hash the srh properly.
		 */
		if (unlikely(ret = hash_sr6_data_memcpy(sr6_elem, srh)))
			goto err;

		*e = sr6_elem;
		break;
	default:
		nsegs = srh->first_segment + 1;

		if (unlikely(nsegs > NF_SRH_SEGS_MAX))
			return -ENOMEM;

		/* for delete and test we do not need to copy data into an
		 * auxiliary structure. Indeed, we perform the operation by
		 * looking at the segments list and we do not need to store
		 * a SRH zeroed header (as opposed to add and create use
		 * cases). The hash function has been redefined, so that
		 * now we look always at some srh specific fields instead
		 * of the whole structure.
		 */
		*e = (struct hash_sr6_elem *) srh;
		break;
	};

	*cached = release_cache;

	return 0;

err:
	if (release_cache)
		hash_sr6_element_destroy(sr6_elem);

	return ret;
}

static int
hash_sr6_kadt(struct ip_set *set, const struct sk_buff *skb,
	      const struct xt_action_param *par,
	      enum ipset_adt adt, struct ip_set_adt_opt *opt)
{
	struct ip_set_ext ext = IP_SET_INIT_KEXT(skb, opt, set);
	ipset_adtfn adtfn = set->variant->adt[adt];
	bool release_cache = false;
	struct hash_sr6_elem *e;
	struct ipv6_sr_hdr *srh;
	int ret;

	/* we validate the srh and and then we retrieve the reference to
	 * this structure within the packet.
	 */
	if ((ret = hash_sr6_srh_kval((struct sk_buff *) skb, &srh)))
		return ret;

	if (unlikely(!srh))
		return -EINVAL;

	if (unlikely((ret = hash_sr6_elem_alloc_manager(adt, &e, srh, true,
							&release_cache))))
		return ret;

	ret = adtfn(set, e, &ext, &opt->ext, opt->cmdflags);

	if (unlikely(release_cache))
		hash_sr6_element_destroy(e);

	return ret;
}

static int
hash_sr6_uadt(struct ip_set *set, struct nlattr *tb[],
	      enum ipset_adt adt, u32 *lineno, u32 flags, bool retried)
{
	struct ip_set_ext ext = IP_SET_INIT_UEXT(set);
	ipset_adtfn adtfn = set->variant->adt[adt];
	bool release_cache = false;
	struct hash_sr6_elem *e;
	struct ipv6_sr_hdr *srh;
	int ret;

	if (tb[IPSET_ATTR_LINENO])
		*lineno = nla_get_u32(tb[IPSET_ATTR_LINENO]);

	if (unlikely(!tb[IPSET_ATTR_SRH] || (sizeof(struct nf_srh)
		     < nla_len(tb[IPSET_ATTR_SRH]))))
		return -IPSET_ERR_PROTOCOL;

	if ((ret = ip_set_get_extensions(set, tb, &ext)))
		return ret;

	if (!(srh = (struct ipv6_sr_hdr *) nla_data(tb[IPSET_ATTR_SRH])))
		return -IPSET_ERR_IPADDR_IPV6;

	/* we validate the srh given by userpsace */
	if ((ret = hash_sr6_srh_uval(srh)))
		return ret;

	if (unlikely((ret = hash_sr6_elem_alloc_manager(adt, &e, srh, true,
							&release_cache))))
		return ret;

	ret = adtfn(set, e, &ext, &ext, flags);

	if (unlikely(release_cache))
		hash_sr6_element_destroy(e);

	return ret;
}

static struct ip_set_type hash_sr_type __read_mostly = {
	.name		= "hash:sr6",
	.protocol	= IPSET_PROTOCOL,
	.features	= IPSET_TYPE_IP,
	.dimension	= IPSET_DIM_ONE,
	.family		= NFPROTO_IPV6,
	.revision_min	= IPSET_TYPE_REV_MIN,
	.revision_max	= IPSET_TYPE_REV_MAX,
	.create		= hash_sr_create,
	.create_policy	= {
		[IPSET_ATTR_HASHSIZE]	= { .type = NLA_U32 },
		[IPSET_ATTR_MAXELEM]	= { .type = NLA_U32 },
		[IPSET_ATTR_PROBES]	= { .type = NLA_U8  },
		[IPSET_ATTR_RESIZE]	= { .type = NLA_U8  },
		[IPSET_ATTR_TIMEOUT]	= { .type = NLA_U32 },
		[IPSET_ATTR_CADT_FLAGS]	= { .type = NLA_U32 },
	},
	.adt_policy	= {
		[IPSET_ATTR_SRH]	= { .type = NLA_BINARY },
		[IPSET_ATTR_TIMEOUT]	= { .type = NLA_U32 },
		[IPSET_ATTR_LINENO]	= { .type = NLA_U32 },
		[IPSET_ATTR_BYTES]	= { .type = NLA_U64 },
		[IPSET_ATTR_PACKETS]	= { .type = NLA_U64 },
		[IPSET_ATTR_SKBMARK]	= { .type = NLA_U64 },
		[IPSET_ATTR_SKBPRIO]	= { .type = NLA_U32 },
		[IPSET_ATTR_SKBQUEUE]	= { .type = NLA_U16 },
	},
	.me		= THIS_MODULE,
};

static int __init hash_sr_init(void)
{
	/* we create a cache for storing temporary hash_sr6_elem(s). In
	 * this way we avoid filling the stack by allocating temporary
	 * elements that can be huge. These elements are used during some
	 * operations such as kadt/uadt to hold intermediate results and
	 * they are no longer needed after processing. Indeed, ipset makes
	 * a copy of processed hash_sr6_elem(s) and cache objects can be
	 * safely discared.
	 */
	hash_sr6_elem_cache = kmem_cache_create(HASH_SR6_ELEM_CACHE_NAME,
						sizeof(struct hash_sr6_elem),
						0, SLAB_HWCACHE_ALIGN |
						SLAB_PANIC, NULL);
	if (!hash_sr6_elem_cache) {
		pr_debug("cache creation failed.\n");
		return -ENOMEM;
	}

	return ip_set_type_register(&hash_sr_type);
}

static void __exit hash_sr_fini(void)
{
	rcu_barrier();
	ip_set_type_unregister(&hash_sr_type);

	/* here the current hash type is not available anymore and thus we
	 * cannot be in any function that uses cache objects. Therefore, we
	 * can destroy the entire cache and free the memory.
	 *
	 * note: a cache element (or object) is designed to be destroyed
	 * immediately after its use. This means that we cannot have any
	 * remaining element into the cache at this point. If this is not
	 * true, than there are some BUGs or there is a misuse of the
	 * cache.
	 */
	kmem_cache_destroy(hash_sr6_elem_cache);
}

module_init(hash_sr_init);
module_exit(hash_sr_fini);
