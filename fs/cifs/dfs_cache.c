/*
 *  DFS referral cache routines.
 *
 *  Copyright (c) 2018 Paulo Alcantara <palcantara@suse.de>
 *
 *  This library is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License v2 as published
 *  by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 *  the GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this library; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#include <linux/rcupdate.h>
#include <linux/rculist.h>
#include <linux/jhash.h>
#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/nls.h>
#include "cifsglob.h"
#include "smb2pdu.h"
#include "smb2proto.h"
#include "cifsproto.h"
#include "cifs_debug.h"
#include "cifs_unicode.h"
#include "smb2glob.h"

#include "dfs_cache.h"

/*
 * TODO: add LRU (probably from linux/list_lru.h) to limit number of DFS cache
 * entries.
 */

#define DFS_CACHE_HTABLE_SIZE 32

#define IS_INTERLINK_SET(v) ((v) & (DFSREF_REFERRAL_SERVER | \
				    DFSREF_STORAGE_SERVER))

struct dfs_cache_tgt {
	char *t_name;
	struct list_head t_list;
};

struct dfs_cache_entry {
	struct hlist_node ce_hlist;
	const char *ce_path;
	int ce_ttl;
	int ce_srvtype;
	int ce_flags;
	struct timespec64 ce_etime;
	int ce_path_consumed;
	struct list_head ce_tlist;
	struct dfs_cache_tgt *ce_tgthint;
	struct rcu_head ce_rcu;
};

static struct kmem_cache *dfs_cache_slab __read_mostly;

static DEFINE_MUTEX(dfs_cache_lock);
static struct hlist_head dfs_cache_htable[DFS_CACHE_HTABLE_SIZE];

#ifdef CONFIG_CIFS_DEBUG2
static inline void dump_tgts(const struct dfs_cache_entry *ce)
{
	struct dfs_cache_tgt *t;

	cifs_dbg(FYI, "target list:\n");
	list_for_each_entry(t, &ce->ce_tlist, t_list) {
		cifs_dbg(FYI, "  %s%s\n", t->t_name,
			 ce->ce_tgthint == t ? " (target hint)" : "");
	}
}

static inline void dump_ce(const struct dfs_cache_entry *ce)
{
	cifs_dbg(FYI, "cache entry: path=%s,ttl=%d,etime=%ld,"
		 "interlink=%s,path_consumed=%d\n", ce->ce_path, ce->ce_ttl,
		 ce->ce_etime.tv_nsec,
		 IS_INTERLINK_SET(ce->ce_flags) ? "yes" : "no",
		 ce->ce_path_consumed);
	dump_tgts(ce);
}

static inline void dump_refs(const struct dfs_info3_param *refs, int numrefs)
{
	int i;

	cifs_dbg(FYI, "DFS referrals returned by the server:\n");
	for (i = 0; i < numrefs; i++) {
		const struct dfs_info3_param *ref = &refs[i];
		cifs_dbg(FYI,
			 "\n"
			 "flags:         0x%x\n"
			 "path_consumed: %d\n"
			 "server_type:   0x%x\n"
			 "ref_flag:      0x%x\n"
			 "path_name:     %s\n"
			 "node_name:     %s\n"
			 "ttl:           %d (%dm)\n",
			 ref->flags, ref->path_consumed, ref->server_type,
			 ref->ref_flag, ref->path_name, ref->node_name,
			 ref->ttl, ref->ttl / 60);
	}
}
#else
#define dump_tgts(e)
#define dump_ce(e)
#define dump_refs(r, n)
#endif

int dfs_cache_init(void)
{
	int i;

	dfs_cache_slab = kmem_cache_create("cifs_dfs_cache",
					   sizeof(struct dfs_cache_entry), 0,
					   SLAB_HWCACHE_ALIGN, NULL);
	if (!dfs_cache_slab)
		return -ENOMEM;

	for (i = 0; i < DFS_CACHE_HTABLE_SIZE; i++)
		INIT_HLIST_HEAD(&dfs_cache_htable[i]);

	cifs_dbg(FYI, "%s: Initialized DFS referral cache\n", __func__);
	return 0;
}

static inline unsigned int cache_entry_hash(const void *data, int size)
{
	unsigned int h;

	h = jhash(data, size, 0);
	return h & (DFS_CACHE_HTABLE_SIZE - 1);
}

static inline bool is_sysvol_or_netlogon(const char *path)
{
	const char *s;

	s = strchr(path + 1, '\\') + 1;
	return !strncasecmp(s, "sysvol", strlen("sysvol")) ||
		!strncasecmp(s, "netlogon", strlen("netlogon"));
}

static inline char *get_tgt_name(const struct dfs_cache_entry *ce)
{
	struct dfs_cache_tgt *t = ce->ce_tgthint;
	return t ? t->t_name : NULL;
}

static inline char *get_next_tgt_name(struct dfs_cache_entry *ce)
{
	struct dfs_cache_tgt *t, *n;

	t = ce->ce_tgthint;
	if (!t)
		return NULL;
	if (list_is_last(&t->t_list, &ce->ce_tlist))
		n = NULL;
	else
		n = list_next_entry(t, t_list);
	ce->ce_tgthint = n;
	return n ? n->t_name : NULL;
}

static inline struct timespec64 get_expire_time(int ttl)
{
	struct timespec64 ts = {
		.tv_sec = ttl,
		.tv_nsec = 0,
	};

	return timespec64_add(current_kernel_time64(), ts);
}

static inline void free_tgts(struct dfs_cache_entry *ce)
{
	struct dfs_cache_tgt *t, *n;

	list_for_each_entry_safe(t, n, &ce->ce_tlist, t_list) {
		list_del(&t->t_list);
		kfree(t->t_name);
		kfree(t);
	}
}

static inline struct dfs_cache_tgt *alloc_tgt(const char *name)
{
	struct dfs_cache_tgt *t;

	t = kmalloc(sizeof(*t), GFP_KERNEL);
	if (!t)
		return ERR_PTR(-ENOMEM);
	t->t_name = kstrndup(name, strlen(name), GFP_KERNEL);
	if (!t->t_name) {
		kfree(t);
		return ERR_PTR(-ENOMEM);
	}
	INIT_LIST_HEAD(&t->t_list);
	return t;
}

static int copy_ref_data(const struct dfs_info3_param *refs, int numrefs,
			 struct dfs_cache_entry *ce, const char *tgthint)
{
	int i;

	ce->ce_ttl = refs[0].ttl;
	ce->ce_etime = get_expire_time(ce->ce_ttl);
	ce->ce_srvtype = refs[0].server_type;
	ce->ce_flags = refs[0].ref_flag;
	ce->ce_path_consumed = refs[0].path_consumed;

	for (i = 0; i < numrefs; i++) {
		struct dfs_cache_tgt *t;

		t = alloc_tgt(refs[i].node_name);
		if (IS_ERR(t)) {
			free_tgts(ce);
			return PTR_ERR(t);
		}
		if (tgthint && !strncasecmp(t->t_name, tgthint,
					    strlen(tgthint))) {
			list_add(&t->t_list, &ce->ce_tlist);
			tgthint = NULL;
		} else {
			list_add_tail(&t->t_list, &ce->ce_tlist);
		}
	}

	ce->ce_tgthint = list_first_entry_or_null(&ce->ce_tlist,
						  struct dfs_cache_tgt, t_list);

	return 0;
}

static struct dfs_cache_entry *alloc_cache_entry(const char *path,
						 const struct dfs_info3_param *refs,
						 int numrefs)
{
	struct dfs_cache_entry *ce;
	int rc;

	ce = kmem_cache_zalloc(dfs_cache_slab, GFP_KERNEL);
	if (!ce)
		return ERR_PTR(-ENOMEM);

	ce->ce_path = kstrdup_const(path, GFP_KERNEL);
	if (!ce->ce_path) {
		kfree(ce);
		return ERR_PTR(-ENOMEM);
	}
	INIT_HLIST_NODE(&ce->ce_hlist);
	INIT_LIST_HEAD(&ce->ce_tlist);

	rc = copy_ref_data(refs, numrefs, ce, NULL);
	if (rc) {
		kfree(ce->ce_path);
		kfree(ce);
		ce = ERR_PTR(rc);
	}
	return ce;
}

static inline struct dfs_cache_entry *add_cache_entry(unsigned int hash,
						      const char *path,
						      const struct dfs_info3_param *refs,
						      int numrefs)
{
	struct dfs_cache_entry *ce;

	ce = alloc_cache_entry(path, refs, numrefs);
	if (IS_ERR(ce))
		return ce;

	hlist_add_head_rcu(&ce->ce_hlist, &dfs_cache_htable[hash]);
	return ce;
}

static inline struct dfs_cache_entry *__find_cache_entry(unsigned int hash,
							 const char *path,
							 int len)
{
	struct dfs_cache_entry *ce;
	bool found = false;

	rcu_read_lock();
	hlist_for_each_entry_rcu(ce, &dfs_cache_htable[hash], ce_hlist) {
		if (!strncasecmp(ce->ce_path, path, len)) {
			char *name = get_tgt_name(ce);
			cifs_dbg(FYI, "%s: cache hit\n", __func__);
			cifs_dbg(FYI, "%s: target hint: %s\n", __func__,
				 name ? name : "none");
			found = true;
			break;
		}
	}
	rcu_read_unlock();
	return found ? ce : ERR_PTR(-ENOENT);
}

static struct dfs_cache_entry *find_cache_entry(const char *path,
						unsigned int *hash)
{
	const char *s, *q;
	int len;
	struct dfs_cache_entry *ce;

	len = strlen(path);

	s = strchr(path + 1, '\\');
	s = strchr(s + 1, '\\');
	if (!s) {
		*hash = cache_entry_hash(path, len);
		return __find_cache_entry(*hash, path, len);
	}

	q = path + len - 1;
	do {
		len = q - path + 1;
		*hash = cache_entry_hash(path, len);
		ce = __find_cache_entry(*hash, path, len);
		if (!IS_ERR(ce))
			break;
		while (*q-- != '\\');
	} while (q > s);
	return ce;
}

static void free_cache_entry(struct rcu_head *rcu)
{
	struct dfs_cache_entry *ce = container_of(rcu, struct dfs_cache_entry,
						  ce_rcu);
	kmem_cache_free(dfs_cache_slab, ce);
}

static inline void flush_cache_ent(struct dfs_cache_entry *ce)
{
	if (hlist_unhashed(&ce->ce_hlist))
		return;

	hlist_del_init_rcu(&ce->ce_hlist);
	kfree(ce->ce_path);
	free_tgts(ce);
	call_rcu(&ce->ce_rcu, free_cache_entry);
}

static void flush_cache_ents(void)
{
	int i;

	rcu_read_lock();
	for (i = 0; i < DFS_CACHE_HTABLE_SIZE; i++) {
		struct hlist_head *l = &dfs_cache_htable[i];
		struct dfs_cache_entry *ce;

		hlist_for_each_entry_rcu(ce, l, ce_hlist)
			flush_cache_ent(ce);
	}
	rcu_read_unlock();
}

static inline void destroy_slab_cache(void)
{
	rcu_barrier();
	kmem_cache_destroy(dfs_cache_slab);
}

void dfs_cache_destroy(void)
{
	mutex_lock(&dfs_cache_lock);
	flush_cache_ents();
	mutex_unlock(&dfs_cache_lock);
	destroy_slab_cache();
	cifs_dbg(FYI, "%s: Destroyed DFS referral cache\n", __func__);
}

static inline struct dfs_cache_entry *__update_cache_entry(const char *path,
							   const struct dfs_info3_param *refs,
							   int numrefs)
{
	int rc;
	unsigned int h;
	struct dfs_cache_entry *ce;
	char *s, *th = NULL;

	ce = find_cache_entry(path, &h);
	if (IS_ERR(ce))
		return ce;

	if (ce->ce_tgthint) {
		s = ce->ce_tgthint->t_name;
		th = kstrndup(s, strlen(s), GFP_KERNEL);
		if (!th)
			return ERR_PTR(-ENOMEM);
	}

	free_tgts(ce);

	rc = copy_ref_data(refs, numrefs, ce, th);
	kfree(th);

	if (rc)
		ce = ERR_PTR(rc);

	return ce;
}

static struct dfs_cache_entry *update_cache_entry(const unsigned int xid,
						  struct cifs_ses *ses,
						  const struct nls_table *nls_codepage,
						  int remap,
						  const char *path,
						  struct dfs_cache_entry *ce)
{
	int rc;
	struct dfs_info3_param *refs = NULL;
	int numrefs = 0;

	cifs_dbg(FYI, "%s: update expired cache entry\n", __func__);

	if (!ses || !ses->server || !ses->server->ops->get_dfs_refer)
		return ERR_PTR(-ENOSYS);
	if (unlikely(!nls_codepage))
		return ERR_PTR(-EINVAL);

	cifs_dbg(FYI, "%s: DFS referral request for %s\n", __func__, path);

	rc = ses->server->ops->get_dfs_refer(xid, ses, path, &refs, &numrefs,
					     nls_codepage, remap);
	if (rc)
		ce = ERR_PTR(rc);
	else
		ce = __update_cache_entry(path, refs, numrefs);

	dump_refs(refs, numrefs);
	free_dfs_info_array(refs, numrefs);

	return ce;
}

static struct dfs_cache_entry *do_dfs_cache_find(const unsigned int xid,
						 struct cifs_ses *ses,
						 const struct nls_table *nls_codepage,
						 int remap, const char *path)
{
	int rc;
	unsigned int h;
	struct timespec64 ts;
	bool interlink;
	struct dfs_cache_entry *ce;
	struct dfs_info3_param *nrefs;
	int numnrefs;

	for (;;) {
		cifs_dbg(FYI, "%s: search path: %s\n", __func__, path);

		ce = find_cache_entry(path, &h);
		if (IS_ERR(ce)) {
			cifs_dbg(FYI, "%s: cache miss\n", __func__);

			if (!ses || !ses->server ||
			    !ses->server->ops->get_dfs_refer) {
				ce = ERR_PTR(-ENOSYS);
				break;
			}
			if (unlikely(!nls_codepage)) {
				ce = ERR_PTR(-EINVAL);
				break;
			}

			nrefs = NULL;
			numnrefs = 0;

			cifs_dbg(FYI, "%s: DFS referral request for %s\n",
				 __func__, path);

			rc = ses->server->ops->get_dfs_refer(xid, ses, path,
							     &nrefs, &numnrefs,
							     nls_codepage,
							     remap);
			if (rc) {
				ce = ERR_PTR(rc);
				break;
			}

			dump_refs(nrefs, numnrefs);

			cifs_dbg(FYI, "%s: new cache entry\n", __func__);

			ce = add_cache_entry(h, path, nrefs, numnrefs);
			free_dfs_info_array(nrefs, numnrefs);

			if (IS_ERR(ce))
				break;
		}

		dump_ce(ce);

		interlink = IS_INTERLINK_SET(ce->ce_flags);

		ts = current_kernel_time64();
		if (timespec64_compare(&ts, &ce->ce_etime) >= 0) {
			cifs_dbg(FYI, "%s: expired TTL\n", __func__);
			ce = update_cache_entry(xid, ses, nls_codepage, remap,
						path, ce);
			if (IS_ERR(ce)) {
				cifs_dbg(FYI, "%s: failed to update expired entry\n",
					 __func__);
				break;
			}
			interlink = IS_INTERLINK_SET(ce->ce_flags);
		} else if (!ce->ce_tgthint) {
			cifs_dbg(FYI, "%s: unexpired entry, but no target servers left\n",
				 __func__);
			flush_cache_ent(ce);
			ce = ERR_PTR(-ENOENT);
			break;
		}

		if (ce->ce_srvtype == DFS_TYPE_ROOT ||
		    is_sysvol_or_netlogon(path) || !interlink)
			break;

		path = get_tgt_name(ce);
	}
	return ce;
}

static int setup_ref(const char *path, const struct dfs_cache_entry *ce,
		     struct dfs_info3_param *ref)
{
	char *tgt;

	cifs_dbg(FYI, "%s: set up new ref\n", __func__);

	memset(ref, 0, sizeof(*ref));

	ref->path_name = kstrndup(path, strlen(path), GFP_KERNEL);
	if (!ref->path_name)
		return -ENOMEM;

	ref->path_consumed = ce->ce_path_consumed;

	tgt = get_tgt_name(ce);

	ref->node_name = kstrndup(tgt, strlen(tgt), GFP_KERNEL);
	if (!ref->node_name)
		return -ENOMEM;

	ref->ttl = ce->ce_ttl;
	ref->server_type = ce->ce_srvtype;
	ref->ref_flag = ce->ce_flags;

	return 0;
}

int __dfs_cache_find(const unsigned int xid, struct cifs_ses *ses,
		     const struct nls_table *nls_codepage, int remap,
		     const char *path, struct dfs_info3_param *ref)
{
	int rc;
	struct dfs_cache_entry *ce;

	if (!path || unlikely(!strchr(path + 1, '\\')))
		return -EINVAL;

	mutex_lock(&dfs_cache_lock);
	ce = do_dfs_cache_find(xid, ses, nls_codepage, remap, path);
	if (!IS_ERR(ce)) {
		if (ref)
			rc = setup_ref(path, ce, ref);
		else
			rc = 0;
	} else {
		rc = PTR_ERR(ce);
	}
	mutex_unlock(&dfs_cache_lock);
	return rc;
}

int __dfs_cache_inval_tgt(const unsigned int xid, struct cifs_ses *ses,
			  const struct nls_table *nls_codepage, int remap,
			  const char *tree, struct dfs_info3_param *ref)
{
	struct dfs_cache_entry *ce;
	int rc;
	char *t;

	if (!tree || unlikely(!strchr(tree + 1, '\\')))
		return -EINVAL;

	cifs_dbg(FYI, "%s: tree name: %s\n", __func__, tree);

	mutex_lock(&dfs_cache_lock);

	ce = do_dfs_cache_find(xid, ses, nls_codepage, remap, tree);
	if (IS_ERR(ce)) {
		rc = PTR_ERR(ce);
		goto out;
	}

	cifs_dbg(FYI, "%s: current target: %s\n", __func__, get_tgt_name(ce));

	t = get_next_tgt_name(ce);
	if (!t) {
		rc = -ENOENT;
		cifs_dbg(FYI, "%s: no targets left for invalidation\n",
			 __func__);
	} else  {
		cifs_dbg(FYI, "%s: next target: %s\n", __func__, t);
		rc = 0;
	}

	if (!rc && ref)
		rc = setup_ref(tree, ce, ref);

out:
	mutex_unlock(&dfs_cache_lock);
	return rc;
}
