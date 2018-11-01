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
#ifndef _CIFS_DFS_CACHE_H
#define _CIFS_DFS_CACHE_H

#include <linux/nls.h>
#include <linux/list.h>
#include "cifsglob.h"

struct dfs_cache_tgt_iterator {
	char *it_name;
	struct list_head it_list;
};

#define dfs_cache_find(xid, ses, nc, remap, path, ref, tgt_list, check_ppath) \
	__dfs_cache_find(xid, ses, nc, remap, path, ref, tgt_list, check_ppath)
#define dfs_cache_noreq_find(path, ref, tgt_list) \
({ \
	int __rc; \
	__rc = __dfs_cache_find(0, NULL, NULL, 0, path, ref, tgt_list, true); \
	__rc == -ENOSYS ? -ENOENT : __rc; \
})

#define dfs_cache_update_tgthint(xid, ses, nc, remap, path, it) \
	__dfs_cache_update_tgthint(xid, ses, nc, remap, path, it)
#define dfs_cache_noreq_update_tgthint(path, it) \
({ \
	int __rc; \
	__rc = __dfs_cache_update_tgthint(0, NULL, NULL, 0, path, it); \
	__rc == -ENOSYS ? -ENOENT : __rc; \
})

int dfs_cache_init(void);
void dfs_cache_destroy(void);

int __dfs_cache_find(const unsigned int xid, struct cifs_ses *ses,
		     const struct nls_table *nls_codepage, int remap,
		     const char *path, struct dfs_info3_param *ref,
		     struct list_head *tgt_list, bool check_ppath);
int __dfs_cache_update_tgthint(const unsigned int xid, struct cifs_ses *ses,
			       const struct nls_table *nls_codepage, int remap,
			       const char *path,
			       const struct dfs_cache_tgt_iterator *it);

static inline struct dfs_cache_tgt_iterator *
dfs_cache_get_next_tgt(struct list_head *head,
		       struct dfs_cache_tgt_iterator *it)
{
	if (list_empty(head) || list_is_last(&it->it_list, head) || !it)
		return NULL;
	return list_next_entry(it, it_list);
}

static inline struct dfs_cache_tgt_iterator *
dfs_cache_get_tgt_iterator(struct list_head *head)
{
	return list_first_entry_or_null(head, struct dfs_cache_tgt_iterator,
					it_list);
}

static inline void dfs_cache_free_tgts(struct list_head *list)
{
	struct dfs_cache_tgt_iterator *it, *nit;

	if (!list || list_empty(list))
		return;

	list_for_each_entry_safe(it, nit, list, it_list) {
		kfree(it->it_name);
		kfree(it);
	}
}

static inline const char *
dfs_cache_get_tgt_name(const struct dfs_cache_tgt_iterator *it)
{
	return it ? it->it_name : NULL;
}

int dfs_cache_get_tgt_referral(const char *path,
			       const struct dfs_cache_tgt_iterator *it,
			       struct dfs_info3_param *ref);

#endif /* _CIFS_DFS_CACHE_H */
