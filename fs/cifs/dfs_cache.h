/*
 * DFS referral cache routines.
 *
 * Copyright (c) 2018 Paulo Alcantara <palcantara@suse.de>
 *
 * This program is free software;  you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY;  without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
 * the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program;  if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
 */

#ifndef _CIFS_DFS_CACHE_H
#define _CIFS_DFS_CACHE_H

#include <linux/nls.h>
#include <linux/list.h>
#include "cifsglob.h"

struct dfs_cache_tgt_list {
	int tl_numtgts;
	struct list_head tl_list;
};

struct dfs_cache_tgt_iterator {
	char *it_name;
	struct list_head it_list;
};

extern int dfs_cache_init(void);
extern void dfs_cache_destroy(void);
extern const struct file_operations dfscache_proc_fops;

extern int dfs_cache_find(const unsigned int xid, struct cifs_ses *ses,
			  const struct nls_table *nls_codepage, int remap,
			  const char *path, struct dfs_info3_param *ref,
			  struct dfs_cache_tgt_list *tgt_list);
extern int dfs_cache_noreq_find(const char *path, struct dfs_info3_param *ref,
				struct dfs_cache_tgt_list *tgt_list);
extern int dfs_cache_update_tgthint(const unsigned int xid,
				    struct cifs_ses *ses,
				    const struct nls_table *nls_codepage,
				    int remap, const char *path,
				    const struct dfs_cache_tgt_iterator *it);
extern int dfs_cache_noreq_update_tgthint(const char *path,
					  const struct dfs_cache_tgt_iterator *it);

extern int dfs_cache_get_tgt_referral(const char *path,
				      const struct dfs_cache_tgt_iterator *it,
				      struct dfs_info3_param *ref);
extern int dfs_cache_add_vol(struct smb_vol *vol, const char *fullpath);
extern int dfs_cache_update_vol(const char *fullpath,
				struct TCP_Server_Info *server);
extern void dfs_cache_del_vol(const char *fullpath);

static inline struct dfs_cache_tgt_iterator *
dfs_cache_get_next_tgt(struct dfs_cache_tgt_list *tl,
		       struct dfs_cache_tgt_iterator *it)
{
	if (!tl || list_empty(&tl->tl_list) || !it ||
	    list_is_last(&it->it_list, &tl->tl_list))
		return NULL;
	return list_next_entry(it, it_list);
}

static inline struct dfs_cache_tgt_iterator *
dfs_cache_get_tgt_iterator(struct dfs_cache_tgt_list *tl)
{
	if (!tl)
		return NULL;
	return list_first_entry_or_null(&tl->tl_list,
					struct dfs_cache_tgt_iterator,
					it_list);
}

static inline void dfs_cache_free_tgts(struct dfs_cache_tgt_list *tl)
{
	struct dfs_cache_tgt_iterator *it, *nit;

	if (!tl || list_empty(&tl->tl_list))
		return;
	list_for_each_entry_safe(it, nit, &tl->tl_list, it_list) {
		kfree(it->it_name);
		kfree(it);
	}
	tl->tl_numtgts = 0;
}

static inline const char *
dfs_cache_get_tgt_name(const struct dfs_cache_tgt_iterator *it)
{
	return it ? it->it_name : NULL;
}

static inline int
dfs_cache_get_nr_tgts(const struct dfs_cache_tgt_list *tl)
{
	return tl ? tl->tl_numtgts : 0;
}

#endif /* _CIFS_DFS_CACHE_H */
