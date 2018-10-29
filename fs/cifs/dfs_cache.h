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
#include "cifsglob.h"

#define dfs_cache_find(xid, ses, nc, remap, path, ref, numtgts) \
	__dfs_cache_find(xid, ses, nc, remap, path, ref, numtgts)

#define dfs_cache_noreq_find(tree, ref, numtgts) \
({ \
	int __rc; \
	__rc = __dfs_cache_find(0, NULL, NULL, 0, tree, ref, numtgts); \
	__rc == -ENOSYS ? -ENOENT : __rc; \
})

#define dfs_cache_inval_tgt(xid, ses, nc, remap, tree, ref) \
	__dfs_cache_inval_tgt(xid, ses, nc, remap, tree, ref)

#define dfs_cache_noreq_inval_tgt(tree, ref) \
({ \
	int __rc; \
	__rc = __dfs_cache_inval_tgt(0, NULL, NULL, 0, tree, ref); \
	__rc == -ENOSYS ? -ENOENT : __rc; \
})

int dfs_cache_init(void);
void dfs_cache_destroy(void);

int __dfs_cache_find(const unsigned int xid, struct cifs_ses *ses,
		     const struct nls_table *nls_codepage, int remap,
		     const char *path, struct dfs_info3_param *ref,
		     int *numtgts);
int __dfs_cache_inval_tgt(const unsigned int xid, struct cifs_ses *ses,
			  const struct nls_table *nls_codepage, int remap,
			  const char *tree, struct dfs_info3_param *ref);

#endif /* _CIFS_DFS_CACHE_H */
