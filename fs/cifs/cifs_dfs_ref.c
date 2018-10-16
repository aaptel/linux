/*
 *   Contains the CIFS DFS referral mounting routines used for handling
 *   traversal via DFS junction point
 *
 *   Copyright (c) 2007 Igor Mammedov
 *   Copyright (C) International Business Machines  Corp., 2008
 *   Author(s): Igor Mammedov (niallain@gmail.com)
 *		Steve French (sfrench@us.ibm.com)
 *   This program is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU General Public License
 *   as published by the Free Software Foundation; either version
 *   2 of the License, or (at your option) any later version.
 */

#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/vfs.h>
#include <linux/fs.h>
#include <linux/inet.h>
#include "cifsglob.h"
#include "cifsproto.h"
#include "cifsfs.h"
#include "dns_resolve.h"
#include "cifs_debug.h"
#include "cifs_unicode.h"

/* #define DFSREF_CACHE_TEST */

static LIST_HEAD(cifs_dfs_automount_list);

static void cifs_dfs_expire_automounts(struct work_struct *work);
static DECLARE_DELAYED_WORK(cifs_dfs_automount_task,
			    cifs_dfs_expire_automounts);
static int cifs_dfs_mountpoint_expiry_timeout = 500 * HZ;

#define DFS_CACHE_ENTS_MAX 32
#define DFS_CACHE_TGTS_MAX 128

#define IS_INTERLINK_SET(v) ((v) & (DFSREF_REFERRAL_SERVER | \
				    DFSREF_STORAGE_SERVER))

struct dfs_cache_entry {
	char *prepath;
	int ttl;
	int srv_type;
	int flags;
	struct timespec64 etime;
	int numtgts;
	char *tgts[DFS_CACHE_TGTS_MAX];
	int tgthint;
};

struct dfs_cache {
	struct mutex lock;
	int numents;
	struct dfs_cache_entry ents[DFS_CACHE_ENTS_MAX];
};

static struct dfs_cache dfs_cache;
static bool dfs_cache_initialized;

static void cifs_dfs_expire_automounts(struct work_struct *work)
{
	struct list_head *list = &cifs_dfs_automount_list;

	mark_mounts_for_expiry(list);
	if (!list_empty(list))
		schedule_delayed_work(&cifs_dfs_automount_task,
				      cifs_dfs_mountpoint_expiry_timeout);
}

void cifs_dfs_release_automount_timer(void)
{
	BUG_ON(!list_empty(&cifs_dfs_automount_list));
	cancel_delayed_work_sync(&cifs_dfs_automount_task);
}

/**
 * cifs_build_devname - build a devicename from a UNC and optional prepath
 * @nodename:	pointer to UNC string
 * @prepath:	pointer to prefixpath (or NULL if there isn't one)
 *
 * Build a new cifs devicename after chasing a DFS referral. Allocate a buffer
 * big enough to hold the final thing. Copy the UNC from the nodename, and
 * concatenate the prepath onto the end of it if there is one.
 *
 * Returns pointer to the built string, or a ERR_PTR. Caller is responsible
 * for freeing the returned string.
 */
static char *
cifs_build_devname(char *nodename, const char *prepath)
{
	size_t pplen;
	size_t unclen;
	char *dev;
	char *pos;

	/* skip over any preceding delimiters */
	nodename += strspn(nodename, "\\");
	if (!*nodename)
		return ERR_PTR(-EINVAL);

	/* get length of UNC and set pos to last char */
	unclen = strlen(nodename);
	pos = nodename + unclen - 1;

	/* trim off any trailing delimiters */
	while (*pos == '\\') {
		--pos;
		--unclen;
	}

	/* allocate a buffer:
	 * +2 for preceding "//"
	 * +1 for delimiter between UNC and prepath
	 * +1 for trailing NULL
	 */
	pplen = prepath ? strlen(prepath) : 0;
	dev = kmalloc(2 + unclen + 1 + pplen + 1, GFP_KERNEL);
	if (!dev)
		return ERR_PTR(-ENOMEM);

	pos = dev;
	/* add the initial "//" */
	*pos = '/';
	++pos;
	*pos = '/';
	++pos;

	/* copy in the UNC portion from referral */
	memcpy(pos, nodename, unclen);
	pos += unclen;

	/* copy the prefixpath remainder (if there is one) */
	if (pplen) {
		*pos = '/';
		++pos;
		memcpy(pos, prepath, pplen);
		pos += pplen;
	}

	/* NULL terminator */
	*pos = '\0';

	convert_delimiter(dev, '/');
	return dev;
}


/**
 * cifs_compose_mount_options	-	creates mount options for refferral
 * @sb_mountdata:	parent/root DFS mount options (template)
 * @fullpath:		full path in UNC format
 * @ref:		server's referral
 * @devname:		pointer for saving device name
 *
 * creates mount options for submount based on template options sb_mountdata
 * and replacing unc,ip,prefixpath options with ones we've got form ref_unc.
 *
 * Returns: pointer to new mount options or ERR_PTR.
 * Caller is responcible for freeing retunrned value if it is not error.
 */
char *cifs_compose_mount_options(const char *sb_mountdata,
				   const char *fullpath,
				   const struct dfs_info3_param *ref,
				   char **devname)
{
	int rc;
	char *mountdata = NULL;
	const char *prepath = NULL;
	int md_len;
	char *tkn_e;
	char *srvIP = NULL;
	char sep = ',';
	int off, noff;

	if (sb_mountdata == NULL)
		return ERR_PTR(-EINVAL);

	if (strlen(fullpath) - ref->path_consumed) {
		prepath = fullpath + ref->path_consumed;
		/* skip initial delimiter */
		if (*prepath == '/' || *prepath == '\\')
			prepath++;
	}

	*devname = cifs_build_devname(ref->node_name, prepath);
	if (IS_ERR(*devname)) {
		rc = PTR_ERR(*devname);
		*devname = NULL;
		goto compose_mount_options_err;
	}

	rc = dns_resolve_server_name_to_ip(*devname, &srvIP);
	if (rc < 0) {
		cifs_dbg(FYI, "%s: Failed to resolve server part of %s to IP: %d\n",
			 __func__, *devname, rc);
		goto compose_mount_options_err;
	}

	/*
	 * In most cases, we'll be building a shorter string than the original,
	 * but we do have to assume that the address in the ip= option may be
	 * much longer than the original. Add the max length of an address
	 * string to the length of the original string to allow for worst case.
	 */
	md_len = strlen(sb_mountdata) + INET6_ADDRSTRLEN;
	mountdata = kzalloc(md_len + sizeof("ip=") + 1, GFP_KERNEL);
	if (mountdata == NULL) {
		rc = -ENOMEM;
		goto compose_mount_options_err;
	}

	/* copy all options except of unc,ip,prefixpath */
	off = 0;
	if (strncmp(sb_mountdata, "sep=", 4) == 0) {
			sep = sb_mountdata[4];
			strncpy(mountdata, sb_mountdata, 5);
			off += 5;
	}

	do {
		tkn_e = strchr(sb_mountdata + off, sep);
		if (tkn_e == NULL)
			noff = strlen(sb_mountdata + off);
		else
			noff = tkn_e - (sb_mountdata + off) + 1;

		if (strncasecmp(sb_mountdata + off, "unc=", 4) == 0) {
			off += noff;
			continue;
		}
		if (strncasecmp(sb_mountdata + off, "ip=", 3) == 0) {
			off += noff;
			continue;
		}
		if (strncasecmp(sb_mountdata + off, "prefixpath=", 11) == 0) {
			off += noff;
			continue;
		}
		strncat(mountdata, sb_mountdata + off, noff);
		off += noff;
	} while (tkn_e);
	strcat(mountdata, sb_mountdata + off);
	mountdata[md_len] = '\0';

	/* copy new IP and ref share name */
	if (mountdata[strlen(mountdata) - 1] != sep)
		strncat(mountdata, &sep, 1);
	strcat(mountdata, "ip=");
	strcat(mountdata, srvIP);

	/*cifs_dbg(FYI, "%s: parent mountdata: %s\n", __func__, sb_mountdata);*/
	/*cifs_dbg(FYI, "%s: submount mountdata: %s\n", __func__, mountdata );*/

compose_mount_options_out:
	kfree(srvIP);
	return mountdata;

compose_mount_options_err:
	kfree(mountdata);
	mountdata = ERR_PTR(rc);
	kfree(*devname);
	*devname = NULL;
	goto compose_mount_options_out;
}

/**
 * cifs_dfs_do_refmount - mounts specified path using provided refferal
 * @cifs_sb:		parent/root superblock
 * @fullpath:		full path in UNC format
 * @ref:		server's referral
 */
static struct vfsmount *cifs_dfs_do_refmount(struct dentry *mntpt,
		struct cifs_sb_info *cifs_sb,
		const char *fullpath, const struct dfs_info3_param *ref)
{
	struct vfsmount *mnt;
	char *mountdata;
	char *devname = NULL;

	/* strip first '\' from fullpath */
	mountdata = cifs_compose_mount_options(cifs_sb->mountdata,
			fullpath + 1, ref, &devname);

	if (IS_ERR(mountdata))
		return (struct vfsmount *)mountdata;

	mnt = vfs_submount(mntpt, &cifs_fs_type, devname, mountdata);
	kfree(mountdata);
	kfree(devname);
	return mnt;

}

static void dump_referral(const struct dfs_info3_param *ref)
{
	cifs_dbg(FYI, "DFS: ref path: %s\n", ref->path_name);
	cifs_dbg(FYI, "DFS: node path: %s\n", ref->node_name);
	cifs_dbg(FYI, "DFS: fl: %hd, srv_type: %hd\n",
		 ref->flags, ref->server_type);
	cifs_dbg(FYI, "DFS: ref_flags: %hd, path_consumed: %hd\n",
		 ref->ref_flag, ref->path_consumed);
}

/*
 * Create a vfsmount that we can automount
 */
static struct vfsmount *cifs_dfs_do_automount(struct dentry *mntpt)
{
	struct dfs_info3_param referral = {0};
	struct cifs_sb_info *cifs_sb;
	struct cifs_ses *ses;
	char *full_path;
	unsigned int xid;
	int len;
	int rc;
	struct vfsmount *mnt;
	struct tcon_link *tlink;

	cifs_dbg(FYI, "in %s\n", __func__);
	BUG_ON(IS_ROOT(mntpt));

	mnt = ERR_PTR(-ENOMEM);

	cifs_sb = CIFS_SB(mntpt->d_sb);
	if (cifs_sb->mnt_cifs_flags & CIFS_MOUNT_NO_DFS) {
		mnt = ERR_PTR(-EREMOTE);
		goto cdda_exit;
	}

	/* always use tree name prefix */
	full_path = build_path_from_dentry_optional_prefix(mntpt, true);
	if (full_path == NULL)
		goto cdda_exit;

	tlink = cifs_sb_tlink(cifs_sb);
	if (IS_ERR(tlink)) {
		mnt = ERR_CAST(tlink);
		goto free_full_path;
	}
	ses = tlink_tcon(tlink)->ses;

	xid = get_xid();
	/*
	 * The MSDFS spec states that paths in DFS referral requests and
	 * responses must be prefixed by a single '\' character instead of
	 * the double backslashes usually used in the UNC. This function
	 * gives us the latter, so we must adjust the result.
	 */
	rc = get_dfs_path(xid, ses, full_path + 1, cifs_sb->local_nls,
			  &referral, cifs_remap(cifs_sb));
	free_xid(xid);

	cifs_put_tlink(tlink);

	while (!rc) {
		dump_referral(&referral);

		/* connect to a node */
		len = strlen(referral.node_name);
		if (len < 2) {
			cifs_dbg(VFS, "%s: Net Address path too short: %s\n",
				 __func__, referral.node_name);
			rc = -EINVAL;
			break;
		}

		mnt = cifs_dfs_do_refmount(mntpt, cifs_sb, full_path,
					   &referral);
		cifs_dbg(FYI, "%s: cifs_dfs_do_refmount:%s , mnt:%p\n",
			 __func__, referral.node_name, mnt);
		if (!IS_ERR(mnt))
			break;

		rc = dfs_cache_invalidate_tgt(referral.node_name);

		free_dfs_info_param(&referral);
	}

	/* no valid submounts were found; return error from get_dfs_path() by
	 * preference */
	if (rc != 0)
		mnt = ERR_PTR(rc);

free_full_path:
	kfree(full_path);
cdda_exit:
	cifs_dbg(FYI, "leaving %s\n" , __func__);
	return mnt;
}

/*
 * Attempt to automount the referral
 */
struct vfsmount *cifs_dfs_d_automount(struct path *path)
{
	struct vfsmount *newmnt;

	cifs_dbg(FYI, "in %s\n", __func__);

	newmnt = cifs_dfs_do_automount(path->dentry);
	if (IS_ERR(newmnt)) {
		cifs_dbg(FYI, "leaving %s [automount failed]\n" , __func__);
		return newmnt;
	}

	mntget(newmnt); /* prevent immediate expiration */
	mnt_set_expiry(newmnt, &cifs_dfs_automount_list);
	schedule_delayed_work(&cifs_dfs_automount_task,
			      cifs_dfs_mountpoint_expiry_timeout);
	cifs_dbg(FYI, "leaving %s [ok]\n" , __func__);
	return newmnt;
}

static inline void dump_tgts(const struct dfs_cache_entry *ce)
{
	int i;

	cifs_dbg(FYI, "targets (num=%d):\n", ce->numtgts);
	for (i = 0; i < ce->numtgts; i++)
		cifs_dbg(FYI, "  %s\n", ce->tgts[i]);
}

static inline void dump_dfs_cache(void)
{
	int i;

	cifs_dbg(FYI, "DFS referral cache (nents=%d):\n", dfs_cache.numents);
	for (i = 0; i < dfs_cache.numents; i++) {
		struct dfs_cache_entry *ce = &dfs_cache.ents[i];
		cifs_dbg(FYI, "prefix_path: %s\n", ce->prepath);
		cifs_dbg(FYI, "ttl=%d,etime=%ld,target_type=%s,interlink=%s\n",
			 ce->ttl, ce->etime.tv_nsec,
			 ce->srv_type == DFS_TYPE_LINK ? "link" : "root",
			 IS_INTERLINK_SET(ce->flags) ? "yes" : "no");
		dump_tgts(ce);
	}
}

void dfs_cache_init(void)
{
	if (unlikely(dfs_cache_initialized))
		return;

	mutex_init(&dfs_cache.lock);
	dfs_cache_initialized = true;
	cifs_dbg(FYI, "initialized DFS referral cache\n");
}

static inline void free_tgts(struct dfs_cache_entry *ce)
{
	int i;

	for (i = 0; i < ce->numtgts; i++)
		kfree(ce->tgts[i]);
	ce->numtgts = 0;
}

void dfs_cache_destroy(void)
{
	int i;

	if (unlikely(!dfs_cache_initialized))
		return;

	mutex_lock(&dfs_cache.lock);

	for (i = 0; i < dfs_cache.numents; i++) {
		struct dfs_cache_entry *ce = &dfs_cache.ents[i];
		free_tgts(ce);
		kfree(ce->prepath);
	}

	mutex_unlock(&dfs_cache.lock);
	mutex_destroy(&dfs_cache.lock);

	memset(&dfs_cache, 0, sizeof(dfs_cache));
	dfs_cache_initialized = false;
	cifs_dbg(FYI, "Destroyed DFS referral cache\n");
}

static inline struct timespec64 get_expire_time(int ttl)
{
	struct timespec64 ts = {
		.tv_sec = ttl,
		.tv_nsec = 0,
	};
	return timespec64_add(current_kernel_time64(), ts);
}

static inline int copy_ref_data(const struct dfs_info3_param *refs, int numrefs,
				struct dfs_cache_entry *ce)
{
	int i;

	if (unlikely(numrefs > DFS_CACHE_TGTS_MAX))
		return -ENOMEM;

	ce->ttl = refs[0].ttl;
	ce->etime = get_expire_time(ce->ttl);
	ce->srv_type = refs[0].server_type;
	ce->flags = refs[0].ref_flag;

	free_tgts(ce);

	ce->tgthint = 0;

	for (i = 0; i < numrefs; i++) {
		const struct dfs_info3_param *ref = &refs[i];

		ce->tgts[i] = kstrndup(ref->node_name, strlen(ref->node_name),
				       GFP_KERNEL);
		if (!ce->tgts[i]) {
			free_tgts(ce);
			return -ENOMEM;
		}
		ce->numtgts++;
	}
	return 0;
}

static int add_cache_entry(const char *path, const struct dfs_info3_param *refs,
			   int numrefs)
{
	int rc;
	struct dfs_cache_entry *ce;

	cifs_dbg(FYI, "%s: path %s refs %p numrefs %d\n", __func__, path, refs,
		 numrefs);

	if (unlikely(dfs_cache.numents + 1 > DFS_CACHE_ENTS_MAX)) {
		rc = -ENOMEM;
		goto out;
	}

	ce = &dfs_cache.ents[dfs_cache.numents];
	memset(ce, 0, sizeof(*ce));

	rc = copy_ref_data(refs, numrefs, ce);
	if (rc)
		goto out;
#ifdef DFSREF_CACHE_TEST
	if (ce->srv_type == DFS_TYPE_ROOT) {
		ce->ttl = 30;
		ce->etime = get_expire_time(ce->ttl);
	}
#endif
	ce->prepath = kstrndup(path, strlen(path), GFP_KERNEL);
	if (!ce->prepath) {
		rc = -ENOMEM;
		goto out;
	}

	cifs_dbg(FYI, "%s: new cache entry: prepath=%s,ttl=%d,etime=%ld"
		 "target_type=%s,interlink=%s\n",
		 __func__, ce->prepath, ce->ttl, ce->etime.tv_nsec,
		 ce->srv_type == DFS_TYPE_LINK ? "link" : "root",
		 IS_INTERLINK_SET(ce->flags) ? "yes" : "no");

	dfs_cache.numents++;
	rc = 0;

out:
	cifs_dbg(FYI, "%s: rc = %d\n", __func__, rc);
	return rc;
}

static int setup_ref(const char *path, const struct dfs_cache_entry *ce,
		     struct dfs_info3_param *ref)
{
	char *tgt;

	memset(ref, 0, sizeof(*ref));

	ref->path_name = kstrndup(path, strlen(path), GFP_KERNEL);
	if (!ref->path_name)
		return -ENOMEM;

	ref->path_consumed = strlen(path);

	tgt = ce->tgts[ce->tgthint];

	ref->node_name = kstrndup(tgt, strlen(tgt), GFP_KERNEL);
	if (!ref->node_name)
		return -ENOMEM;

	ref->ttl = ce->ttl;
	ref->server_type = ce->srv_type;
	ref->ref_flag = ce->flags;

	return 0;
}

static inline int __update_cache_lru(int index)
{
	int i;
	struct dfs_cache_entry tmp;

	if (likely(index == dfs_cache.numents - 1))
		return index;

	memcpy(&tmp, &dfs_cache.ents[index], sizeof(tmp));
	for (i = index; i < dfs_cache.numents - 1; i++) {
		memcpy(&dfs_cache.ents[i], &dfs_cache.ents[i + 1],
		       sizeof(dfs_cache.ents[i]));
	}
	memcpy(&dfs_cache.ents[i], &tmp, sizeof(dfs_cache.ents[i]));
	return i;
}

static inline struct dfs_cache_entry *find_cache_entry(const char *path)
{
	int i;

	for (i = dfs_cache.numents - 1; i >= 0; i--) {
		if (!strcasecmp(dfs_cache.ents[i].prepath, path)) {
			i = __update_cache_lru(i);
			break;
		}
	}
	return i >= 0 ? &dfs_cache.ents[i] : ERR_PTR(-ENOENT);
}

static struct dfs_cache_entry *update_cache_entry(const char *path,
						  const struct dfs_info3_param *refs,
						  int numrefs)
{
	int rc;
	struct dfs_cache_entry *ce;

	ce = find_cache_entry(path);
	if (IS_ERR(ce))
		return ce;
	rc = copy_ref_data(refs, numrefs, ce);
	if (rc)
		ce = ERR_PTR(rc);
	return ce;
}

static struct dfs_cache_entry *get_updated_cache_entry(struct dfs_cache_entry *ce,
						       const unsigned int xid,
						       struct cifs_ses *ses,
						       const char *path,
						       const struct nls_table *nls_codepage,
						       int remap)
{
	int rc;
	struct dfs_info3_param *refs = NULL;
	int numrefs = 0;

	cifs_dbg(FYI, "%s: DFS referral request for %s\n", __func__,
		 path);

	rc = ses->server->ops->get_dfs_refer(xid, ses, path, &refs, &numrefs,
					     nls_codepage, remap);
	if (rc)
		ce = ERR_PTR(rc);
	else
		ce = update_cache_entry(path, refs, numrefs);

	free_dfs_info_array(refs, numrefs);
	return ce;
}

static inline bool is_sysvol_or_netlogon(const char *path)
{
	const char *s;

	s = strchr(path + 1, '\\') + 1;
	return !strncasecmp(s, "sysvol", strlen("sysvol")) ||
		!strncasecmp(s, "netlogon", strlen("netlogon"));
}

int dfs_cache_find(const unsigned int xid, struct cifs_ses *ses,
		   const char *path, const struct nls_table *nls_codepage,
		   int remap, struct dfs_info3_param *ref)
{
	int rc;
	struct dfs_cache_entry *ce;
	struct timespec64 ts;
	bool interlink;
	struct dfs_info3_param *nrefs;
	int numnrefs;

	if (!ses || !path || !nls_codepage || !ref)
		return -EINVAL;
	if (unlikely(!dfs_cache_initialized))
		return -EINVAL;
	if (unlikely(!ses->server->ops->get_dfs_refer))
		return -ENOSYS;
	if (unlikely(!strchr(path + 1, '\\')))
		return -EINVAL;

	mutex_lock(&dfs_cache.lock);
#ifdef CONFIG_CIFS_DEBUG2
	dump_dfs_cache();
#endif
	for (;;) {
		cifs_dbg(FYI, "%s: search path: %s\n", __func__, path);

		ce = find_cache_entry(path);
		if (IS_ERR(ce)) {
			rc = ses->server->ops->get_dfs_refer(xid, ses, path,
							     &nrefs, &numnrefs,
							     nls_codepage,
							     remap);
			if (rc)
				goto out;

			rc = add_cache_entry(path, nrefs, numnrefs);
			free_dfs_info_array(nrefs, numnrefs);

			if (rc)
				goto out;

			ce = find_cache_entry(path);
			if (IS_ERR(ce)) {
				rc = PTR_ERR(ce);
				goto out;
			}
		}

		interlink = IS_INTERLINK_SET(ce->flags);

		cifs_dbg(FYI, "%s: cache entry: prepath=%s,ttl=%d,etime=%ld,"
			 "interlink=%s\n", __func__, ce->prepath, ce->ttl,
			 ce->etime.tv_nsec, interlink ? "yes" : "no");

		ts = current_kernel_time64();
		cifs_dbg(FYI, "%s: ctime %ld\n", __func__, ts.tv_nsec);
		if (timespec64_compare(&ts, &ce->etime) >= 0) {
			cifs_dbg(FYI, "%s: expired TTL\n", __func__);
			ce = get_updated_cache_entry(ce, xid, ses, path,
						     nls_codepage, remap);
			if (IS_ERR(ce)) {
				rc = PTR_ERR(ce);
				cifs_dbg(FYI, "%s: failed to update expired entry\n",
					 __func__);
				goto out;
			}
			interlink = IS_INTERLINK_SET(ce->flags);
		}

		if (ce->srv_type == DFS_TYPE_ROOT ||
		    is_sysvol_or_netlogon(path) || !interlink)
			break;
		path = ce->tgts[ce->tgthint];
	}

	rc = setup_ref(path, ce, ref);

out:
	mutex_unlock(&dfs_cache.lock);
	cifs_dbg(FYI, "%s: rc = %d\n", __func__, rc);
	return rc;
}

int dfs_cache_invalidate_tgt(const char *tgt)
{
	int rc;
	struct dfs_cache_entry *ce;
	char *s;

	if (!tgt)
		return -EINVAL;

	cifs_dbg(FYI, "%s: target: %s\n", __func__, tgt);

	if (unlikely(!dfs_cache_initialized))
		return -EINVAL;

	mutex_lock(&dfs_cache.lock);

	if (unlikely(!dfs_cache.numents)) {
		rc = -ENOENT;
		goto out;
	}

	ce = &dfs_cache.ents[dfs_cache.numents - 1];
	if (unlikely(!ce->numtgts)) {
		rc = -EINVAL;
		goto out;
	}
	if (ce->tgthint + 1 >= ce->numtgts) {
		rc = -ENOENT;
		goto out;
	}

	cifs_dbg(FYI, "%s: cache entry: prepath=%s,ttl=%d,etime=%ld,"
		 "interlink=%s\n", __func__, ce->prepath, ce->ttl,
		 ce->etime.tv_nsec, IS_INTERLINK_SET(ce->flags) ? "yes" : "no");

	s = ce->tgts[ce->tgthint];
	cifs_dbg(FYI, "%s: current tgt hint: %s\n", __func__, s);
	if (strcasecmp(tgt, s)) {
		rc = -EINVAL;
		goto out;
	}

	s = ce->tgts[++ce->tgthint];
	cifs_dbg(FYI, "%s: new tgt hint: %s\n", __func__, s);
	rc = 0;

out:
	mutex_unlock(&dfs_cache.lock);
	return rc;
}

const struct inode_operations cifs_dfs_referral_inode_operations = {
};
