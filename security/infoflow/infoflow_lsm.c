// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2018,2019 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: infoflow_lsm.c
 *      Function implementing LSM hooks.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/cred.h>
#include <linux/magic.h>
#include <linux/audit.h>
#include <linux/xattr.h>

#include "infoflow.h"

struct infoflow_class_desc infoflow_class_array[CLASS__LAST] = {
	[CLASS_LNK_FILE] = { .name = "lnk_file", .excluded = 1 },
	[CLASS_REG_FILE] = { .name = "file" },
	[CLASS_DIR] = { .name = "dir", .excluded = 1 },
	[CLASS_CHR_FILE] = { .name = "chr_file" },
	[CLASS_BLK_FILE] = { .name = "blk_file" },
	[CLASS_FIFO_FILE] = { .name = "fifo_file" },
	[CLASS_SOCK_FILE] = { .name = "sock_file", .excluded = 1 },
	[CLASS_IPC] = { .name = "ipc" },
	[CLASS_MSGQ] = { .name = "msgq" },
	[CLASS_SHM] = { .name = "shm" },
	[CLASS_SEM] = { .name = "sem" },
	[CLASS_SOCKET] = { .name = "socket" },
	[CLASS_KEY] = { .name = "key" },
	[CLASS_PROCESS] = { .name = "process" },
	[CLASS_KERNEL] = { .name = "kernel" },
	[CLASS_MODULE] = { .name = "module" },
	[CLASS_UNDEFINED] = { .name = "undefined" },
};

const char *infoflow_modes_str[INFOFLOW_MODE__LAST] = {
	[INFOFLOW_DISABLED] = "disabled",
	[INFOFLOW_DISCOVER] = "discover",
	[INFOFLOW_ENFORCE] = "enforce",
	[INFOFLOW_ENFORCE_AUDIT] = "enforce-audit",
	[INFOFLOW_PERMISSIVE] = "permissive",
	[INFOFLOW_PERMISSIVE_AUDIT] = "permissive-audit",
};

int infoflow_mode __lsm_ro_after_init = INFOFLOW_ENFORCE;
static int __init infoflow_mode_setup(char *str)
{
	int i;

	for (i = 0; i < INFOFLOW_MODE__LAST; i++) {
		if (!strcmp(str, infoflow_modes_str[i])) {
			infoflow_mode = i;
			break;
		}
	}

	if (i == INFOFLOW_MODE__LAST)
		pr_err("Unknown mode %s\n", str);

	return 1;
}
__setup("infoflow_mode=", infoflow_mode_setup);

int infoflow_enabled __lsm_ro_after_init = 1;
static int __init infoflow_enabled_setup(char *str)
{
	unsigned long enabled;

	if (!kstrtoul(str, 0, &enabled))
		infoflow_enabled = enabled ? 1 : 0;
	return 1;
}
__setup("infoflow=", infoflow_enabled_setup);

int infoflow_init_flags;
static int __init infoflow_promote_setup(char *str)
{
	infoflow_init_flags |= INFOFLOW_PROMOTE;
	return 1;
}
__setup("infoflow_promote", infoflow_promote_setup);

static int infoflow_seqno;

static int infoflow_security_change(struct notifier_block *nb,
				    unsigned long event, void *lsm_data)
{
	if (event != LSM_POLICY_CHANGE)
		return NOTIFY_DONE;

	infoflow_seqno++;
	infoflow_ctx_update_sid();
	infoflow_init_flags |= INFOFLOW_PARENT_LSM_INIT;

	return NOTIFY_OK;
}

static struct notifier_block infoflow_lsm_nb = {
	.notifier_call = infoflow_security_change,
};

static int infoflow_inode_init_security(struct inode *inode, struct inode *dir,
					const struct qstr *qstr,
					const char **name, void **value,
					size_t *len)
{
	const struct cred *cred = current_cred();
	u8 *iflags = infoflow_inode(inode);
	u16 class = infoflow_inode_class(inode->i_mode);
	struct infoflow_ctx *sctx;
	u8 flags = CTX_FLAG_TCB;
	u32 sid;

	if (name)
		*name = XATTR_INFOFLOW_SUFFIX;

	if (infoflow_class_array[class].excluded)
		return 0;

	if (!(infoflow_init_flags & INFOFLOW_POLICY_INIT))
		return -EOPNOTSUPP;

	validate_creds(cred);

	security_cred_getsecid(cred, &sid);
	sctx = infoflow_ctx_find_sid(CLASS_PROCESS, sid);

	if (!sctx || !(sctx->flags & CTX_FLAG_TCB))
		return 0;

	*iflags |= (flags | CTX_FLAG_INITIALIZED);

	if (value && len) {
		*value = kmemdup(&flags, sizeof(flags), GFP_NOFS);
		if (!*value)
			return -ENOMEM;

		*len = sizeof(flags);
	}

	return 0;
}

int infoflow_check_fs(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;

	switch (sb->s_magic) {
	case PROC_SUPER_MAGIC:
	case SYSFS_MAGIC:
	case DEBUGFS_MAGIC:
	case RAMFS_MAGIC:
	case DEVPTS_SUPER_MAGIC:
	case BINFMTFS_MAGIC:
	case SECURITYFS_MAGIC:
	case SELINUX_MAGIC:
	case SMACK_MAGIC:
	case NSFS_MAGIC:
	case CGROUP_SUPER_MAGIC:
	case CGROUP2_SUPER_MAGIC:
		return 0;
	default:
		return 1;
	}
}

static int infoflow_inode_init(struct dentry *opt_dentry, struct inode *inode,
			       bool may_sleep)
{
	u8 *iflags = infoflow_inode(inode);
	u16 class = infoflow_inode_class(inode->i_mode);
	struct dentry *dentry = NULL;
	u8 flags = 0;
	int rc;

	might_sleep_if(may_sleep);

	if (infoflow_class_array[class].excluded)
		return 0;

	if (!(infoflow_init_flags & INFOFLOW_POLICY_INIT))
		return 0;

	if (!may_sleep)
		return -ECHILD;

	if (*iflags & CTX_FLAG_INITIALIZED)
		return 0;

	if (!infoflow_check_fs(inode) || !(inode->i_opflags & IOP_XATTR)) {
		*iflags |= CTX_FLAG_INITIALIZED;
		return 0;
	}

	if (!opt_dentry) {
		dentry = d_find_alias(inode);
		if (!dentry)
			dentry = d_find_any_alias(inode);
	} else {
		dentry = dget(opt_dentry);
	}

	if (!dentry)
		return 0;

	rc = __vfs_getxattr(dentry, inode, XATTR_NAME_INFOFLOW, &flags,
			    sizeof(flags));
	if (rc == sizeof(flags))
		*iflags |= (flags & CTX_FLAG_TCB);

	*iflags |= CTX_FLAG_INITIALIZED;

	if (dentry)
		dput(dentry);

	return 0;
}

static void infoflow_d_instantiate(struct dentry *opt_dentry,
				   struct inode *inode)
{
	infoflow_inode_init(opt_dentry, inode, true);
}

static int inode_has_perm(const struct cred *cred,
			  struct inode *inode,
			  int mask,
			  struct common_audit_data *adp)
{
	u8 *iflags = infoflow_inode(inode);
	u32 ssid, isid;

	if (!infoflow_check_fs(inode))
		return 0;

	validate_creds(cred);

	if (unlikely(IS_PRIVATE(inode)))
		return 0;

	security_cred_getsecid(cred, &ssid);
	security_inode_getsecid(inode, &isid);

	return infoflow_allow_access(CLASS_PROCESS, ssid,
				     infoflow_inode_class(inode->i_mode), isid,
				     iflags, mask, adp);
}

static int infoflow_inode_permission(struct inode *inode, int mask)
{
	const struct cred *cred = current_cred();
	struct common_audit_data ad;

	mask &= (MAY_READ|MAY_WRITE|MAY_EXEC|MAY_APPEND);

	/* No permission to check.  Existence test. */
	if (!mask)
		return 0;

	ad.type = LSM_AUDIT_DATA_INODE;
	ad.u.inode = inode;

	return inode_has_perm(cred, inode, mask, &ad);
}

static int infoflow_inode_setxattr(struct dentry *dentry, const char *name,
				   const void *value, size_t size, int flags)
{
	struct inode *inode = d_backing_inode(dentry);
	const struct cred *cred = current_cred();

	if (strcmp(name, XATTR_NAME_INFOFLOW))
		return 0;

	if (!capable(CAP_SYS_ADMIN))
		return -EPERM;

	return inode_has_perm(cred, inode, MAY_WRITE, NULL);
}

static void infoflow_inode_post_setxattr(struct dentry *dentry,
					 const char *name, const void *value,
					 size_t size, int flags)
{
	struct inode *inode = d_backing_inode(dentry);
	u8 *iflags = infoflow_inode(inode);

	if (strcmp(name, XATTR_NAME_INFOFLOW) != 0)
		return;

	if (size != 1)
		return;

	*iflags = *(u8 *)value;
}

static int infoflow_inode_removexattr(struct dentry *dentry, const char *name)
{
	if (strcmp(name, XATTR_NAME_INFOFLOW))
		return 0;

	/* There is no inode_post_removexattr() hook, we cannot clear
	 * the inode flags.
	 */
	return -EACCES;
}

static int infoflow_inode_setsecurity(struct inode *inode, const char *name,
				      const void *value, size_t size, int flags)
{
	u8 *iflags = infoflow_inode(inode);

	if (strcmp(name, XATTR_INFOFLOW_SUFFIX))
		return -EOPNOTSUPP;

	if (!value || !size)
		return -EACCES;

	if (size != 1)
		return -EINVAL;

	*iflags = *(u8 *)value;

	return 0;
}

static int file_has_perm(const struct cred *cred,
			 struct file *file,
			 int mask)
{
	struct inode *inode = file_inode(file);
	struct common_audit_data ad;
	int rc;

	ad.type = LSM_AUDIT_DATA_FILE;
	ad.u.file = file;

	/* av is zero if only checking access to the descriptor. */
	rc = 0;
	if (mask)
		rc = inode_has_perm(cred, inode, mask, &ad);

	return rc;
}

/* Same as path_has_perm, but uses the inode from the file struct. */
static inline int file_path_has_perm(const struct cred *cred,
				     struct file *file,
				     int mask)
{
	struct common_audit_data ad;

	ad.type = LSM_AUDIT_DATA_FILE;
	ad.u.file = file;

	return inode_has_perm(cred, file_inode(file), mask, &ad);
}

static int infoflow_revalidate_file_permission(struct file *file, int mask)
{
	const struct cred *cred = current_cred();

	return file_has_perm(cred, file, mask);
}

static int infoflow_file_permission(struct file *file, int mask)
{
	const struct cred *cred = current_cred();
	struct inode *inode = file_inode(file);
	struct file_security_struct *fsec = infoflow_file(file);
	u32 ssid, isid;

	if (!mask)
		/* No permission to check.  Existence test. */
		return 0;

	validate_creds(cred);
	security_cred_getsecid(cred, &ssid);

	security_inode_getsecid(inode, &isid);

	if (ssid == fsec->sid && fsec->isid == isid &&
	    fsec->pseqno == infoflow_seqno)
		/* No change since file_open check. */
		return 0;

	return infoflow_revalidate_file_permission(file, mask);
}

static int infoflow_file_receive(struct file *file)
{
	const struct cred *cred = current_cred();

	return file_has_perm(cred, file, infoflow_file_f_mode_to_mask(file));
}

static int infoflow_file_open(struct file *file)
{
	struct file_security_struct *fsec;
	u32 isid;

	fsec = infoflow_file(file);

	security_inode_getsecid(file_inode(file), &isid);

	fsec->isid = isid;
	fsec->pseqno = infoflow_seqno;

	return file_path_has_perm(file->f_cred, file,
				  infoflow_file_f_mode_to_mask(file));
}

static int infoflow_kernel_module_from_file(struct file *file, bool module)
{
	struct common_audit_data ad;
	const struct cred *cred = current_cred();
	enum infoflow_class class = CLASS_MODULE;
	struct inode *inode;
	u32 ssid, isid;
	u8 *iflags;

	validate_creds(cred);
	security_cred_getsecid(cred, &ssid);

	/* init_module */
	if (file == NULL) {
		if (!module)
			class = CLASS_UNDEFINED;

		return infoflow_allow_access(CLASS_KERNEL, ssid, class, ssid,
					     NULL, MAY_READ, NULL);
	}

	/* finit_module */
	ad.type = LSM_AUDIT_DATA_FILE;
	ad.u.file = file;

	inode = file_inode(file);
	security_inode_getsecid(inode, &isid);
	iflags = infoflow_inode(inode);

	if (!module)
		class = infoflow_inode_class(inode->i_mode);

	return infoflow_allow_access(CLASS_KERNEL, ssid, class, isid, iflags,
				     MAY_READ, &ad);
}

static int infoflow_kernel_read_file(struct file *file,
				     enum kernel_read_file_id id)
{
	return infoflow_kernel_module_from_file(file, id == READING_MODULE);
}

static int infoflow_kernel_load_data(enum kernel_load_data_id id)
{
	return infoflow_kernel_module_from_file(NULL, id == LOADING_MODULE);
}

static int infoflow_setprocattr(const char *name, void *value, size_t size)
{
	const struct cred *cred = current_cred();
	struct infoflow_ctx *old_ctx, *new_ctx;
	u32 old_ssid, new_ssid;
	int rc;

	if (strcmp(name, "current"))
		return 0;

	validate_creds(cred);
	security_cred_getsecid(cred, &old_ssid);

	old_ctx = infoflow_ctx_find_sid(CLASS_PROCESS, old_ssid);

	rc = security_secctx_to_secid((char *)value, size, &new_ssid);
	if (rc < 0)
		return -EPERM;

	new_ctx = infoflow_ctx_find_sid(CLASS_PROCESS, new_ssid);

	/* We cannot let a non-TCB process go inside the TCB, because
	 * load-time integrity of non-TCB processes cannot be determined.
	 */
	if ((!old_ctx || !(old_ctx->flags & CTX_FLAG_TCB)) &&
	    new_ctx && (new_ctx->flags & CTX_FLAG_TCB))
		return -EPERM;

	return 0;
}

static int ipc_has_perm(const struct cred *cred, u32 sid,
			enum infoflow_class oclass,
			struct kern_ipc_perm *ipc_perms, int mask)
{
	struct common_audit_data ad;
	u32 ssid, isid;

	if (cred) {
		validate_creds(cred);
		security_cred_getsecid(cred, &ssid);
	} else {
		ssid = sid;
	}

	security_ipc_getsecid(ipc_perms, &isid);

	ad.type = LSM_AUDIT_DATA_IPC;
	ad.u.ipc_id = ipc_perms->key;

	return infoflow_allow_access(CLASS_PROCESS, ssid, oclass, isid, NULL,
				     mask, &ad);
}

static int infoflow_ipc_permission(struct kern_ipc_perm *ipcp, short flag)
{
	const struct cred *cred = current_cred();
	int mask = 0;

	if (flag & S_IRUGO)
		mask |= MAY_READ;
	if (flag & S_IWUGO)
		mask |= MAY_WRITE;

	if (mask == 0)
		return 0;

	return ipc_has_perm(cred, 0, CLASS_IPC, ipcp, mask);
}

static int infoflow_msg_queue_msgsnd(struct kern_ipc_perm *msq,
				     struct msg_msg *msg, int msqflg)
{
	const struct cred *cred = current_cred();

	return ipc_has_perm(cred, 0, CLASS_MSGQ, msq, MAY_WRITE);
}

static int infoflow_msg_queue_msgrcv(struct kern_ipc_perm *msq,
				     struct msg_msg *msg,
				     struct task_struct *target,
				     long type, int mode)
{
	u32 ssid;

	security_task_getsecid(target, &ssid);

	return ipc_has_perm(NULL, ssid, CLASS_MSGQ, msq, MAY_READ);
}

static int infoflow_shm_shmat(struct kern_ipc_perm *shp,
			      char __user *shmaddr, int shmflg)
{
	const struct cred *cred = current_cred();
	int mask;

	if (shmflg & SHM_RDONLY)
		mask = MAY_READ;
	else
		mask = MAY_READ | MAY_WRITE;

	return ipc_has_perm(cred, 0, CLASS_SHM, shp, mask);
}

/* Note, at this point, sma is locked down */
static int infoflow_sem_semctl(struct kern_ipc_perm *sma, int cmd)
{
	const struct cred *cred = current_cred();
	int mask;

	switch (cmd) {
	case GETVAL:
	case GETALL:
		mask = MAY_READ;
		break;
	case SETVAL:
	case SETALL:
		mask = MAY_WRITE;
		break;
	default:
		return 0;
	}

	return ipc_has_perm(cred, 0, CLASS_SEM, sma, mask);
}

static int infoflow_sem_semop(struct kern_ipc_perm *sma,
			      struct sembuf *sops, unsigned nsops, int alter)
{
	const struct cred *cred = current_cred();
	int mask;

	if (alter)
		mask = MAY_READ | MAY_WRITE;
	else
		mask = MAY_READ;

	return ipc_has_perm(cred, 0, CLASS_SEM, sma, mask);
}

static int infoflow_socket_unix_may_send(struct socket *sock,
					 struct socket *other)
{
	struct common_audit_data ad;
	struct lsm_network_audit net = {0,};
	struct flowi fl_sock, fl_other;

	ad.type = LSM_AUDIT_DATA_NET;
	ad.u.net = &net;
	ad.u.net->sk = other->sk;

	security_sk_classify_flow(sock->sk, &fl_sock);
	security_sk_classify_flow(other->sk, &fl_other);

	return infoflow_allow_access(CLASS_PROCESS, fl_sock.flowi_secid,
				     CLASS_SOCKET, fl_other.flowi_secid,
				     NULL, MAY_WRITE, &ad);
}

static int sock_has_perm(struct sock *sk, int mask)
{
	const struct cred *cred = current_cred();
	struct common_audit_data ad;
	struct lsm_network_audit net = {0,};
	struct flowi fl_sk;
	u32 ssid;

	ad.type = LSM_AUDIT_DATA_NET;
	ad.u.net = &net;
	ad.u.net->sk = sk;

	validate_creds(cred);
	security_cred_getsecid(cred, &ssid);

	security_sk_classify_flow(sk, &fl_sk);

	return infoflow_allow_access(CLASS_PROCESS, ssid, CLASS_SOCKET,
				     fl_sk.flowi_secid, NULL, mask, &ad);
}

static int infoflow_socket_sendmsg(struct socket *sock, struct msghdr *msg,
				   int size)
{
	return sock_has_perm(sock->sk, MAY_WRITE);
}

static int infoflow_socket_recvmsg(struct socket *sock, struct msghdr *msg,
				   int size, int flags)
{
	return sock_has_perm(sock->sk, MAY_READ);
}

static int infoflow_audit_rule_init(u32 field, u32 op, char *rulestr,
				    void **vrule)
{
	if (field != AUDIT_SUBJ_USER)
		return -EINVAL;

	if (op != Audit_equal && op != Audit_not_equal)
		return -EINVAL;

	return 0;
}

static int infoflow_audit_rule_known(struct audit_krule *krule)
{
	struct audit_field *f;
	int i;

	for (i = 0; i < krule->field_count; i++) {
		f = &krule->fields[i];

		if (f->type == AUDIT_SUBJ_USER)
			return 1;
	}

	return 0;
}

static int infoflow_audit_rule_match(u32 sid, u32 field, u32 op, void *vrule)
{
	struct infoflow_ctx *ctx;

	if (field != AUDIT_SUBJ_USER)
		return 0;

	if (!(infoflow_init_flags & INFOFLOW_PARENT_LSM_INIT))
		return (op == Audit_equal) ? true : false;

	ctx = infoflow_ctx_find_sid(CLASS_PROCESS, sid);

	if (op == Audit_equal)
		return (ctx && (ctx->flags & CTX_FLAG_TCB));
	if (op == Audit_not_equal)
		return (!ctx || !(ctx->flags & CTX_FLAG_TCB));

	return 0;
}

struct lsm_blob_sizes infoflow_blob_sizes = {
	.lbs_inode = sizeof(u8),
	.lbs_file = sizeof(struct file_security_struct),
};

static struct security_hook_list infoflow_hooks[] __lsm_ro_after_init = {
	LSM_HOOK_INIT(inode_init_security, infoflow_inode_init_security),

	LSM_HOOK_INIT(d_instantiate, infoflow_d_instantiate),

	LSM_HOOK_INIT(inode_permission, infoflow_inode_permission),
	LSM_HOOK_INIT(inode_setxattr, infoflow_inode_setxattr),
	LSM_HOOK_INIT(inode_post_setxattr, infoflow_inode_post_setxattr),
	LSM_HOOK_INIT(inode_removexattr, infoflow_inode_removexattr),
	LSM_HOOK_INIT(inode_setsecurity, infoflow_inode_setsecurity),

	LSM_HOOK_INIT(file_permission, infoflow_file_permission),
	LSM_HOOK_INIT(file_receive, infoflow_file_receive),
	LSM_HOOK_INIT(file_open, infoflow_file_open),

	LSM_HOOK_INIT(kernel_read_file, infoflow_kernel_read_file),
	LSM_HOOK_INIT(kernel_load_data, infoflow_kernel_load_data),

	LSM_HOOK_INIT(setprocattr, infoflow_setprocattr),

	LSM_HOOK_INIT(ipc_permission, infoflow_ipc_permission),

	LSM_HOOK_INIT(msg_queue_msgsnd, infoflow_msg_queue_msgsnd),
	LSM_HOOK_INIT(msg_queue_msgrcv, infoflow_msg_queue_msgrcv),

	LSM_HOOK_INIT(shm_shmat, infoflow_shm_shmat),

	LSM_HOOK_INIT(sem_semctl, infoflow_sem_semctl),
	LSM_HOOK_INIT(sem_semop, infoflow_sem_semop),

	LSM_HOOK_INIT(unix_may_send, infoflow_socket_unix_may_send),
	LSM_HOOK_INIT(socket_sendmsg, infoflow_socket_sendmsg),
	LSM_HOOK_INIT(socket_recvmsg, infoflow_socket_recvmsg),

#ifdef CONFIG_AUDIT
	LSM_HOOK_INIT(audit_rule_init, infoflow_audit_rule_init),
	LSM_HOOK_INIT(audit_rule_known, infoflow_audit_rule_known),
	LSM_HOOK_INIT(audit_rule_match, infoflow_audit_rule_match),
#endif

};

static __init int infoflow_init(void)
{
	int rc;

	if (!infoflow_enabled)
		return 0;

	rc = register_blocking_lsm_notifier(&infoflow_lsm_nb);
	if (rc) {
		pr_warn("Couldn't register LSM notifier. rc %d\n", rc);
		return rc;
	}

	security_add_hooks(infoflow_hooks, ARRAY_SIZE(infoflow_hooks),
			   "infoflow");
	return 0;
}

DEFINE_LSM(infoflow) = {
	.name = "infoflow",
	.flags = LSM_FLAG_LEGACY_MAJOR,
	.blobs = &infoflow_blob_sizes,
	.init = infoflow_init,
};
