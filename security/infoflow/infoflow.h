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
 * File: infoflow.h
 *      Header file.
 */

#ifndef __INFOFLOW_H
#define __INFOFLOW_H

#include <linux/lsm_hooks.h>
#include <linux/lsm_audit.h>
#include <linux/msg.h>
#include <net/flow.h>
#include <net/sock.h>

enum infoflow_class {CLASS_LNK_FILE, CLASS_REG_FILE, CLASS_DIR,
		     CLASS_CHR_FILE, CLASS_BLK_FILE, CLASS_FIFO_FILE,
		     CLASS_SOCK_FILE, CLASS_IPC, CLASS_MSGQ, CLASS_SHM,
		     CLASS_SEM, CLASS_SOCKET, CLASS_KEY, CLASS_PROCESS,
		     CLASS_KERNEL, CLASS_MODULE, CLASS_UNDEFINED, CLASS__LAST};

struct infoflow_class_desc {
	const char *name;
	u8 excluded;
};

extern struct infoflow_class_desc infoflow_class_array[CLASS__LAST];

extern struct list_head contexts;

#define INFOFLOW_PARENT_LSM_INIT	0x1
#define INFOFLOW_POLICY_INIT		0x2
#define INFOFLOW_PROMOTE		0x4
extern int infoflow_init_flags;

enum infoflow_modes { INFOFLOW_DISABLED, INFOFLOW_DISCOVER, INFOFLOW_ENFORCE,
		      INFOFLOW_ENFORCE_AUDIT, INFOFLOW_PERMISSIVE,
		      INFOFLOW_PERMISSIVE_AUDIT, INFOFLOW_MODE__LAST };

extern const char *infoflow_modes_str[INFOFLOW_MODE__LAST];
extern int infoflow_mode;

#define CTX_FLAG_TCB		0x01
#define CTX_FLAG_FILTER		0x02
#define CTX_FLAG_INITIALIZED	0x04
#define CTX_FLAG_CANNOT_PROMOTE	0x08
struct infoflow_ctx {
	struct rb_node rb_node;
	struct list_head access_subjs;
	struct list_head filter_subjs;
	struct list_head context_list;
	spinlock_t ctx_lock;
	u32 sid;
	u8 flags;
	enum infoflow_class class;
	char *label;
	int label_len;
};

#define TYPE_RULE		0
#define TYPE_FILTER		1
struct infoflow_subj_desc {
	struct list_head list;
	struct infoflow_ctx *ctx;
	int mask;
	u8 denied;
	const char *cause;
};

struct infoflow_audit_data {
	struct infoflow_ctx *subj;
	struct infoflow_ctx *obj;
	int request;
	int result;
	char *cause;
};

static inline u16 infoflow_inode_class(umode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFSOCK:
		return CLASS_SOCK_FILE;
	case S_IFLNK:
		return CLASS_LNK_FILE;
	case S_IFREG:
		return CLASS_REG_FILE;
	case S_IFBLK:
		return CLASS_BLK_FILE;
	case S_IFDIR:
		return CLASS_DIR;
	case S_IFCHR:
		return CLASS_CHR_FILE;
	case S_IFIFO:
		return CLASS_FIFO_FILE;
	}

	return CLASS_UNDEFINED;
}

static inline u32 infoflow_file_f_mode_to_mask(struct file *file)
{
	int mask = 0;

	if (file->f_mode & FMODE_READ)
		mask |= MAY_READ;
	if (file->f_mode & FMODE_WRITE)
		mask |= MAY_WRITE;

	return mask;
}

static inline enum infoflow_class infoflow_lookup_class(char *class)
{
	int i;

	for (i = 0; i < CLASS__LAST; i++) {
		if (!strcmp(infoflow_class_array[i].name, class))
			break;
	}

	return i;
}

struct file_security_struct {
	u32 sid;
	u32 isid;
	int pseqno;
};

extern struct lsm_blob_sizes infoflow_blob_sizes;

static inline u8 *infoflow_inode(const struct inode *inode)
{
	return inode->i_security + infoflow_blob_sizes.lbs_inode;
}

static inline struct file_security_struct *infoflow_file(
						const struct file *file)
{
	return file->f_security + infoflow_blob_sizes.lbs_file;
}

struct infoflow_ctx *infoflow_ctx_find_sid(enum infoflow_class class,
					   u32 sid);
struct infoflow_ctx *infoflow_ctx_insert_sid(enum infoflow_class class, u32 sid,
					     u8 flags);
struct infoflow_ctx *infoflow_ctx_insert_label(enum infoflow_class class,
					       char *label, int label_len,
					       u8 flags);
void infoflow_ctx_delete(void);
void infoflow_ctx_update_sid(void);
int infoflow_ctx_find_add_subj(enum infoflow_class sclass, u32 ssid,
			       struct infoflow_ctx **sctx, u8 sflags,
			       enum infoflow_class oclass, u32 osid,
			       struct infoflow_ctx **octx, u8 oflags,
			       int mask, u8 denied, const char *cause,
			       int type);

int infoflow_allow_access(enum infoflow_class sclass, u32 ssid,
			  enum infoflow_class oclass, u32 osid,
			  u8 *inode_flags, int mask,
			  struct common_audit_data *a);

#endif /*__INFOFLOW_H*/
