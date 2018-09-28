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
 * File: infoflow_access.c
 *      Functions to enforce Clark-Wilson policy and log decisions.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/cred.h>
#include <linux/magic.h>
#include <linux/audit.h>
#include <linux/xattr.h>

#include "infoflow.h"

struct infoflow_ctx unknown_ctx = { .class = CLASS_UNDEFINED,
				    .label = "unknown_label" };

static void infoflow_log_callback(struct audit_buffer *ab, void *a)
{
	struct common_audit_data *ad = a;
	struct infoflow_audit_data *sad = ad->infoflow_audit_data;

	audit_log_format(ab, "lsm=infoflow request=%d action=%s cause=%s",
			 sad->request, sad->result ? "denied" : "granted",
			 sad->cause);
	audit_log_format(ab, " subject=%s object=%s oclass=%s",
			 sad->subj->label, sad->obj->label,
			 infoflow_class_array[sad->obj->class].name);
}

static void infoflow_log(struct infoflow_ctx *subj, struct infoflow_ctx *obj,
			 int request, int result, char *cause,
			 struct common_audit_data *a)
{
	struct infoflow_audit_data sad;

	memset(&sad, 0, sizeof(sad));

	sad.subj = subj;
	if (!sad.subj)
		sad.subj = &unknown_ctx;
	sad.obj = obj;
	if (!sad.obj)
		sad.obj = &unknown_ctx;
	sad.request = request;
	sad.result = result;
	sad.cause = cause;

	a->infoflow_audit_data = &sad;

	common_lsm_audit(a, infoflow_log_callback, NULL);
}

/**
 * infoflow_allow_access - enforce Clark-Wilson policy
 * @sclass: subject class
 * @ssid: subject's security identifier
 * @oclass: object class
 * @osid: object's security identifier
 * @inode_flags: inode's flags
 * @mask: operations requested
 * @a: audit structure
 *
 * Return 0 on success, a negative value on failure.
 */
int infoflow_allow_access(enum infoflow_class sclass, u32 ssid,
			  enum infoflow_class oclass, u32 osid,
			  u8 *inode_flags, int mask,
			  struct common_audit_data *a)
{
	struct infoflow_subj_desc *desc, *found_desc = NULL;
	struct infoflow_ctx *sctx = NULL, *octx = NULL;
	u8 sflags = 0, oflags = inode_flags ? *inode_flags : 0;
	bool denied = false;
	char *cause = "unknown";
	int result;

	if (infoflow_class_array[oclass].excluded)
		return 0;

	if (!(infoflow_init_flags & INFOFLOW_PARENT_LSM_INIT))
		return 0;

	if (infoflow_mode == INFOFLOW_DISCOVER) {
		result = infoflow_ctx_find_add_subj(sclass, ssid, &sctx, 0,
						    oclass, osid, &octx, 0,
						    mask, 0, NULL, TYPE_RULE);
		if (result < 0)
			pr_err("Cannot add rule for sclass %d, ssid %d, "
			       "oclass %d, osid %d\n", sclass, ssid, oclass,
			       osid);

		return 0;
	}

	if (!(infoflow_init_flags & INFOFLOW_POLICY_INIT))
		return 0;

	sctx = infoflow_ctx_find_sid(sclass, ssid);
	if (sctx)
		sflags |= sctx->flags;

	octx = infoflow_ctx_find_sid(oclass, osid);
	if (octx)
		oflags |= octx->flags;

	if (mask & MAY_WRITE && !(sflags & CTX_FLAG_TCB) &&
	    !(oflags & CTX_FLAG_TCB) && inode_flags)
		*inode_flags |= CTX_FLAG_CANNOT_PROMOTE;

	if ((mask & MAY_WRITE) && !(sflags & CTX_FLAG_TCB) &&
	    (oflags & CTX_FLAG_TCB) && !(oflags & CTX_FLAG_FILTER)) {
		denied = true;
		cause = "biba-write-up";
	}

	if ((mask & (MAY_READ | MAY_EXEC)) && (sflags & CTX_FLAG_TCB) &&
	    !(oflags & CTX_FLAG_TCB) && !(oflags & CTX_FLAG_FILTER)) {
		if ((infoflow_init_flags & INFOFLOW_PROMOTE) &&
		    !(mask & MAY_WRITE) &&
		    !(oflags & CTX_FLAG_CANNOT_PROMOTE) && inode_flags) {
			*inode_flags |= CTX_FLAG_TCB;
		} else {
			denied = true;
			cause = "biba-read-down";
		}
	}

	if ((mask & (MAY_READ | MAY_EXEC)) && (sflags & CTX_FLAG_TCB) &&
	    !(oflags & CTX_FLAG_TCB) && (oflags & CTX_FLAG_FILTER)) {
		if (list_empty(&octx->filter_subjs)) {
			found_desc = (void *)1;
		} else {
			list_for_each_entry(desc, &octx->filter_subjs, list)
				if (desc->ctx == sctx) {
					found_desc = desc;
					break;
				}
		}

		if (!found_desc) {
			denied = true;
			cause = "filtering-subj-not-found";
		}
	}

	if (!denied)
		return 0;

	if (infoflow_mode == INFOFLOW_ENFORCE_AUDIT ||
	    infoflow_mode == INFOFLOW_PERMISSIVE_AUDIT) {
		result = infoflow_ctx_find_add_subj(sclass, ssid, &sctx, 0,
						    oclass, osid, &octx, 0,
						    mask, denied, cause,
						    TYPE_RULE);
		if (result < 0)
			pr_err("Cannot add rule for sclass %d, ssid %d,"
			       "oclass %d, osid %d\n", sclass, ssid,
			       oclass, osid);
	}

	result = 0;

	if (infoflow_mode == INFOFLOW_ENFORCE ||
	    infoflow_mode == INFOFLOW_ENFORCE_AUDIT)
		result = -EACCES;

	if (a)
		infoflow_log(sctx, octx, mask, result, cause, a);

	return result;
}
