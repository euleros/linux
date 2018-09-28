// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2008 IBM Corporation
 * Copyright (C) 2018,2019 Huawei Technologies Duesseldorf GmbH
 *
 * Authors: Roberto Sassu <roberto.sassu@huawei.com>
 *          Mimi Zohar <zohar@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: infoflow_ctx.c
 *      Functions to manage security contexts.
 */

#include <linux/slab.h>
#include <linux/module.h>
#include <linux/spinlock.h>
#include <linux/rbtree.h>

#include "infoflow.h"

static struct rb_root infoflow_ctx_tree[CLASS__LAST] = { RB_ROOT };
static DEFINE_RWLOCK(infoflow_ctx_lock);
LIST_HEAD(contexts);

static struct infoflow_ctx *__infoflow_ctx_find_sid(enum infoflow_class class,
						    u32 sid)
{
	struct infoflow_ctx *ctx;
	struct rb_node *n = infoflow_ctx_tree[class].rb_node;

	while (n) {
		ctx = rb_entry(n, struct infoflow_ctx, rb_node);

		if (sid < ctx->sid)
			n = n->rb_left;
		else if (sid > ctx->sid)
			n = n->rb_right;
		else
			break;
	}
	if (!n)
		return NULL;

	return ctx;
}

/*
 * infoflow_ctx_find_sid - return the ctx associated with the class and sid
 * @class: object class
 * @sid: object's security identifier
 *
 * Return infoflow_ctx if found, NULL otherwise.
 */
struct infoflow_ctx *infoflow_ctx_find_sid(enum infoflow_class class, u32 sid)
{
	struct infoflow_ctx *ctx;

	read_lock(&infoflow_ctx_lock);
	ctx = __infoflow_ctx_find_sid(class, sid);
	read_unlock(&infoflow_ctx_lock);

	return ctx;
}

static struct infoflow_ctx *__infoflow_ctx_find_label(enum infoflow_class class,
						      char *label,
						      int label_len)
{
	struct infoflow_ctx *ctx;

	list_for_each_entry(ctx, &contexts, context_list)
		if (ctx->class == class && ctx->label_len == label_len &&
		    !strncmp(ctx->label, label, label_len))
			return ctx;

	return NULL;
}

static struct infoflow_ctx *infoflow_ctx_find_label(enum infoflow_class class,
						    char *label, int label_len)
{
	struct infoflow_ctx *ctx;

	read_lock(&infoflow_ctx_lock);
	ctx = __infoflow_ctx_find_label(class, label, label_len);
	read_unlock(&infoflow_ctx_lock);

	return ctx;
}

static void infoflow_ctx_insert_to_rbtree(struct infoflow_ctx *ctx)
{
	struct rb_node **p;
	struct rb_node *node, *parent = NULL;
	struct infoflow_ctx *test_ctx;

	p = &infoflow_ctx_tree[ctx->class].rb_node;
	while (*p) {
		parent = *p;
		test_ctx = rb_entry(parent, struct infoflow_ctx, rb_node);
		if (ctx->sid < test_ctx->sid)
			p = &(*p)->rb_left;
		else
			p = &(*p)->rb_right;
	}

	node = &ctx->rb_node;
	rb_link_node(node, parent, p);
	rb_insert_color(node, &infoflow_ctx_tree[ctx->class]);
}

static struct infoflow_ctx *infoflow_ctx_insert(enum infoflow_class class,
						u32 sid, u8 flags, char *label,
						int label_len)
{
	struct infoflow_ctx *ctx;

	ctx = kmalloc(sizeof(*ctx), GFP_ATOMIC | __GFP_NOWARN);
	if (!ctx)
		return ERR_PTR(-ENOMEM);

	ctx->sid = sid;
	ctx->flags = flags;
	ctx->class = class;
	ctx->label = kmemdup_nul(label, label_len, GFP_ATOMIC | __GFP_NOWARN);
	if (!ctx->label) {
		kfree(ctx);
		return ERR_PTR(-ENOMEM);
	}

	ctx->label_len = label_len;

	INIT_LIST_HEAD(&ctx->access_subjs);
	INIT_LIST_HEAD(&ctx->filter_subjs);
	spin_lock_init(&ctx->ctx_lock);

	write_lock(&infoflow_ctx_lock);
	infoflow_ctx_insert_to_rbtree(ctx);
	list_add_tail_rcu(&ctx->context_list, &contexts);
	write_unlock(&infoflow_ctx_lock);

	return ctx;
}

/**
 * infoflow_ctx_insert_sid - insert ctx from sid
 * @class: object class
 * @sid: object's security identifier
 * @flags: flags associated to the sid
 *
 * Return new infoflow_ctx on success, NULL on error.
 */
struct infoflow_ctx *infoflow_ctx_insert_sid(enum infoflow_class class, u32 sid,
					     u8 flags)
{
	char *label;
	int label_len;
	int result;
	struct infoflow_ctx *ctx;

	ctx = infoflow_ctx_find_sid(class, sid);
	if (ctx) {
		ctx->flags |= flags;
		return ctx;
	}

	result = security_secid_to_secctx(sid, &label, &label_len);
	if (result < 0) {
		pr_err("Cannot retrieve label for sid %d\n", sid);
		return ERR_PTR(-EINVAL);
	}

	ctx = infoflow_ctx_insert(class, sid, flags, label, label_len);

	security_release_secctx(label, label_len);
	return ctx;
}

/**
 * infoflow_ctx_insert_label - insert ctx from label
 * @class: object class
 * @label: label associated to the sid
 * @label_len: label length
 * @flags: flags associated to the sid
 *
 * Return new infoflow_ctx on success, NULL on error.
 */
struct infoflow_ctx *infoflow_ctx_insert_label(enum infoflow_class class,
					       char *label, int label_len,
					       u8 flags)
{
	struct infoflow_ctx *ctx;
	u32 sid = 0;
	int result;

	ctx = infoflow_ctx_find_label(class, label, label_len);
	if (ctx) {
		ctx->flags |= flags;
		return ctx;
	}

	if (!(infoflow_init_flags & INFOFLOW_PARENT_LSM_INIT))
		goto out;

	result = security_secctx_to_secid(label, label_len, &sid);
	if (result < 0) {
		pr_err("Cannot retrieve sid for label %s\n", label);
		return ERR_PTR(-EINVAL);
	}
out:
	return infoflow_ctx_insert(class, sid, flags, label, label_len);
}

/**
 * infoflow_ctx_delete - delete all contexts
 *
 */
void infoflow_ctx_delete(void)
{
	struct infoflow_ctx *ctx, *tmp_ctx;
	int i;

	write_lock(&infoflow_ctx_lock);
	list_for_each_entry_safe(ctx, tmp_ctx, &contexts, context_list) {
		list_del(&ctx->context_list);
		kfree(ctx->label);
		kfree(ctx);
	}

	for (i = 0; i < CLASS__LAST; i++)
		infoflow_ctx_tree[i] = RB_ROOT;

	write_unlock(&infoflow_ctx_lock);
}

/**
 * infoflow_ctx_update_sid - update infoflow_ctx SID after policy change
 *
 */
void infoflow_ctx_update_sid(void)
{
	struct infoflow_ctx *ctx;
	u32 new_sid;
	int result;

	list_for_each_entry(ctx, &contexts, context_list) {
		result = security_secctx_to_secid(ctx->label,
						  strlen(ctx->label),
						  &new_sid);
		if (result < 0) {
			pr_err("Cannot obtain SID for context %s\n",
			       ctx->label);
			continue;
		}

		if (ctx->sid == new_sid)
			continue;

		write_lock(&infoflow_ctx_lock);
		rb_erase(&ctx->rb_node, &infoflow_ctx_tree[ctx->class]);

		ctx->sid = new_sid;
		infoflow_ctx_insert_to_rbtree(ctx);
		write_unlock(&infoflow_ctx_lock);
	}
}

/**
 * infoflow_ctx_find_add_subj - add discovered interaction or filtering subj
 * @sclass: subject class
 * @ssid: subject's security identifier
 * @sctx: subject's infoflow_ctx
 * @sflags: subject's flags
 * @oclass: object class
 * @osid: object's security identifier
 * @octx: object's infoflow_ctx
 * @oflags: object's flags
 * @mask: operations requested
 * @denied: whether access is denied
 * @cause: reason if access is denied
 * @type: type of information (rule, filtering subj)
 *
 * Return 0 on success, a negative value on failure.
 */
int infoflow_ctx_find_add_subj(enum infoflow_class sclass, u32 ssid,
			       struct infoflow_ctx **sctx, u8 sflags,
			       enum infoflow_class oclass, u32 osid,
			       struct infoflow_ctx **octx, u8 oflags,
			       int mask, u8 denied, const char *cause,
			       int type)
{
	struct infoflow_subj_desc *desc, *found_desc = NULL;
	struct list_head *head;

	if (!*sctx) {
		*sctx = infoflow_ctx_insert_sid(sclass, ssid, sflags);
		if (IS_ERR(*sctx))
			return PTR_ERR(*sctx);
	}

	if (!*octx) {
		*octx = infoflow_ctx_insert_sid(oclass, osid, oflags);
		if (IS_ERR(*octx))
			return PTR_ERR(*octx);
	}

	head = &(*octx)->access_subjs;
	if (type == TYPE_FILTER)
		head = &(*octx)->filter_subjs;

	list_for_each_entry(desc, head, list) {
		if (desc->ctx == *sctx) {
			found_desc = desc;
			break;
		}
	}

	if (!found_desc) {
		desc = kmalloc(sizeof(*desc), GFP_ATOMIC | __GFP_NOWARN);
		if (!desc) {
			pr_err("Cannot allocate memory for subject desc\n");
			return -ENOMEM;
		}

		desc->ctx = *sctx;
		desc->mask = 0;
		desc->denied = 0;
		desc->cause = cause;

		spin_lock(&(*octx)->ctx_lock);
		list_add_tail_rcu(&desc->list, head);
		spin_unlock(&(*octx)->ctx_lock);
	}

	desc->mask |= mask;
	desc->denied |= denied;
	return 0;
}
