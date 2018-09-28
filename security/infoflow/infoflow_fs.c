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
 * File: infoflow_fs.c
 *      Functions implementing methods for securityfs.
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/seq_file.h>
#include <linux/security.h>
#include <linux/parser.h>

#include "infoflow.h"

static struct dentry *infoflow_dir;
static struct dentry *infoflow_rules;
static struct dentry *infoflow_policy;
static struct dentry *infoflow_enforce;

static void *infoflow_ctx_start(struct seq_file *m, loff_t *pos)
{
	loff_t l = *pos;
	struct infoflow_ctx *ctx;

	if (m->file->f_path.dentry == infoflow_policy &&
	    !(infoflow_init_flags & INFOFLOW_POLICY_INIT))
		return NULL;

	rcu_read_lock();
	list_for_each_entry_rcu(ctx, &contexts, context_list) {
		if (!l--) {
			rcu_read_unlock();
			return ctx;
		}
	}
	rcu_read_unlock();
	return NULL;
}

static void *infoflow_ctx_next(struct seq_file *m, void *v, loff_t *pos)
{
	struct infoflow_ctx *ctx = v;

	rcu_read_lock();
	ctx = list_entry_rcu(ctx->context_list.next, struct infoflow_ctx,
			     context_list);
	rcu_read_unlock();
	(*pos)++;

	return (&ctx->context_list == &contexts) ? NULL : ctx;
}

static void infoflow_ctx_stop(struct seq_file *m, void *v)
{
}

int infoflow_rules_show(struct seq_file *m, void *v)
{
	struct infoflow_ctx *ctx = v;
	struct infoflow_subj_desc *desc;

	list_for_each_entry(desc, &ctx->access_subjs, list) {
		seq_printf(m, "allow %s %s:%s {", desc->ctx->label, ctx->label,
			   infoflow_class_array[ctx->class].name);

		if (desc->mask & MAY_READ || desc->mask & MAY_EXEC)
			seq_printf(m, " read");
		if (desc->mask & MAY_WRITE || desc->mask & MAY_APPEND)
			seq_printf(m, " write");

		seq_printf(m, " };");

		if (desc->denied)
			seq_printf(m, " [denied:%s]", desc->cause);

		seq_printf(m, "\n");
	}

	return 0;
}

static const struct seq_operations infoflow_rules_seqops = {
	.start = infoflow_ctx_start,
	.next = infoflow_ctx_next,
	.stop = infoflow_ctx_stop,
	.show = infoflow_rules_show,
};

static int infoflow_rules_open(struct inode *inode, struct file *file)
{
	return seq_open(file, &infoflow_rules_seqops);
}

static const struct file_operations infoflow_rules_ops = {
	.open = infoflow_rules_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

int infoflow_policy_show(struct seq_file *m, void *v)
{
	struct infoflow_ctx *ctx = v;
	struct infoflow_subj_desc *desc;

	if (ctx->flags & CTX_FLAG_FILTER)
		seq_printf(m, "filter");
	else if (ctx->flags & CTX_FLAG_TCB)
		seq_printf(m, "tcb");
	else
		return 0;

	if (ctx->class == CLASS_PROCESS)
		seq_printf(m, " subj=");
	else
		seq_printf(m, " obj=");

	seq_printf(m, "%s:%s", ctx->label,
		   infoflow_class_array[ctx->class].name);

	list_for_each_entry(desc, &ctx->filter_subjs, list)
		seq_printf(m, " subj=%s:%s", desc->ctx->label,
			   infoflow_class_array[desc->ctx->class].name);

	seq_printf(m, "\n");

	return 0;
}

static const struct seq_operations policy_seq_ops = {
	.start = infoflow_ctx_start,
	.next  = infoflow_ctx_next,
	.stop  = infoflow_ctx_stop,
	.show  = infoflow_policy_show,
};

enum {
	Opt_err = -1, Opt_tcb = 1, Opt_filter, Opt_subj, Opt_obj,
};

static match_table_t policy_tokens = {
	{Opt_tcb, "tcb"},
	{Opt_filter, "filter"},
	{Opt_subj, "subj=%s"},
	{Opt_obj, "obj=%s"},
};

int valid_policy;

static int infoflow_open_policy(struct inode *inode, struct file *file)
{
	if ((infoflow_init_flags & INFOFLOW_POLICY_INIT) &&
	    (file->f_mode & FMODE_WRITE))
		return -EPERM;

	valid_policy = 1;

	return seq_open(file, &policy_seq_ops);
}

static struct infoflow_ctx *infoflow_add_ctx(char *label, u8 flags, bool obj)
{
	enum infoflow_class class = CLASS_PROCESS;
	char *class_ptr;

	if (!obj)
		goto out;

	class_ptr = strrchr(label, ':');
	if (!class_ptr)
		return ERR_PTR(-EINVAL);

	*class_ptr++ = '\0';

	class = infoflow_lookup_class(class_ptr);
	if (class == CLASS__LAST) {
		pr_err("Invalid class %s\n", class_ptr);
		return ERR_PTR(-EINVAL);
	}
out:
	return infoflow_ctx_insert_label(class, label, strlen(label), flags);
}

static int infoflow_parse_rule(char *rule)
{
	struct infoflow_ctx *subj = NULL, *obj = NULL;
	LIST_HEAD(filtering_subjects);
	struct infoflow_subj_desc *desc, *tmp_desc;
	char *p;
	u8 flags = 0;
	int result = 0;

	while ((p = strsep(&rule, " \t")) != NULL) {
		substring_t args[MAX_OPT_ARGS];
		int token;

		if (result < 0)
			break;
		if ((*p == '\0') || (*p == ' ') || (*p == '\t'))
			continue;
		token = match_token(p, policy_tokens, args);
		switch (token) {
		case Opt_tcb:
			if (flags) {
				pr_err("Rule type already specified\n");
				result = -EINVAL;
				break;
			}

			flags |= CTX_FLAG_TCB;
			break;
		case Opt_filter:
			if (flags) {
				pr_err("Rule type already specified\n");
				result = -EINVAL;
				break;
			}

			flags |= CTX_FLAG_FILTER;
			break;
		case Opt_subj:
			if (!flags) {
				pr_err("Rule type not specified\n");
				result = -EINVAL;
				break;
			}

			if (!(flags & CTX_FLAG_FILTER) && subj) {
				pr_err("Subject already specified\n");
				result = -EINVAL;
				break;
			}

			if ((flags & CTX_FLAG_FILTER) && !obj) {
				pr_err("Object not specified\n");
				result = -EINVAL;
				break;
			}

			subj = infoflow_add_ctx(args[0].from,
					(flags & CTX_FLAG_FILTER) ?
					0 : flags, false);
			if (IS_ERR(subj)) {
				result = PTR_ERR(subj);
				break;
			}

			if (flags & CTX_FLAG_FILTER) {
				result = infoflow_ctx_find_add_subj(0, 0, &subj,
						0, 0, 0, &obj, 0, 0, 0, NULL,
						TYPE_FILTER);
				if (result < 0)
					break;
			}

			desc = kmalloc(sizeof(*desc), GFP_KERNEL);
			if (!desc) {
				result = -ENOMEM;
				break;
			}
			desc->ctx = subj;
			list_add_tail(&desc->list, &filtering_subjects);
			break;
		case Opt_obj:
			if (!flags || obj) {
				pr_err("Rule type not specified or "
				       "object specified\n");
				result = -EINVAL;
				break;
			}

			obj = infoflow_add_ctx(args[0].from, flags, true);
			if (IS_ERR(obj)) {
				result = -ENOMEM;
				break;
			}
			break;
		case Opt_err:
			result = -EINVAL;
			break;
		}
	}

	if (!result && !flags) {
		pr_err("Rule type not specified\n");
		result = -EINVAL;
	}

	list_for_each_entry_safe(desc, tmp_desc, &filtering_subjects, list) {
		if (!(desc->ctx->flags & CTX_FLAG_TCB)) {
			pr_err("Filtering subject %s not added to TCB\n",
			       desc->ctx->label);
			list_del(&desc->list);
			kfree(desc);
			result = -EINVAL;
		}
	}

	if (result < 0)
		infoflow_ctx_delete();

	return result;
}

static ssize_t infoflow_write_policy(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos)
{
	char *data, *data_ptr, *newline_ptr;
	int rc = 0;

	if (cap_capable(current_cred(), &init_user_ns, CAP_MAC_ADMIN,
			CAP_OPT_NONE))
		return -EACCES;

	if (*ppos != 0)
		return -EINVAL;

	if (count >= PAGE_SIZE)
		count = PAGE_SIZE - 1;

	data_ptr = data = memdup_user_nul(buf, count);
	if (IS_ERR(data))
		return PTR_ERR(data);

	while (*(newline_ptr = strchrnul(data_ptr, '\n')) == '\n') {
		*newline_ptr = '\0';

		rc = infoflow_parse_rule(data_ptr);
		if (rc < 0)
			break;

		data_ptr = newline_ptr + 1;
	}

	kfree(data);

	if (rc < 0) {
		valid_policy = 0;
		return rc;
	}

	return data_ptr - data;
}

static int infoflow_release_policy(struct inode *inode, struct file *file)
{
	if (!(file->f_mode & FMODE_WRITE))
		return 0;

	if (!valid_policy) {
		pr_err("Cannot load infoflow policy\n");
		return 0;
	}

	infoflow_init_flags |= INFOFLOW_POLICY_INIT;

	pr_info("Successfully loaded Infoflow LSM policy\n");

	return 0;
}

static const struct file_operations infoflow_policy_ops = {
	.open		= infoflow_open_policy,
	.read		= seq_read,
	.llseek         = seq_lseek,
	.write		= infoflow_write_policy,
	.release	= infoflow_release_policy,
};


static int infoflow_open_mode(struct inode *inode, struct file *file)
{
	if ((file->f_mode & FMODE_WRITE) &&
	    cap_capable(current_cred(), &init_user_ns, CAP_MAC_ADMIN,
			CAP_OPT_NONE))
		return -EACCES;

	return 0;
}

#define TMPBUFLEN	32
static ssize_t infoflow_read_mode(struct file *filp, char __user *buf,
				  size_t count, loff_t *ppos)
{
	char tmpbuf[TMPBUFLEN];
	ssize_t length;

	length = scnprintf(tmpbuf, sizeof(tmpbuf), "%s",
			   infoflow_modes_str[infoflow_mode]);
	return simple_read_from_buffer(buf, count, ppos, tmpbuf, length);
}

static ssize_t infoflow_write_mode(struct file *file, const char __user *buf,
				   size_t count, loff_t *ppos)

{
	char *new_mode = NULL;
	ssize_t length;
	int i;

	if (count >= PAGE_SIZE)
		return -ENOMEM;

	/* No partial writes. */
	if (*ppos != 0)
		return -EINVAL;

	new_mode = memdup_user_nul(buf, count);
	if (IS_ERR(new_mode))
		return PTR_ERR(new_mode);

	for (i = 0; i < INFOFLOW_MODE__LAST; i++) {
		if (!strcmp(new_mode, infoflow_modes_str[i])) {
			infoflow_mode = i;
			break;
		}
	}

	if (i == INFOFLOW_MODE__LAST) {
		length = -EINVAL;
		goto out;
	}

	length = count;
out:
	kfree(new_mode);
	return length;
}

static const struct file_operations infoflow_enforce_ops = {
	.open		= infoflow_open_mode,
	.read		= infoflow_read_mode,
	.write		= infoflow_write_mode,
	.llseek		= generic_file_llseek,
};

static int __init init_infoflow_fs(void)
{
	infoflow_dir = securityfs_create_dir("infoflow", NULL);
	if (IS_ERR(infoflow_dir))
		goto out;

	infoflow_rules = securityfs_create_file("rules", S_IRUGO,
				infoflow_dir, NULL, &infoflow_rules_ops);
	if (IS_ERR(infoflow_rules))
		goto out;

	infoflow_policy = securityfs_create_file("policy", S_IRUGO | S_IWUSR,
				infoflow_dir, NULL, &infoflow_policy_ops);
	if (IS_ERR(infoflow_policy))
		goto out;

	infoflow_enforce = securityfs_create_file("enforce",
					S_IRUGO | S_IWUSR, infoflow_dir, NULL,
					&infoflow_enforce_ops);
	if (IS_ERR(infoflow_enforce))
		goto out;

	return 0;
out:
	securityfs_remove(infoflow_enforce);
	securityfs_remove(infoflow_policy);
	securityfs_remove(infoflow_rules);
	securityfs_remove(infoflow_dir);
	return -1;
}

__initcall(init_infoflow_fs);
