// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2017-2019 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: ima_digest_list.h
 *      Header of ima_digest_list.c
 */

#ifndef __LINUX_IMA_DIGEST_LIST_H
#define __LINUX_IMA_DIGEST_LIST_H

static inline bool ima_digest_is_immutable(struct ima_digest *digest)
{
	return (digest->modifiers & (1 << COMPACT_MOD_IMMUTABLE));
}

#ifdef CONFIG_IMA_DIGEST_LIST
extern struct ima_h_table ima_digests_htable;

struct ima_digest *ima_lookup_digest(u8 *digest, enum hash_algo algo);
int ima_parse_compact_list(loff_t size, void *buf);
bool ima_check_current_is_parser(void);
void ima_set_parser(struct task_struct *parser);
struct task_struct *ima_get_parser(void);
void ima_check_parser_action(struct inode *inode, enum ima_hooks hook,
			     int mask, int action, bool check_digest,
			     struct ima_digest *digest);
struct ima_digest *ima_digest_allow(struct ima_digest *digest, int action);
#else
static inline struct ima_digest *ima_lookup_digest(u8 *digest,
						   enum hash_algo algo)
{
	return NULL;
}
static inline int ima_parse_compact_list(loff_t size, void *buf)
{
	return -ENOTSUPP;
}
static inline bool ima_check_current_is_parser(void)
{
	return false;
}
static inline void ima_set_parser(struct task_struct *parser)
{
}
static inline struct task_struct *ima_get_parser(void)
{
	return NULL;
}
static inline void ima_check_parser_action(struct inode *inode,
					   enum ima_hooks hook, int mask,
					   int action, bool check_digest,
					   struct ima_digest *digest)
{
}
static inline struct ima_digest *ima_digest_allow(struct ima_digest *digest,
						  int action)
{
	return NULL;
}
#endif /*CONFIG_IMA_DIGEST_LIST*/
#endif /*LINUX_IMA_DIGEST_LIST_H*/
