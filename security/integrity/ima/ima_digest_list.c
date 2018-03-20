/*
 * Copyright (C) 2017,2018 Huawei Technologies Duesseldorf GmbH
 *
 * Author: Roberto Sassu <roberto.sassu@huawei.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, version 2 of the
 * License.
 *
 * File: ima_digest_list.c
 *      Functions to manage digest lists.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/verification.h>
#include <linux/namei.h>
#include <linux/xattr.h>
#include <linux/magic.h>

#include "ima.h"
#include "ima_template_lib.h"

#define REQ_METADATA_VERSION 1

#define PARSER_STRING "~parser~\n"
#define REQ_PARSER_VERSION 1

static int ima_parser_metadata_load;

/*******************************
 * Digest list metadata parser *
 *******************************/
enum digest_metadata_fields {DATA_ALGO, DATA_TYPE, DATA_TYPE_EXT,
			     DATA_DIGEST_ALGO, DATA_DIGEST,
			     DATA_SIG_FMT, DATA_SIG,
			     DATA_FILE_PATH, DATA_LENGTH, DATA__LAST};

enum data_sig_formats {SIG_FMT_NONE, SIG_FMT_IMA, SIG_FMT_PGP, SIG_FMT_PKCS7};

static int ima_check_parser(u8 *data, u32 data_len,
			    u8 **digest, u16 *digest_algo)
{
	int parser_len = sizeof(PARSER_STRING) - 1;
	int digest_len, expected_data_len;
	u8 *datap = data + data_len - parser_len;
	u16 version, algo;

	version = *(u16 *)data;
	if (ima_canonical_fmt)
		version = le16_to_cpu(version);

	if (version > REQ_PARSER_VERSION)
		return -EINVAL;

	algo = *(u16 *)(data + sizeof(u16));
	if (ima_canonical_fmt)
		algo = le16_to_cpu(algo);

	if (algo < 0 || algo >= HASH_ALGO__LAST)
		return -EINVAL;

	digest_len = hash_digest_size[algo];
	expected_data_len = sizeof(u16) * 2 + digest_len + parser_len;
	if (data_len != expected_data_len)
		return -EINVAL;

	if (memcmp(datap, PARSER_STRING, parser_len))
		return -EINVAL;

	*digest = data + 2 * sizeof(u16);
	*digest_algo = algo;
	return 0;
}

static int ima_check_signature(u16 data_algo, u8 *type_ext, u32 type_ext_len,
			       u8 *digest, u32 digest_len, u16 sig_fmt,
			       u8 *sig, u32 sig_len)
{
	struct {
		struct ima_digest_data hdr;
		char digest[IMA_MAX_DIGEST_SIZE];
	} hash;

	const unsigned int id = INTEGRITY_KEYRING_IMA;
	int ret;

	switch (sig_fmt) {
	case SIG_FMT_IMA:
		if (type_ext) {
			hash.hdr.algo = data_algo;

			ret = ima_calc_buffer_hash(type_ext, type_ext_len,
						   &hash.hdr);
			if (ret < 0)
				return ret;

			digest = hash.hdr.digest;
			digest_len = hash.hdr.length;
		}

		ret = integrity_digsig_verify(id, (const char *)sig, sig_len,
					      digest, digest_len);
		break;
#ifdef CONFIG_SYSTEM_DATA_VERIFICATION
	case SIG_FMT_PGP:
		ret = verify_pgp_signature(type_ext, type_ext_len, digest,
					   digest_len, sig, sig_len, NULL);
		if (ret < 0) {
			struct key *keyring = integrity_keyring_from_id(id);

			if (IS_ERR(keyring)) {
				ret = PTR_ERR(keyring);
				break;
			}

			ret = verify_pgp_signature(type_ext, type_ext_len,
				digest, digest_len, sig, sig_len, keyring);
		}
		break;
	case SIG_FMT_PKCS7:
		ret = verify_pkcs7_signature(type_ext, type_ext_len, sig,
			sig_len, NULL, VERIFYING_MODULE_SIGNATURE, NULL, NULL);
		if (ret < 0) {
			struct key *keyring = integrity_keyring_from_id(id);

			if (IS_ERR(keyring)) {
				ret = PTR_ERR(keyring);
				break;
			}

			ret = verify_pkcs7_signature(type_ext, type_ext_len,
				sig, sig_len, keyring,
				VERIFYING_MODULE_SIGNATURE, NULL, NULL);
		}
		break;
#endif /* CONFIG_SYSTEM_DATA_VERIFICATION */
	case SIG_FMT_NONE:
		ret = -ENOENT;
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int ima_digest_list_create_key(u8 *payload, u32 len)
{
	struct key *ima_keyring;
	key_ref_t key;

	ima_keyring = integrity_keyring_from_id(INTEGRITY_KEYRING_IMA);
	if (IS_ERR(ima_keyring)) {
		pr_err("Unable to find IMA keyring, ret: %ld\n",
		       PTR_ERR(ima_keyring));
		return PTR_ERR(ima_keyring);
	}

	key = key_create_or_update(make_key_ref(ima_keyring, 1),
				   "asymmetric", NULL, payload, len,
				   ((KEY_POS_ALL & ~KEY_POS_SETATTR) |
				    KEY_USR_VIEW | KEY_USR_READ),
				   KEY_ALLOC_NOT_IN_QUOTA);
	if (IS_ERR(key)) {
		pr_err("Unable to create a key from metadata, ret: %ld\n",
		       PTR_ERR(key));
		return PTR_ERR(key);
	}

	key_ref_put(key);
	return 0;
}

static void ima_digest_list_set_algo(char *pathname, u16 algo)
{
	struct integrity_iint_cache *iint;
	struct path path;
	int ret;

	if (!pathname)
		return;

	ret = kern_path(pathname, LOOKUP_FOLLOW, &path);
	if (ret < 0)
		return;

	if (path.dentry->d_inode->i_sb->s_magic == RAMFS_MAGIC) {
		iint = integrity_inode_get(path.dentry->d_inode);
		if (iint && !iint->ima_hash) {
			iint->ima_hash = kmalloc(sizeof(*iint->ima_hash),
						 GFP_NOFS);
			if (iint->ima_hash)
				iint->ima_hash->algo = algo;
		}

		goto out;
	}

	/* extended attribute is set by the parser */
	if (!ima_parser_metadata_load)
		goto out;

	ret = __vfs_setxattr_noperm(path.dentry, XATTR_NAME_IMA_ALGO,
				    &algo, sizeof(algo), 0);
	if (!ret)
		goto out;
out:
	path_put(&path);
}

enum hash_algo ima_digest_list_get_algo(struct file *file,
					struct integrity_iint_cache *iint)
{
	struct dentry *dentry = file_dentry(file);
	u16 xattr_algo;
	int ret;

	if (dentry->d_inode->i_sb->s_magic == RAMFS_MAGIC) {
		if (iint->ima_hash)
			return iint->ima_hash->algo;

		goto out;
	}

	ret = __vfs_getxattr(dentry, dentry->d_inode, XATTR_NAME_IMA_ALGO,
			     &xattr_algo, sizeof(xattr_algo));
	if (ret == sizeof(xattr_algo))
		return xattr_algo;
out:
	return ima_hash_algo;
}

ssize_t ima_parse_digest_list_metadata(loff_t size, void *buf)
{
	struct ima_field_data entry;

	struct ima_field_data entry_data[DATA__LAST] = {
		[DATA_ALGO] = {.len = sizeof(u16)},
		[DATA_TYPE] = {.len = sizeof(u16)},
		[DATA_DIGEST_ALGO] = {.len = sizeof(u16)},
		[DATA_SIG_FMT] = {.len = sizeof(u16)},
		[DATA_LENGTH] = {.len = sizeof(u32)},
	};

	DECLARE_BITMAP(data_mask, DATA__LAST);
	void *bufp = buf, *bufendp = buf + size;
	u16 data_algo, data_type, digest_algo, sig_fmt, version, parser_algo;
	u8 flags = DIGEST_FLAG_IMMUTABLE;
	u8 *digest;
	char *path;
	int ret;

	bitmap_zero(data_mask, DATA__LAST);
	bitmap_set(data_mask, DATA_ALGO, 1);
	bitmap_set(data_mask, DATA_TYPE, 1);
	bitmap_set(data_mask, DATA_DIGEST_ALGO, 1);
	bitmap_set(data_mask, DATA_SIG_FMT, 1);
	bitmap_set(data_mask, DATA_LENGTH, 1);

	ret = ima_parse_buf(bufp, bufendp, &bufp, 1, &entry, NULL, NULL,
			    ENFORCE_FIELDS, "metadata list entry");
	if (ret < 0)
		return ret;

	ret = ima_parse_buf(entry.data, entry.data + entry.len, NULL,
			    DATA__LAST, entry_data, NULL, data_mask,
			    ENFORCE_FIELDS | ENFORCE_BUFEND,
			    "metadata entry data");
	if (ret < 0)
		return ret;

	data_algo = *(u16 *)entry_data[DATA_ALGO].data;
	data_type = *(u16 *)entry_data[DATA_TYPE].data;
	digest_algo = *(u16 *)entry_data[DATA_DIGEST_ALGO].data;
	sig_fmt = *(u16 *)entry_data[DATA_SIG_FMT].data;
	digest = entry_data[DATA_DIGEST].data;
	path = (char *)entry_data[DATA_FILE_PATH].data;

	if (ima_canonical_fmt) {
		data_algo = le16_to_cpu(data_algo);
		data_type = le16_to_cpu(data_type);
		digest_algo = le16_to_cpu(digest_algo);
		sig_fmt = le16_to_cpu(sig_fmt);
	}

	switch (data_type) {
	case DATA_TYPE_HEADER:
		if (entry_data[DATA_TYPE_EXT].len != sizeof(u16))
			return -EINVAL;

		version = le16_to_cpu(*(u16 *)entry_data[DATA_TYPE_EXT].data);
		if (version > REQ_METADATA_VERSION)
			return -EINVAL;

		goto out;
	case DATA_TYPE_DIGEST_LIST:
		/* digest lists, except the compact, are parsed in user space */
		break;
	case DATA_TYPE_KEY:
		ret = ima_digest_list_create_key(entry_data[DATA_TYPE_EXT].data,
						 entry_data[DATA_TYPE_EXT].len);
		goto out;
	case DATA_TYPE_PARSER:
		ret = ima_check_parser(entry_data[DATA_TYPE_EXT].data,
				       entry_data[DATA_TYPE_EXT].len,
				       &digest, &parser_algo);
		if (ret < 0)
			return ret;

		if (parser_algo != data_algo) {
			pr_err("Parser digest algorithm mismatch\n");
			return -EINVAL;
		}

		digest_algo = parser_algo;
		break;
	default:
		pr_err("Invalid data type %d\n", data_type);
		return -EINVAL;
	}

	if (digest_algo != ima_hash_algo) {
		if (digest_algo < 0 || digest_algo >= HASH_ALGO__LAST) {
			pr_err("Unknown algorithm\n");
			return -EINVAL;
		}

		flags |= DIGEST_FLAG_DIGEST_ALGO;
		ima_digest_list_set_algo(path, digest_algo);
	}

	if (ima_policy_flag & IMA_APPRAISE) {
		ret = ima_check_signature(data_algo,
					  entry_data[DATA_TYPE_EXT].data,
					  entry_data[DATA_TYPE_EXT].len,
					  digest, entry_data[DATA_DIGEST].len,
					  sig_fmt, entry_data[DATA_SIG].data,
					  entry_data[DATA_SIG].len);
		if (ret < 0) {
			if (ret == -ENOENT)
				goto out;

			pr_err("Failed signature verification of: %s (%d)\n",
			       path, ret);
			return ret;
		}
	}

	ret = ima_add_digest_data_entry(digest, digest_algo, flags, data_type);
	if (ret < 0 && ret != -EEXIST)
		return ret;
out:
	return bufp - buf;
}

/*******************************
 * Digest list metadata loader *
 *******************************/
static void ima_exec_parser(void)
{
	char *argv[5] = {NULL}, *envp[1] = {NULL};

	argv[0] = (char *)CONFIG_IMA_PARSER_BINARY_PATH;
	argv[1] = "-e";
	argv[2] = (char *)hash_algo_name[ima_hash_algo];
#ifndef CONFIG_INTEGRITY_TRUSTED_KEYRING
	argv[3] = "-c";
#endif
	call_usermodehelper(argv[0], argv, envp, UMH_WAIT_PROC);
}

void __init ima_load_digest_list_metadata(void)
{
	void *datap;
	loff_t size;
	int ret;

	ret = kernel_read_file_from_path(CONFIG_IMA_PARSER_METADATA_PATH,
					 &datap, &size, 0,
					 READING_DIGEST_LIST_METADATA);
	if (ret < 0) {
		if (ret != -ENOENT)
			pr_err("Unable to open file: %s (%d)",
			       CONFIG_IMA_PARSER_METADATA_PATH, ret);
		return;
	}

	ima_parser_metadata_load = 1;

	/* header */
	ret = ima_parse_digest_list_metadata(size, datap);
	if (ret > 0)
		/* parser metadata */
		ret = ima_parse_digest_list_metadata(size - ret, datap + ret);

	ima_parser_metadata_load =  0;
	vfree(datap);

	if (ret < 0) {
		pr_err("Unable to parse file: %s (%d)",
			CONFIG_IMA_PARSER_METADATA_PATH, ret);
		return;
	}

	ima_exec_parser();
}
