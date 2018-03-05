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

#include "ima.h"
#include "ima_template_lib.h"

#define REQ_METADATA_VERSION 1

/*******************************
 * Digest list metadata parser *
 *******************************/
enum digest_metadata_fields {DATA_ALGO, DATA_TYPE, DATA_TYPE_EXT,
			     DATA_DIGEST_ALGO, DATA_DIGEST,
			     DATA_SIG_FMT, DATA_SIG,
			     DATA_FILE_PATH, DATA_LENGTH, DATA__LAST};

enum data_sig_formats {SIG_FMT_NONE, SIG_FMT_IMA, SIG_FMT_PGP, SIG_FMT_PKCS7};

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
	u16 data_algo, data_type, digest_algo, sig_fmt, version;
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
