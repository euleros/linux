/*
 * Copyright (C) 2017 Huawei Technologies Duesseldorf GmbH
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

#include "ima.h"
#include "ima_template_lib.h"

#define RPMTAG_FILEDIGESTS 1035
#define RPMTAG_FILEMODES 1030

enum digest_metadata_fields {DATA_ALGO, DATA_DIGEST, DATA_SIGNATURE,
			     DATA_FILE_PATH, DATA_REF_ID, DATA_TYPE,
			     DATA__LAST};

enum digest_data_types {DATA_TYPE_COMPACT_LIST, DATA_TYPE_RPM};

enum compact_list_entry_ids {COMPACT_DIGEST, COMPACT_DIGEST_MUTABLE};

struct compact_list_hdr {
	u16 entry_id;
	u32 count;
	u32 datalen;
} __packed;

struct rpm_hdr {
	u32 magic;
	u32 reserved;
	u32 tags;
	u32 datasize;
} __packed;

struct rpm_entryinfo {
	int32_t tag;
	u32 type;
	int32_t offset;
	u32 count;
} __packed;

static int ima_parse_compact_list(loff_t size, void *buf)
{
	void *bufp = buf, *bufendp = buf + size;
	int digest_len = hash_digest_size[ima_hash_algo];
	struct compact_list_hdr *hdr;
	u8 is_mutable = 0;
	int ret, i;

	while (bufp < bufendp) {
		if (bufp + sizeof(*hdr) > bufendp) {
			pr_err("compact list, missing header\n");
			return -EINVAL;
		}

		hdr = bufp;

		if (ima_canonical_fmt) {
			hdr->entry_id = le16_to_cpu(hdr->entry_id);
			hdr->count = le32_to_cpu(hdr->count);
			hdr->datalen = le32_to_cpu(hdr->datalen);
		}

		switch (hdr->entry_id) {
		case COMPACT_DIGEST_MUTABLE:
			is_mutable = 1;
		case COMPACT_DIGEST:
			break;
		default:
			pr_err("compact list, invalid data type\n");
			return -EINVAL;
		}

		bufp += sizeof(*hdr);

		for (i = 0; i < hdr->count &&
		     bufp + digest_len <= bufendp; i++) {
			ret = ima_add_digest_data_entry(bufp, is_mutable);
			if (ret < 0 && ret != -EEXIST)
				return ret;

			bufp += digest_len;
		}

		if (i != hdr->count ||
		    bufp != (void *)hdr + sizeof(*hdr) + hdr->datalen) {
			pr_err("compact list, invalid data\n");
			return -EINVAL;
		}
	}

	return 0;
}

static int ima_parse_rpm(loff_t size, void *buf)
{
	void *bufp = buf, *bufendp = buf + size;
	struct rpm_hdr *hdr = bufp;
	u32 tags = be32_to_cpu(hdr->tags);
	struct rpm_entryinfo *entry;
	void *datap = bufp + sizeof(*hdr) + tags * sizeof(struct rpm_entryinfo);
	void *digests = NULL, *modes = NULL;
	u32 digests_count, modes_count;
	int digest_len = hash_digest_size[ima_hash_algo];
	u8 digest[digest_len];
	int ret, i;

	const unsigned char rpm_header_magic[8] = {
		0x8e, 0xad, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00
	};

	if (size < sizeof(*hdr)) {
		pr_err("Missing RPM header\n");
		return -EINVAL;
	}

	if (memcmp(bufp, rpm_header_magic, sizeof(rpm_header_magic))) {
		pr_err("Invalid RPM header\n");
		return -EINVAL;
	}

	bufp += sizeof(*hdr);

	for (i = 0; i < tags && (bufp + sizeof(*entry)) <= bufendp;
	     i++, bufp += sizeof(*entry)) {
		entry = bufp;

		if (be32_to_cpu(entry->tag) == RPMTAG_FILEDIGESTS) {
			digests = datap + be32_to_cpu(entry->offset);
			digests_count = be32_to_cpu(entry->count);
		}
		if (be32_to_cpu(entry->tag) == RPMTAG_FILEMODES) {
			modes = datap + be32_to_cpu(entry->offset);
			modes_count = be32_to_cpu(entry->count);
		}
		if (digests && modes)
			break;
	}

	if (digests == NULL)
		return 0;

	for (i = 0; i < digests_count && digests < bufendp; i++) {
		u8 is_mutable = 0;
		u16 mode;

		if (strlen(digests) == 0) {
			digests++;
			continue;
		}

		if (modes) {
			if (modes + (i + 1) * sizeof(mode) > bufendp) {
				pr_err("RPM header read at invalid offset\n");
				return -EINVAL;
			}

			mode = be16_to_cpu(*(u16 *)(modes + i * sizeof(mode)));
			if (!(mode & (S_IXUGO | S_ISUID | S_ISGID | S_ISVTX)) &&
			    (mode & S_IWUGO))
				is_mutable = 1;
		}

		if (digests + digest_len * 2 + 1 > bufendp) {
			pr_err("RPM header read at invalid offset\n");
			return -EINVAL;
		}

		ret = hex2bin(digest, digests, digest_len);
		if (ret < 0)
			return -EINVAL;

		ret = ima_add_digest_data_entry(digest, is_mutable);
		if (ret < 0 && ret != -EEXIST)
			return ret;

		digests += digest_len * 2 + 1;
	}

	return 0;
}

static int ima_parse_digest_list_data(struct ima_field_data *data)
{
	void *digest_list;
	loff_t digest_list_size;
	u16 data_algo = le16_to_cpu(*(u16 *)data[DATA_ALGO].data);
	u16 data_type = le16_to_cpu(*(u16 *)data[DATA_TYPE].data);
	int ret;

	if (data_algo != ima_hash_algo) {
		pr_err("Incompatible digest algorithm, expected %s\n",
		       hash_algo_name[ima_hash_algo]);
		return -EINVAL;
	}

	ret = kernel_read_file_from_path(data[DATA_FILE_PATH].data,
					 &digest_list, &digest_list_size,
					 0, READING_DIGEST_LIST);
	if (ret < 0) {
		pr_err("Unable to open file: %s (%d)",
		       data[DATA_FILE_PATH].data, ret);
		return ret;
	}

	switch (data_type) {
	case DATA_TYPE_COMPACT_LIST:
		ret = ima_parse_compact_list(digest_list_size, digest_list);
		break;
	case DATA_TYPE_RPM:
		ret = ima_parse_rpm(digest_list_size, digest_list);
		break;
	default:
		pr_err("Parser for data type %d not implemented\n", data_type);
		ret = -EINVAL;
	}

	if (ret < 0) {
		pr_err("Error parsing file: %s (%d)\n",
		       data[DATA_FILE_PATH].data, ret);
		return ret;
	}

	vfree(digest_list);
	return ret;
}

ssize_t ima_parse_digest_list_metadata(loff_t size, void *buf)
{
	struct ima_field_data entry;

	struct ima_field_data entry_data[DATA__LAST] = {
		[DATA_ALGO] = {.len = sizeof(u16)},
		[DATA_TYPE] = {.len = sizeof(u16)},
	};

	DECLARE_BITMAP(data_mask, DATA__LAST);
	void *bufp = buf, *bufendp = buf + size;
	int ret;

	bitmap_zero(data_mask, DATA__LAST);
	bitmap_set(data_mask, DATA_ALGO, 1);
	bitmap_set(data_mask, DATA_TYPE, 1);

	ret = ima_parse_buf(bufp, bufendp, &bufp, 1, &entry, NULL, NULL,
			    ENFORCE_FIELDS, "metadata list entry");
	if (ret < 0)
		return ret;

	ret = ima_parse_buf(entry.data, entry.data + entry.len, NULL,
			    DATA__LAST, entry_data, NULL, data_mask,
			    ENFORCE_FIELDS | ENFORCE_BUFEND,
			    "metadata entry data");
	if (ret < 0)
		goto out;

	if (ima_policy_flag & IMA_APPRAISE) {
		ret = integrity_digsig_verify(INTEGRITY_KEYRING_IMA,
				(const char *)entry_data[DATA_SIGNATURE].data,
				entry_data[DATA_SIGNATURE].len,
				entry_data[DATA_DIGEST].data,
				entry_data[DATA_DIGEST].len);
		if (ret < 0) {
			pr_err("Failed signature verification of: %s (%d)",
				entry_data[DATA_FILE_PATH].data, ret);
			goto out_parse_digest_list;
		}
	}

	ret = ima_add_digest_data_entry(entry_data[DATA_DIGEST].data, 0);
	if (ret < 0) {
		if (ret == -EEXIST)
			ret = 0;

		goto out;
	}

out_parse_digest_list:
	ret = ima_parse_digest_list_data(entry_data);
out:
	return ret < 0 ? ret : bufp - buf;
}

void __init ima_load_digest_list_metadata(void)
{
	void *datap;
	loff_t size;
	int ret;

	int unset_flags = ima_policy_flag & IMA_APPRAISE;

	if (!ima_policy_flag)
		return;

	ima_policy_flag &= ~unset_flags;
	ret = kernel_read_file_from_path(CONFIG_IMA_DIGEST_LIST_METADATA_PATH,
					 &datap, &size, 0,
					 READING_DIGEST_LIST_METADATA);
	if (ret < 0)
		pr_err("Unable to open file: %s (%d)",
		       CONFIG_IMA_DIGEST_LIST_METADATA_PATH, ret);

	ima_policy_flag |= unset_flags;

	while (size > 0) {
		ret = ima_parse_digest_list_metadata(size, datap);
		if (ret < 0) {
			pr_err("Unable to parse file: %s (%d)",
			       CONFIG_IMA_DIGEST_LIST_METADATA_PATH, ret);
			break;
		}
		datap += ret;
		size -= ret;
	}
}
