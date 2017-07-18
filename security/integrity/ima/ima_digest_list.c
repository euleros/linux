/*
 * Copyright (C) 2017 Huawei Technologies Co. Ltd.
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

enum digest_metadata_fields {DATA_ALGO, DATA_DIGEST, DATA_SIGNATURE,
			     DATA_FILE_PATH, DATA_REF_ID, DATA_TYPE,
			     DATA__LAST};

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

	ret = ima_add_digest_data_entry(entry_data[DATA_DIGEST].data);
	if (ret < 0) {
		if (ret == -EEXIST)
			ret = 0;

		goto out;
	}

	ret = ima_parse_digest_list_data(entry_data);
out:
	return ret < 0 ? ret : bufp - buf;
}
