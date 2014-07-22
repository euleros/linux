/* PGP library definitions (RFC 4880)
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifndef _LINUX_PGPLIB_H
#define _LINUX_PGPLIB_H

#if defined(CONFIG_PGP_LIBRARY) || defined(CONFIG_PGP_LIBRARY_MODULE)

#include <linux/pgp.h>

/*
 * PGP library packet parser
 */
struct pgp_parse_context {
	u64 types_of_interest;
	int (*process_packet)(struct pgp_parse_context *context,
			      enum pgp_packet_tag type,
			      u8 headerlen,
			      const u8 *data,
			      size_t datalen);
};

extern int pgp_parse_packets(const u8 *data, size_t datalen,
			     struct pgp_parse_context *ctx);

struct pgp_parse_pubkey {
	enum pgp_key_version version : 8;
	enum pgp_pubkey_algo pubkey_algo : 8;
	time_t		creation_time;
	time_t		expires_at;
};

extern int pgp_parse_public_key(const u8 **_data, size_t *_datalen,
				struct pgp_parse_pubkey *pk);

struct pgp_parse_sig_context {
	unsigned long types_of_interest[128 / BITS_PER_LONG];
	int (*process_packet)(struct pgp_parse_sig_context *context,
			      enum pgp_sig_subpkt_type type,
			      const u8 *data,
			      size_t datalen);
};

extern int pgp_parse_sig_packets(const u8 *data, size_t datalen,
				 struct pgp_parse_sig_context *ctx);

struct pgp_sig_parameters {
	enum pgp_signature_version version : 8;
	enum pgp_signature_type signature_type : 8;
	enum pgp_pubkey_algo pubkey_algo : 8;
	enum pgp_hash_algo hash_algo : 8;
	union {
		struct pgp_key_ID issuer;
		__be32 issuer32[2];
	};
};

extern int pgp_parse_sig_params(const u8 **_data, size_t *_datalen,
				struct pgp_sig_parameters *p);


#endif /* CONFIG_PGP_LIBRARY */

#endif /* _LINUX_PGPLIB_H */
