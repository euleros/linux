/* PGP signature processing
 *
 * Copyright (C) 2014 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifndef _LINUX_PGP_SIG_H
#define _LINUX_PGP_SIG_H

struct key;

int pgp_verify_sig(struct key *keyring, const u8 *raw_data, size_t raw_datalen,
		   const u8 *digest, size_t digest_size, const u8 *sig_data,
		   size_t sig_datalen, bool *trusted);

#endif /* _LINUX_PGP_SIG_H */
