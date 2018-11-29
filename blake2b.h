/**
 * Parts of this software are based on BLAKE2:
 * https://github.com/BLAKE2/BLAKE2
 *
 * BLAKE2 reference source code package - reference C implementations
 *
 * Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.  You may use this under
 * the terms of the CC0, the OpenSSL Licence, or the Apache Public License
 * 2.0, at your option.  The terms of these licenses can be found at:
 *
 * - CC0 1.0 Universal : http://creativecommons.org/publicdomain/zero/1.0
 * - OpenSSL license   : https://www.openssl.org/source/license.html
 * - Apache 2.0        : http://www.apache.org/licenses/LICENSE-2.0
 *
 * More information about the BLAKE2 hash function can be found at
 * https://blake2.net.
 */

#ifndef _BLAKE2B_H
#define _BLAKE2B_H

#include <stddef.h>
#include <stdint.h>

#if defined(_MSC_VER)
#define BLAKE2B_PACKED(x) __pragma(pack(push, 1)) x __pragma(pack(pop))
#else
#define BLAKE2B_PACKED(x) x __attribute__((packed))
#endif

#if defined(__cplusplus)
extern "C" {
#endif

enum blake2b_constant {
  BLAKE2B_BLOCKBYTES = 128,
  BLAKE2B_OUTBYTES = 64,
  BLAKE2B_KEYBYTES = 64,
  BLAKE2B_SALTBYTES = 16,
  BLAKE2B_PERSONALBYTES = 16
};

typedef struct blake2b_ctx__ {
  uint64_t h[8];
  uint64_t t[2];
  uint64_t f[2];
  uint8_t buf[BLAKE2B_BLOCKBYTES];
  size_t buflen;
  size_t outlen;
  uint8_t last_node;
} blake2b_ctx;

BLAKE2B_PACKED(struct blake2b_param__ {
  uint8_t digest_length;
  uint8_t key_length;
  uint8_t fanout;
  uint8_t depth;
  uint32_t leaf_length;
  uint32_t node_offset;
  uint32_t xof_length;
  uint8_t node_depth;
  uint8_t inner_length;
  uint8_t reserved[14];
  uint8_t salt[BLAKE2B_SALTBYTES];
  uint8_t personal[BLAKE2B_PERSONALBYTES];
});

typedef struct blake2b_param__ blake2b_param;

enum {
  BLAKE2B_DUMMY =
    1 / (sizeof(blake2b_param) == BLAKE2B_OUTBYTES)
};

int blake2b_init(blake2b_ctx *ctx, size_t outlen);

int blake2b_init_key(
  blake2b_ctx *ctx,
  size_t outlen,
  const void *key,
  size_t keylen
);

int
blake2b_init_param(
  blake2b_ctx *ctx,
  const blake2b_param *P
);

int
blake2b_update(blake2b_ctx *ctx, const void *in, size_t inlen);

int
blake2b_final(blake2b_ctx *ctx, void *out, size_t outlen);

int
blake2b(
  void *out,
  size_t outlen,
  const void *in,
  size_t inlen,
  const void *key,
  size_t keylen
);

#if defined(__cplusplus)
}
#endif

#endif
