#ifndef AXOLOTL_H
#define AXOLOTL_H

#include "crypto_scalarmult.h"
#include <stdint.h>

#define axolotl_box_BYTES 128

#ifndef BagSize
#define BagSize 8
#endif // BagSize

#ifndef BagReuseDeleted
#define BagReuseDeleted 1
#endif // BagReuseDeleted

#ifndef AXOLOTL_DEBUG
#define AXOLOTL_DEBUG 0
#endif // AXOLOTL_DEBUG

typedef struct {
  uint8_t id;
  uint8_t mk[crypto_scalarmult_curve25519_BYTES];
} __attribute((packed)) BagEntry;

typedef struct {
  uint8_t sk[crypto_scalarmult_curve25519_BYTES];
  uint8_t pk[crypto_scalarmult_curve25519_BYTES];
} __attribute((packed)) Axolotl_KeyPair;

typedef struct {
  // 32-byte root key which gets updated by DH ratchet
  uint8_t rk[crypto_scalarmult_curve25519_BYTES];

  // 32-byte header keys (send and recv versions)
  uint8_t hks[crypto_scalarmult_curve25519_BYTES];
  uint8_t hkr[crypto_scalarmult_curve25519_BYTES];

  // 32-byte next header keys (")
  uint8_t nhks[crypto_scalarmult_curve25519_BYTES];
  uint8_t nhkr[crypto_scalarmult_curve25519_BYTES];

  // 32-byte chain keys (used for forward-secrecy updating)
  uint8_t cks[crypto_scalarmult_curve25519_BYTES];
  uint8_t ckr[crypto_scalarmult_curve25519_BYTES];

  // ECDH Identity keys
  Axolotl_KeyPair dhis;
  uint8_t dhir[crypto_scalarmult_curve25519_BYTES];

  // ECDH Ratchet keys
  Axolotl_KeyPair dhrs;
  uint8_t dhrr[crypto_scalarmult_curve25519_BYTES];

  // Message numbers (reset to 0 with each new ratchet)
  unsigned long long ns, nr;

  // Previous message numbers (# of msgs sent under prev ratchet)
  unsigned long long pns;

  // bobs 1st message?
  unsigned char bobs1stmsg;

  // A array[STAGING_SIZE] of stored message keys and their associated header
  // keys for "skipped" messages, i.e. messages that have not been
  // received despite the reception of more recent messages.
  BagEntry skipped_HK_MK[BagSize];

  Axolotl_KeyPair eph;
} __attribute((packed)) Axolotl_ctx;


typedef struct {
  uint8_t identitykey[crypto_scalarmult_curve25519_BYTES];
  uint8_t ephemeralkey[crypto_scalarmult_curve25519_BYTES];
  uint8_t DHRs[crypto_scalarmult_curve25519_BYTES];
} __attribute((packed)) Axolotl_InitMsg;

void axolotl_genid(Axolotl_KeyPair * keys);
void axolotl_setup(Axolotl_InitMsg *initmsg, Axolotl_ctx *ctx, const Axolotl_KeyPair *keypair);
int axolotl_accept(Axolotl_ctx* ctx, const Axolotl_InitMsg *init);
void axolotl_box(Axolotl_ctx *ctx, uint8_t *out, int *out_len, const uint8_t *in, const int in_len);
int axolotl_box_open(Axolotl_ctx *ctx, uint8_t *out, int *out_len, const uint8_t *in, const int in_len);

#if AXOLOTL_DEBUG
void print_ctx(Axolotl_ctx *ctx);
void print_key(const char* prefix, const uint8_t* key);
#endif // AXOLOTL_DEBUG

#endif // AXOLOTL_H
