/*
    This file is part of libsaxolotl.

    libsaxolotl is free software: you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public License
    as published by the Free Software Foundation, either version 3 of
    the License, or (at your option) any later version.

    libsaxolotl is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with libsaxolotl. If not, see <http://www.gnu.org/licenses/>.
*/
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>

#include "randombytes_salsa20_random.h"
#include "crypto_secretbox.h"
#include "crypto_generichash.h"
#include "crypto_scalarmult.h"

#include "axolotl.h"

#define PADDEDHCRYPTLEN (16+sizeof(long long)*2 + crypto_scalarmult_curve25519_BYTES+crypto_secretbox_MACBYTES)

static void bubble_sort(uint8_t ptr[BagSize][2],int s);
static BagEntry* bag_put(BagEntry bag[]);
static void bag_init(BagEntry bag[]);
static void bag_del(BagEntry *bag);
#if AXOLOTL_DEBUG
static void bag_dump(BagEntry bag[]);
#endif // AXOLOTL_DEBUG

void axolotl_genid(Axolotl_KeyPair * keys) {
  randombytes_buf(keys->sk,crypto_scalarmult_curve25519_BYTES);
  crypto_scalarmult_curve25519_base(keys->pk, keys->sk);
}

void axolotl_setup(Axolotl_InitMsg *initmsg, Axolotl_ctx *ctx, const Axolotl_KeyPair *keypair) {
  memset(ctx,0,sizeof(Axolotl_ctx));
  bag_init(ctx->skipped_HK_MK);

  // copy identity key into CTX DHIs
  memcpy(ctx->dhis.pk, keypair->pk, crypto_scalarmult_curve25519_BYTES);
  memcpy(ctx->dhis.sk, keypair->sk, crypto_scalarmult_curve25519_BYTES);

  // copy pk of identity key to initmsg
  memcpy(initmsg->identitykey, keypair->pk, crypto_scalarmult_curve25519_BYTES);

  // create ephemeral key and store it in ctx
  randombytes_buf(ctx->eph.sk,crypto_scalarmult_curve25519_BYTES);
  crypto_scalarmult_curve25519_base(ctx->eph.pk, ctx->eph.sk);
  // and publish in initmsg
  memcpy(initmsg->ephemeralkey, ctx->eph.pk, crypto_scalarmult_curve25519_BYTES);

  // also create DHRs
  randombytes_buf(ctx->dhrs.sk,crypto_scalarmult_curve25519_BYTES);
  crypto_scalarmult_curve25519_base(ctx->dhrs.pk, ctx->dhrs.sk);
  // and publish in initmsg
  memcpy(initmsg->DHRs, ctx->dhrs.pk, crypto_scalarmult_curve25519_BYTES);
}

static int isalice(const Axolotl_ctx *ctx) {
  return memcmp(ctx->dhis.pk, ctx->dhir, crypto_scalarmult_curve25519_BYTES);
}

static int tripledh(uint8_t *mk, const Axolotl_ctx *ctx, const Axolotl_InitMsg *init) {
  /*
  Triple DH performs cross DH between two peers having two keys each:

  - an identity key (Ai,Bi), and
  - an ephemeral key (Ae, Be).

  the cross DH is then performed on these pairs:
  (Ai,Be)+(Bi,Ae)+(Ae,Be) The order of the parameters to these
  operations depends on the order in which the peers are acting.
  */
  uint8_t sec[crypto_scalarmult_curve25519_BYTES * 3], *ptr = sec;

  if(isalice(ctx) <= 0) {
    // 3 DHs
    if(crypto_scalarmult_curve25519(ptr, ctx->dhis.sk, init->ephemeralkey)!=0) {
#if AXOLOTL_DEBUG
        printf("fail\n");
#endif
      return 1;
    }
    ptr+=crypto_scalarmult_curve25519_BYTES;

    if(crypto_scalarmult_curve25519(ptr, ctx->eph.sk, init->identitykey)!=0) {
#if AXOLOTL_DEBUG
      printf("fail\n");
#endif
      return 1;
    }
    ptr+=crypto_scalarmult_curve25519_BYTES;

    if(crypto_scalarmult_curve25519(ptr, ctx->eph.sk, init->ephemeralkey)!=0) {
#if AXOLOTL_DEBUG
      printf("fail\n");
#endif
      return 1;
    }
  } else {
    // 3 DHs
    if(crypto_scalarmult_curve25519(ptr, ctx->eph.sk, init->identitykey)!=0) {
#if AXOLOTL_DEBUG
      printf("fail\n");
#endif
      return 1;
    }
    ptr+=crypto_scalarmult_curve25519_BYTES;

    if(crypto_scalarmult_curve25519(ptr, ctx->dhis.sk, init->ephemeralkey)!=0) {
#if AXOLOTL_DEBUG
      printf("fail\n");
#endif
      return 1;
    }
    ptr+=crypto_scalarmult_curve25519_BYTES;

    if(crypto_scalarmult_curve25519(ptr, ctx->eph.sk, init->ephemeralkey)!=0) {
#if AXOLOTL_DEBUG
      printf("fail\n");
#endif
      return 1;
    }
  }

  // and hash for the result
  crypto_generichash(mk, crypto_scalarmult_curve25519_BYTES, // output
                     sec, sizeof(sec),                       // msg
                     NULL, 0);                               // no key
  memset(sec,0, sizeof(sec));
  return 0;
}

int axolotl_accept(Axolotl_ctx* ctx, const Axolotl_InitMsg *init) {
  /*
  as per https://github.com/trevp/axolotl/wiki/newversion (Nov 19, 2013 · 41 revisions)

  Key Agreement
  --------------
  - Parties exchange identity keys (A,B) and handshake keys (Ah,Ai) and (Bh,Bi)
  - Parties assign themselves "Alice" or "Bob" roles by comparing public keys
  - Parties perform triple-DH with (A,B,Ah,Bh) and derive initial keys:
  Alice:
  KDF from triple-DH: RK, HKs, HKr, NHKs, NHKr, CKs, CKr
  DHIs, DHIr = A, B
  DHRs, DHRr = <none>, Bi
  Ns, Nr = 0, 0
  PNs = 0
  bobs_first_message = False
  Bob:
  KDF from triple-DH: RK, HKr, HKs, NHKr, NHKs, CKr, CKs
  DHIs, DHIr = B, A
  DHRs, DHRr = Bi, <none>
  Ns, Nr = 0, 0
  PNs = 0
  bobs_first_message = True
  */

  uint8_t mk[crypto_scalarmult_curve25519_BYTES];
  // DHIr = peer identity key
  memcpy(ctx->dhir, init->identitykey, crypto_scalarmult_curve25519_BYTES);
  // perform triple DH to derive master key
  if(tripledh(mk, ctx, init)!=0) return 1;
  // mk is the shared secret derived of the triple dh which seeds all keys:

  // derive root key
  crypto_generichash(ctx->rk, crypto_scalarmult_curve25519_BYTES,
                     mk, sizeof(mk),
                     (uint8_t*) "RK", 2);
  if(isalice(ctx) <= 0) {
    // DHRr = peer DHRs
    memcpy(ctx->dhrr, init->DHRs, crypto_scalarmult_curve25519_BYTES);
    // clear DHRs
    memset(ctx->dhrs.sk,0,crypto_scalarmult_curve25519_BYTES);
    memset(ctx->dhrs.pk,0,crypto_scalarmult_curve25519_BYTES);

    // derive HKs
    crypto_generichash(ctx->hks, crypto_scalarmult_curve25519_BYTES,
                       mk, sizeof(mk),
                       (uint8_t*) "HKs", 3);
    // derive HKr
    crypto_generichash(ctx->hkr, crypto_scalarmult_curve25519_BYTES,
                       mk, sizeof(mk),
                       (uint8_t*) "HKr", 3);

    // derive NHKs
    crypto_generichash(ctx->nhks, crypto_scalarmult_curve25519_BYTES,
                       mk, sizeof(mk),
                       (uint8_t*) "NHKs", 4);
    // derive NHKr
    crypto_generichash(ctx->nhkr, crypto_scalarmult_curve25519_BYTES,
                       mk, sizeof(mk),
                       (uint8_t*) "NHKr", 4);
    // derive CKs
    crypto_generichash(ctx->cks, crypto_scalarmult_curve25519_BYTES,
                       mk, sizeof(mk),
                       (uint8_t*) "CKs", 3);
    // derive CKr
    crypto_generichash(ctx->ckr, crypto_scalarmult_curve25519_BYTES,
                       mk, sizeof(mk),
                       (uint8_t*) "CKr", 3);
    ctx->bobs1stmsg = 0;
  } else {
    // derive HKs
    crypto_generichash(ctx->hks, crypto_scalarmult_curve25519_BYTES,
                       mk, sizeof(mk),
                       (uint8_t*) "HKr", 3);
    // derive HKr
    crypto_generichash(ctx->hkr, crypto_scalarmult_curve25519_BYTES,
                       mk, sizeof(mk),
                       (uint8_t*) "HKs", 3);

    // derive NHKs
    crypto_generichash(ctx->nhks, crypto_scalarmult_curve25519_BYTES,
                       mk, sizeof(mk),
                       (uint8_t*) "NHKr", 4);
    // derive NHKr
    crypto_generichash(ctx->nhkr, crypto_scalarmult_curve25519_BYTES,
                       mk, sizeof(mk),
                       (uint8_t*) "NHKs", 4);
    // derive CKs
    crypto_generichash(ctx->cks, crypto_scalarmult_curve25519_BYTES,
                       mk, sizeof(mk),
                       (uint8_t*) "CKr", 3);
    // derive CKr
    crypto_generichash(ctx->ckr, crypto_scalarmult_curve25519_BYTES,
                       mk, sizeof(mk),
                       (uint8_t*) "CKs", 3);
    ctx->bobs1stmsg = 1;
  }
  ctx->ns = 0;
  ctx->nr = 0;
  ctx->pns = 0;
  memset(mk, 0, sizeof(mk));
  return 0;
}

void axolotl_box(Axolotl_ctx *ctx, uint8_t *out, int *out_len, const uint8_t *in, const int in_len) {
/*
   as per https://github.com/trevp/axolotl/wiki/newversion (Nov 19, 2013 · 41 revisions)

   Sending messages
   -----------------
   Local variables:
     MK  : message key

   if DHRs == <none>:
     DHRs = generateECDH()
   MK = HASH(CKs || "0")
   msg = Enc(HKs, Ns || PNs || DHRs) || Enc(MK, plaintext)
   Ns = Ns + 1
   CKs = HASH(CKs || "1")
   return msg
*/
  uint8_t mk[crypto_secretbox_KEYBYTES];
  uint8_t *hnonce=out;
  uint8_t *mnonce=out+crypto_secretbox_NONCEBYTES;
  int i,j;
  // check if we have a DHRs
  for(i=0,j=0;i<crypto_secretbox_KEYBYTES;i++) if(ctx->dhrs.sk[i]==0) j++;
  if(j==crypto_secretbox_KEYBYTES) { // if not, generate one, and reset counter
#if AXOLOTL_DEBUG
    printf("new dhrs\n");
#endif
    randombytes_buf(ctx->dhrs.sk,crypto_scalarmult_curve25519_BYTES);
    crypto_scalarmult_curve25519_base(ctx->dhrs.pk, ctx->dhrs.sk);
    ctx->pns=ctx->ns;
    ctx->ns=0;
  }
  // derive message key
#if AXOLOTL_DEBUG
  print_key("cks", ctx->cks);
#endif
  crypto_generichash(mk, crypto_secretbox_KEYBYTES,       // output
                     ctx->cks, crypto_secretbox_KEYBYTES, // msg
                     (uint8_t*) "MK", 2);                 // "MK")
#if AXOLOTL_DEBUG
  print_key("mk", mk);
#endif
  // hnonce
  randombytes_buf(hnonce,crypto_secretbox_NONCEBYTES);
  // mnonce
  randombytes_buf(mnonce,crypto_secretbox_NONCEBYTES);

  // calculate Enc(HKs, Ns || PNs || DHRs)
  uint8_t header[PADDEDHCRYPTLEN]; // includes nacl padding
  memset(header,0,sizeof(header));
  // concat ns || pns || dhrs
  memcpy(header+32,&ctx->ns, sizeof(long long));
  memcpy(header+32+sizeof(long long),&ctx->pns, sizeof(long long));
  memcpy(header+32+sizeof(long long)*2, ctx->dhrs.pk, crypto_scalarmult_curve25519_BYTES);

#if AXOLOTL_DEBUG
  print_key("hks", ctx->hks);
  print_key("hnonce", hnonce);
  printf("header: ");
  {int j; for(j=0;j<sizeof(header);j++) printf("%02x:", header[j]);}
  printf("\n");
#endif

  uint8_t header_enc[PADDEDHCRYPTLEN]; // also nacl padded
  // encrypt them
  crypto_secretbox(header_enc, header, sizeof(header), hnonce, ctx->hks);

  //{ int j; for(j=0;j<sizeof(header_enc);j++) printf("%02x:", header_enc[j]); printf("\n"); }

  // unpad to output buf
  memcpy(mnonce+crypto_secretbox_NONCEBYTES, header_enc+16, sizeof(header_enc)-16);

  //{ int j; for(j=0;j<crypto_secretbox_NONCEBYTES*2+sizeof(header_enc)-16;j++) printf("%02x:", out[j]); printf("\n"); }

  // pad the message // todo handle big messages using outbuf/bufs
  uint8_t padded[32+in_len];
  memset(padded,0,32);
  uint8_t paddedout[16+in_len+crypto_secretbox_MACBYTES];
  memcpy(padded+32, in, in_len);
#if AXOLOTL_DEBUG
  print_key("mnonce", mnonce);
#endif
  crypto_secretbox(paddedout, padded, sizeof(padded), mnonce, mk);
#if AXOLOTL_DEBUG
    printf("encrypt ");
    { int j; for(j=0;j<sizeof(paddedout);j++) printf("%02x:", paddedout[j]); }
    printf("\n");
#endif
  memcpy(mnonce+crypto_secretbox_NONCEBYTES+sizeof(header_enc)-16,paddedout+16, sizeof(paddedout)-16);
  memset(mk,0,sizeof(mk));
  *out_len = crypto_secretbox_NONCEBYTES*2+sizeof(header_enc)-16+sizeof(paddedout)-16;
  ctx->ns++;
  crypto_generichash(ctx->cks, crypto_scalarmult_curve25519_BYTES, // output
                     ctx->cks, crypto_scalarmult_curve25519_BYTES, // msg
                     (uint8_t*) "CK", 2);                          // no key
#if AXOLOTL_DEBUG
    print_key("cks1", ctx->cks);
    printf("\n");
#endif
}

static int try_skipped(Axolotl_ctx *ctx, uint8_t *out, int *outlen,
                const uint8_t *hcrypt, const uint8_t *hnonce,
                const uint8_t *mcrypt, const int mcrypt_len, const uint8_t *mnonce) {
  /*
    def try_skipped_keys(self, hcrypt, hnonce, mcrypt, mnonce):
        for mk, hkr in self.skipped_HK_MK.items():
            try: nacl.crypto_secretbox_open(hcrypt, hnonce, hkr)
            except: continue
            try: msg = nacl.crypto_secretbox_open(mcrypt, mnonce, mk)
            except: continue
            del self.skipped_HK_MK[mk]
            return msg
   */
  uint8_t paddedout[mcrypt_len];
  int i;
  for(i=0;i<BagSize;i++) {
    if(ctx->skipped_HK_MK[i].id==0xff || ctx->skipped_HK_MK[i].id==0) continue;
    if(crypto_secretbox_open(paddedout, mcrypt, mcrypt_len, mnonce, ctx->skipped_HK_MK[i].mk)!=0) continue;
    memcpy(out, paddedout+32, sizeof(paddedout) - 32);
    *outlen = sizeof(paddedout)-32;
    bag_del(&(ctx->skipped_HK_MK[i]));
    return 1;
  }
  return 0;
}

static void stage_skipped_keys(uint8_t* ckp, uint8_t* mk,  // output
                               const long long nr, const long long np, uint8_t *ck, // input
                               BagEntry stagedkeys[BagSize]) {
  /*
    stage_skipped_header_and_message_keys() : Given a current header
    key, a current message number, a future message number, and a
    chain key, calculates and stores all skipped-over message keys (if
    any) in a staging area where they can later be committed, along
    with their associated header key.

    Returns the chain key and message key corresponding to the future
    message number.
  */
  long long i;
  uint8_t _ckp[crypto_secretbox_KEYBYTES];
  memcpy(_ckp, ck, crypto_secretbox_KEYBYTES);
#if AXOLOTL_DEBUG
    if(np < nr) {
      printf("smaller, %lld < %lld\n", np, nr);
    } else if(np > nr) {
      printf("bigger, %lld < %lld\n", np, nr);
    }
#endif
  BagEntry *slot;
  for(i=0;i<np - nr;i++) {
    slot = bag_put(stagedkeys);
    crypto_generichash(slot->mk, crypto_secretbox_KEYBYTES, // mk=
                         _ckp, crypto_secretbox_KEYBYTES,  // h(ck,
                         (uint8_t*) "MK", 2);              // "MK")
    crypto_generichash(_ckp, crypto_secretbox_KEYBYTES,   // mk=
                       _ckp, crypto_secretbox_KEYBYTES,   // h(ck,
                       (uint8_t*) "CK", 2);               // "MK")
  }
  if(mk!=NULL) {
#if AXOLOTL_DEBUG
    print_key("ck", _ckp);
#endif
    crypto_generichash(mk, crypto_secretbox_KEYBYTES,     // mk=
                       _ckp, crypto_secretbox_KEYBYTES,   // h(ck,
                       (uint8_t*) "MK", 2);               // "MK")
  }
  if(ckp!=NULL) {
    crypto_generichash(ckp, crypto_secretbox_KEYBYTES,    // ck=
                       _ckp, crypto_secretbox_KEYBYTES,   // h(ck,
                       (uint8_t*) "CK", 2);               // "MK")
  }
}

int axolotl_box_open(Axolotl_ctx *ctx, uint8_t *out, int *out_len, const uint8_t *in, const int in_len) {
  /*
  as per https://github.com/trevp/axolotl/wiki/newversion (Nov 19, 2013 · 41 revisions)

  Receiving messages
  -------------------
  Local variables:
    MK  : message key
    Np  : Purported message number
    PNp : Purported previous message number
    CKp : Purported new chain key
    DHp : Purported new DHr
    RKp : Purported new root key
    NHKp, HKp : Purported new header keys

  if (plaintext = try_skipped_header_and_message_keys()):
    return plaintext

  if Dec(HKr, header):
    Np = read()
    CKp, MK = stage_skipped_header_and_message_keys(HKr, Nr, Np, CKr)
    if not Dec(MK, ciphertext):
      raise undecryptable
    if bobs_first_message:
      DHRr = read()
      RK = HASH(RK || ECDH(DHRs, DHRr))
      HKs = NHKs
      NHKs, CKs = KDF(RK)
      erase(DHRs)
      bobs_first_message = False
  else:
    if not Dec(NHKr, header):
      raise undecryptable()
    Np, PNp, DHRp = read()
    stage_skipped_header_and_message_keys(HKr, Nr, PNp, CKr)
    RKp = HASH(RK || ECDH(DHRs, DHRr))
    HKp = NHKr
    NHKp, CKp = KDF(RKp)
    CKp, MK = stage_skipped_header_and_message_keys(HKp, 0, Np, CKp)
    if not Dec(MK, ciphertext):
      raise undecryptable()
    RK = RKp
    HKr = HKp
    NHKr = NHKp
    DHRr = DHRp
    RK = HASH(RK || ECDH(DHRs, DHRr))
    HKs = NHKs
    NHKs, CKs = KDF(RK)
    erase(DHRs)
  commit_skipped_header_and_message_keys()
  Nr = Np + 1
  CKr = CKp
  return read()
  */

  const uint8_t *hnonce=in;
  const uint8_t *mnonce=in+crypto_secretbox_NONCEBYTES;
  const uint8_t *hcrypt=mnonce+crypto_secretbox_NONCEBYTES;
  const uint8_t *mcrypt=hcrypt+crypto_secretbox_MACBYTES + sizeof(long long)*2 + crypto_scalarmult_curve25519_BYTES;
  uint8_t paddedhcrypt[PADDEDHCRYPTLEN];
  uint8_t headers[PADDEDHCRYPTLEN];
  uint8_t tmp[crypto_secretbox_KEYBYTES];
  BagEntry stagedkeys[BagSize];
  bag_init(stagedkeys);

  unsigned long long np;
  uint8_t paddedmcrypt[16+in_len - (mcrypt-in)];
  uint8_t paddedout[sizeof(paddedmcrypt)];
  memset((uint8_t*) stagedkeys, 0, sizeof(stagedkeys));
  memset(paddedmcrypt,0,16);
  memcpy(paddedmcrypt+16,mcrypt,sizeof(paddedmcrypt)-16);

  memset(paddedhcrypt,0,16);
  memcpy(paddedhcrypt+16, hcrypt, sizeof(paddedhcrypt)-16);

  if(try_skipped(ctx, out, out_len, paddedhcrypt, hnonce, paddedmcrypt, sizeof(paddedmcrypt), mnonce)==1) {
    return 0;
  }

  uint8_t ckp[crypto_secretbox_KEYBYTES], mk[crypto_secretbox_KEYBYTES];
#if AXOLOTL_DEBUG
    print_key("hkr", ctx->hkr);
    print_key("hnonce", hnonce);
    printf("hcrypt");
    { int j; for(j=0;j<sizeof(paddedhcrypt);j++) printf("%02x:", paddedhcrypt[j]); }
    printf("\n");
#endif
  if(crypto_secretbox_open(headers, paddedhcrypt, sizeof(paddedhcrypt), hnonce, ctx->hkr)==0) {
    memcpy((uint8_t*) &np, headers+32, sizeof(long long));
    // CKp, MK = self.stage_skipped_keys(self.HKr, self.Nr, Np, self.CKr)
    //void stage_skipped_keys(uint8_t* ckp, uint8_t* mk, const uint8_t *hk, const long long nr, const long long np, const uint8_t *ck) {
    stage_skipped_keys(ckp, mk, ctx->nr, np, ctx->ckr, stagedkeys);
#if AXOLOTL_DEBUG
      print_key("mk", mk);
      print_key("mnonce", mnonce);
      printf("decrypt ");
      { int j; for(j=0;j<sizeof(paddedmcrypt);j++) printf("%02x:", paddedmcrypt[j]); }
      printf("\n");
#endif
    if(crypto_secretbox_open(paddedout, paddedmcrypt, sizeof(paddedmcrypt), mnonce, mk)!=0) {
      // todo fail!!!!
#if AXOLOTL_DEBUG
      printf("mcrypt err\n");
#endif
      return 1;
    }
    memcpy(out, paddedout+32, sizeof(paddedout) - 32);
    *out_len = sizeof(paddedout)-32;
    if(ctx->bobs1stmsg!=0) {
#if AXOLOTL_DEBUG
      printf("bobs1st\n");
#endif
      memcpy(ctx->dhrr, headers+32+2*sizeof(long long), crypto_secretbox_KEYBYTES);
#if AXOLOTL_DEBUG
      print_key("dhrr", ctx->dhrr);
#endif
      if(crypto_scalarmult_curve25519(tmp, ctx->dhrs.sk, ctx->dhrr)!=0) {
#if AXOLOTL_DEBUG
        printf("scalarmult err\n");
#endif
        return 1;
      }
      crypto_generichash(ctx->rk, crypto_secretbox_KEYBYTES, // output
                         ctx->rk, crypto_secretbox_KEYBYTES, // msg
                         tmp, crypto_secretbox_KEYBYTES);    // no key
      memcpy(ctx->hks, ctx->nhks, crypto_secretbox_KEYBYTES);
      if(isalice(ctx) <= 0) {
        crypto_generichash(ctx->nhks, crypto_secretbox_KEYBYTES, // output
                           ctx->rk, crypto_secretbox_KEYBYTES,   // msg
                           (uint8_t*) "NHKs", 4);                // no key
        crypto_generichash(ctx->cks, crypto_secretbox_KEYBYTES,  // output
                           ctx->rk, crypto_secretbox_KEYBYTES,   // msg
                           (uint8_t*) "CKs", 3);                 // no key
      } else {
        crypto_generichash(ctx->nhks, crypto_secretbox_KEYBYTES, // output
                           ctx->rk, crypto_secretbox_KEYBYTES,   // msg
                           (uint8_t*) "NHKr", 4);                // no key
        crypto_generichash(ctx->cks, crypto_secretbox_KEYBYTES,  // output
                           ctx->rk, crypto_secretbox_KEYBYTES,   // msg
                           (uint8_t*) "CKr", 3);                 // no key
      }
      memset(ctx->dhrs.sk, 0, crypto_secretbox_KEYBYTES);
      ctx->bobs1stmsg=0;
    }
  } else {
    if(crypto_secretbox_open(headers, paddedhcrypt, sizeof(paddedhcrypt), hnonce, ctx->nhkr)!=0) {
      // todo fail!!!!
#if AXOLOTL_DEBUG
      printf("hcrypt err\n");
#endif
      return 1;
    }
    unsigned long long pnp;
    memcpy((uint8_t*) &np, headers+32, sizeof(long long));
    memcpy((uint8_t*) &pnp, headers+32+sizeof(long long), sizeof(long long));
    uint8_t dhrp[crypto_secretbox_KEYBYTES];
    memcpy(dhrp, headers+32+sizeof(long long)*2, crypto_secretbox_KEYBYTES);
    // self.stage_skipped_keys(self.HKr, self.Nr, PNp, self.CKr)
    //void stage_skipped_keys(uint8_t* ckp, uint8_t* mk, const uint8_t *hk, const long long nr, const long long np, const uint8_t *ck) {
    stage_skipped_keys(NULL, NULL, ctx->nr, pnp, ctx->ckr, stagedkeys);
    uint8_t rkp[crypto_secretbox_KEYBYTES];
    if(crypto_scalarmult_curve25519(tmp, ctx->dhrs.sk, ctx->dhrr)!=0) {
#if AXOLOTL_DEBUG
      printf("scalarmult err\n");
#endif
      return 1;
    }
    crypto_generichash(rkp, crypto_secretbox_KEYBYTES,           // output
                       ctx->rk, crypto_secretbox_KEYBYTES,       // msg
                       tmp, crypto_scalarmult_curve25519_BYTES); // no key
    uint8_t hkp[crypto_secretbox_KEYBYTES];
    memcpy(hkp, ctx->nhkr, crypto_secretbox_KEYBYTES);
    uint8_t nhkp[crypto_secretbox_KEYBYTES];
    if(isalice(ctx) <= 0) {
      crypto_generichash(nhkp, crypto_secretbox_KEYBYTES, // output
                         rkp, crypto_secretbox_KEYBYTES,  // msg
                         (uint8_t*) "NHKr", 4);           // no key
      crypto_generichash(ckp, crypto_secretbox_KEYBYTES,  // output
                         rkp, crypto_secretbox_KEYBYTES,  // msg
                         (uint8_t*) "CKr", 3);            // no key
    } else {
      crypto_generichash(nhkp, crypto_secretbox_KEYBYTES, // output
                         rkp, crypto_secretbox_KEYBYTES,  // msg
                         (uint8_t*) "NHKs", 4);           // no key
      crypto_generichash(ckp, crypto_secretbox_KEYBYTES,  // output
                         rkp, crypto_secretbox_KEYBYTES,  // msg
                         (uint8_t*) "CKs", 3);            // no key
    }
    // CKp, MK = self.stage_skipped_keys(HKp, 0, Np, CKp)
    //void stage_skipped_keys(uint8_t* ckp, uint8_t* mk, const uint8_t *hk, const long long nr, const long long np, const uint8_t *ck) {
    stage_skipped_keys(ckp, mk, 0LL, np, ckp, stagedkeys);

#if AXOLOTL_DEBUG
      print_key("mk", mk);
      print_key("mnonce", mnonce);
      printf("decrypt ");
      { int j; for(j=0;j<sizeof(paddedmcrypt);j++) printf("%02x:", paddedmcrypt[j]); }
      printf("\n");
#endif
    if(crypto_secretbox_open(paddedout, paddedmcrypt, sizeof(paddedmcrypt), mnonce, mk)!=0) {
      // todo fail!!!!
#if AXOLOTL_DEBUG
      printf("mcrypt err\n");
#endif
      return 1;
    }
    memcpy(out, paddedout+32, sizeof(paddedout) - 32);
    *out_len = sizeof(paddedout)-32;
    memcpy(ctx->rk, rkp, crypto_secretbox_KEYBYTES);
    memcpy(ctx->hkr, hkp, crypto_secretbox_KEYBYTES);
    memcpy(ctx->nhkr, nhkp, crypto_secretbox_KEYBYTES);
    memcpy(ctx->dhrr, dhrp, crypto_secretbox_KEYBYTES);

    if(crypto_scalarmult_curve25519(tmp, ctx->dhrs.sk, ctx->dhrr)!=0) {
#if AXOLOTL_DEBUG
      printf("scalarmult err\n");
#endif
      return 1;
    };
    crypto_generichash(ctx->rk, crypto_secretbox_KEYBYTES,       // RK =
                       ctx->rk, crypto_secretbox_KEYBYTES,       // h(rk,
                       tmp, crypto_scalarmult_curve25519_BYTES); // tmp)
    memcpy(ctx->hks, ctx->nhks, crypto_secretbox_KEYBYTES);
    if(isalice(ctx) <= 0) {
      crypto_generichash(ctx->nhks, crypto_secretbox_KEYBYTES, // output
                         ctx->rk, crypto_secretbox_KEYBYTES,   // msg
                         (uint8_t*) "NHKs", 4);                // no key
      crypto_generichash(ctx->cks, crypto_secretbox_KEYBYTES,  // output
                         ctx->rk, crypto_secretbox_KEYBYTES,   // msg
                         (uint8_t*) "CKs", 3);                 // no key
    } else {
      crypto_generichash(ctx->nhks, crypto_secretbox_KEYBYTES, // output
                         ctx->rk, crypto_secretbox_KEYBYTES,   // msg
                         (uint8_t*) "NHKr", 4);                // no key
      crypto_generichash(ctx->cks, crypto_secretbox_KEYBYTES,  // output
                         ctx->rk, crypto_secretbox_KEYBYTES,   // msg
                         (uint8_t*) "CKr", 3);                 // no key
    }
    memset(ctx->dhrs.sk, 0, crypto_secretbox_KEYBYTES);
  }
  /*
  # commit_skipped_header_and_message_keys() : Commits any skipped-over message keys from the
  # staging area to persistent storage (along with their associated header keys).
  self.skipped_HK_MK.update(self.staged_HK_MK)
  self.staged_HK_MK = {}
  */
  int i;
  BagEntry *curentry;
  for(i=0;i<BagSize;i++) {
    if(stagedkeys[i].id==0xff || stagedkeys[i].id==0) continue;
    curentry = bag_put(ctx->skipped_HK_MK);
    memcpy(curentry->mk, &(stagedkeys[i].mk), crypto_secretbox_KEYBYTES);
    bag_del(&(stagedkeys[i]));
  }

  ctx->nr = np +1;
  memcpy(ctx->ckr, ckp, crypto_secretbox_KEYBYTES);
#if AXOLOTL_DEBUG
    print_key("ckr1", ctx->ckr);
    printf("\n");
#endif

  return 0;
}

#if AXOLOTL_DEBUG
void print_key(const char* prefix, const uint8_t* key) {
  uint32_t* ptr=(uint32_t*) key,i;
  printf("%s\t", prefix);
  for(i=0;i<7;i++)
    printf("%08x:",ptr[i]);
  printf("%08x\n",ptr[7]);
}

void print_ctx(Axolotl_ctx *ctx) {
  print_key("rk", ctx->rk);
  print_key("hks", ctx->hks);
  print_key("hkr", ctx->hkr);
  print_key("nhks", ctx->nhks);
  print_key("nhkr", ctx->nhkr);
  print_key("cks", ctx->cks);
  print_key("ckr", ctx->ckr);
  print_key("dhis.sk", ctx->dhis.sk);
  print_key("dhis.pk", ctx->dhis.pk);
  print_key("dhir", ctx->dhir);
  print_key("dhrs.sk", ctx->dhrs.sk);
  print_key("dhrs.pk", ctx->dhrs.pk);
  print_key("dhrr", ctx->dhrr);
  print_key("eph.sk", ctx->eph.sk);
  print_key("eph.pk", ctx->eph.pk);
  bag_dump(ctx->skipped_HK_MK);
  printf("ns: %lld nr: %lld pns: %lld bobs1st: %d\n",
         ctx->ns,
         ctx->nr,
         ctx->pns,
         ctx->bobs1stmsg);
}
#endif // AXOLOTL_DEBUG

static void bubble_sort(uint8_t ptr[BagSize][2],int s) {
  int i,j;
  uint8_t temp;
  for(i=1;i<s;i++) {
    for(j=0;j<s-i;j++) {
      //if(*(ptr+j)>*(ptr+j+1)) {
      if(ptr[j][0]>(ptr[j+1][0])) {
      //if(memcmp((char*) ptr[j], (char*) ptr[j+1],32)==1) {
        temp=ptr[j][0];
        ptr[j][0]=ptr[j+1][0];
        ptr[j+1][0]=temp;

        temp=ptr[j][1];
        ptr[j][1]=ptr[j+1][1];
        ptr[j+1][1]=temp;
      }
    }
  }
}

static BagEntry* bag_put(BagEntry bag[]) {
  int i;
  uint8_t minid=0xff,
    maxid=0,
    idx=0xff, minidx=0xff, delidx=0xff;

  // iterate through bag, looking for empty spaces, max and min ids.
  for(i=0;i<BagSize;i++) {
    if(bag[i].id<minid && bag[i].id!=0) {
      minid=bag[i].id;
      minidx=i;
    }
    if(bag[i].id>maxid && bag[i].id!=0xff) {
      maxid=bag[i].id;
    }
    if(bag[i].id==0xff && idx==0xff) {
      // found empty space
      idx=i;
    }
    if(bag[i].id==0 && delidx==0xff) {
      // found deleted space
      delidx=i;
    }
  }
  if(idx==0xff) {
    // did not find empty space
    if(delidx!=0xff && BagReuseDeleted) {
      // reuse deleted
      idx = delidx;
    } else {
      if(!BagReuseDeleted && minidx==0xff) {
        printf("bag erradicated, and no reuse\n");
        while(1);
      }
      // overwrite minidx
      idx=minidx;
    }
  }

  // try to assign id to new item.
  if(maxid<254) {
    bag[idx].id=maxid+1;
    return &bag[idx]; // easy, done
  }
  // we have to reassign all ids
  uint8_t idlist[BagSize][2], ptr;
  for(i=0, ptr=0;i<BagSize;i++) {
    if(i==idx) {
      idlist[ptr][0]=255;
      idlist[ptr++][1]=i;
    } else if(bag[i].id!=0xff && bag[i].id!=0) {
      idlist[ptr][0]=bag[i].id;
      idlist[ptr++][1]=i;
    }
  }
  bubble_sort(idlist,ptr);
  for(i=0;i<ptr;i++) {
    bag[idlist[i][1]].id=i+1;
  }
  return &bag[idx]; // done
}

static void bag_init(BagEntry bag[]) {
  // needed for operation on flash rom:
  memset(bag, 0xff, sizeof(BagEntry) * BagSize);
}

static void bag_del(BagEntry *bag) {
  bag->id=0;
  memset(bag->mk,0,crypto_scalarmult_curve25519_BYTES);
}

#if AXOLOTL_DEBUG
static void bag_dump(BagEntry bag[]) {
  int i;
  for(i=0;i<BagSize;i++) {
    if(bag[i].id==0) {
      printf("%2d deleted\n", i);
    } else if(bag[i].id==0xff) {
      printf("%2d empty\n", i);
    } else {
      printf("%2d %3d", i, bag[i].id);
      print_key("\tmk", bag[i].mk);
    }
  }
}
#endif
