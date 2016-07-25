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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "randombytes_salsa20_random.h"
#include "crypto_secretbox.h"
#include "axolotl.h"

int main(void) {
  Axolotl_ctx alice_ctx, bob_ctx;
  Axolotl_KeyPair alice_id, bob_id;
  Axolotl_PreKey alice_prekey, bob_prekey;

  printf("sizeof axolotl ctx: %d\n", sizeof(Axolotl_ctx));
  printf("sizeof axolotl prekey: %d\n", sizeof(Axolotl_PreKey));
  // init long-term identity keys (could also be stored seperately for all new "connections"
  axolotl_genid(&alice_id);
  axolotl_genid(&bob_id);
  //randombytes_buf(alice_id.sk,crypto_scalarmult_curve25519_BYTES);
  //crypto_scalarmult_curve25519_base(alice_id.pk, alice_id.sk);

  //randombytes_buf(bob_id.sk,crypto_scalarmult_curve25519_BYTES);
  //crypto_scalarmult_curve25519_base(bob_id.pk, bob_id.sk);

  axolotl_prekey(&alice_prekey, &alice_ctx, &alice_id);
  axolotl_prekey(&bob_prekey, &bob_ctx, &bob_id);

  // theoretically alice and bob exchange intit msgs

  // both derive the ctx from the prekey msg
  axolotl_handshake(&alice_ctx, &bob_prekey);
  axolotl_handshake(&bob_ctx, &alice_prekey);

  printf("alice\n");
  print_ctx(&alice_ctx);
  printf("bob\n");
  print_ctx(&bob_ctx);
  printf("\n");

  if(memcmp(alice_ctx.rk, bob_ctx.rk, crypto_secretbox_KEYBYTES) != 0) {
    printf("fail\n");
    exit(1);
  };

  uint8_t out[4096], out2[4096];
  int outlen,outlen2;
  // assert(ctx2.recv(ctx1.send("howdy")) == 'howdy')
  axolotl_box(&alice_ctx, out, &outlen, (const uint8_t *) "howdy", 6);
  printf("cryptogram is %d bytes long\n", outlen);

  if(axolotl_box_open(&bob_ctx, out2, &outlen2, out, outlen)!=0) {
    // fail
    printf("fail :/\n");
    exit(1);
  }
  printf("%d %s\n", outlen2, out2);

  // test 2
  printf("alice\n");
  print_ctx(&alice_ctx);
  printf("bob\n");
  print_ctx(&bob_ctx);
  printf("\n2nd test\n");

  // assert(ctx2.recv(ctx1.send("2nd howdy")) == '2nd howdy')
  axolotl_box(&alice_ctx, out, &outlen, (const uint8_t *) "2nd howdy", 10);

  if(axolotl_box_open(&bob_ctx, out2, &outlen2, out, outlen)!=0) {
    // fail
    printf("fail :/\n");
    exit(1);
  }
  printf("%d %s\n", outlen2, out2);

  // test 3
  printf("alice\n");
  print_ctx(&alice_ctx);
  printf("bob\n");
  print_ctx(&bob_ctx);
  printf("\n3rd test\n");

  // assert(ctx1.recv(ctx2.send("re")) == 're')
  axolotl_box(&bob_ctx, out, &outlen, (const uint8_t *) "re", 3);

  if(axolotl_box_open(&alice_ctx, out2, &outlen2, out, outlen)!=0) {
    // fail
    printf("fail :/\n");
    exit(1);
  }
  printf("%d %s\n", outlen2, out2);

  // test 4
  printf("alice\n");
  print_ctx(&alice_ctx);
  printf("bob\n");
  print_ctx(&bob_ctx);
  printf("\n4th test\n");

  // assert(ctx2.recv(ctx1.send("rere")) == 'rere')
  axolotl_box(&alice_ctx, out, &outlen, (const uint8_t *) "rerere", 7);

  if(axolotl_box_open(&bob_ctx, out2, &outlen2, out, outlen)!=0) {
    // fail
    printf("fail :/\n");
    exit(1);
  }
  printf("%d %s\n", outlen2, out2);

  // test 5
  printf("alice\n");
  print_ctx(&alice_ctx);
  printf("bob\n");
  print_ctx(&bob_ctx);
  printf("\n5th test\n");

  // assert(ctx2.recv(ctx1.send("2nd rere")) == '2nd rere')
  axolotl_box(&alice_ctx, out, &outlen, (const uint8_t *) "2nd rerere", 11);

  if(axolotl_box_open(&bob_ctx, out2, &outlen2, out, outlen)!=0) {
    // fail
    printf("fail :/\n");
    exit(1);
  }
  printf("%d %s\n", outlen2, out2);

  // test 6
  printf("alice\n");
  print_ctx(&alice_ctx);
  printf("bob\n");
  print_ctx(&bob_ctx);
  printf("\n6th test\n");

  // assert(ctx1.recv(ctx2.send("rerere")) == 'rerere')
  axolotl_box(&bob_ctx, out, &outlen, (const uint8_t *) "rerere", 7);

  if(axolotl_box_open(&alice_ctx, out2, &outlen2, out, outlen)!=0) {
    // fail
    printf("fail :/\n");
    exit(1);
  }
  printf("%d %s\n", outlen2, out2);

  // test 7
  // some out of order sending
  /*
    msgx1 = ctx2.send("aaaaa")
    msg1 = ctx1.send("00000")
    msg2 = ctx1.send("11111")
    msgx2 = ctx2.send("bbbbb")
    msgx3 = ctx2.send("ccccc")
    msg3 = ctx1.send("22222")
    msg4 = ctx1.send("33333")
    msgx4 = ctx2.send("ddddd")
    assert(ctx2.recv(msg2) == '11111')
   */
  printf("\n7th test\n");
  uint8_t msg[5][axolotl_box_BYTES+6];
  uint8_t msgx[5][axolotl_box_BYTES+6];
  printf("alice sends 00000\n");
  axolotl_box(&alice_ctx,msg[0], &outlen, (const uint8_t*) "00000", 6);
  printf("alice sends 11111\n");
  axolotl_box(&alice_ctx,msg[1], &outlen, (const uint8_t*) "11111", 6);
  printf("alice sends 22222\n");
  axolotl_box(&alice_ctx,msg[2], &outlen, (const uint8_t*) "22222", 6);
  printf("alice sends 33333\n");
  axolotl_box(&alice_ctx,msg[3], &outlen, (const uint8_t*) "33333", 6);
  printf("bob sends aaaaa\n");
  axolotl_box(&bob_ctx,msgx[0], &outlen, (const uint8_t*) "aaaaa", 6);
  printf("bob sends bbbbb\n");
  axolotl_box(&bob_ctx,msgx[1], &outlen, (const uint8_t*) "bbbbb", 6);
  printf("bob sends ccccc\n");
  axolotl_box(&bob_ctx,msgx[2], &outlen, (const uint8_t*) "ccccc", 6);
  printf("bob sends ddddd\n");
  axolotl_box(&bob_ctx,msgx[3], &outlen, (const uint8_t*) "ddddd", 6);
  printf("alice\n");
  print_ctx(&alice_ctx);
  printf("bob\n");
  print_ctx(&bob_ctx);

  printf("bob receives 11111\n");
  if(axolotl_box_open(&bob_ctx, out2, &outlen2, msg[1], axolotl_box_BYTES+6)!=0) {
    // fail
    printf("fail :/\n");
    exit(1);
  }
  printf("%d %s\n", outlen2, out2);

  printf("alice\n");
  print_ctx(&alice_ctx);
  printf("bob\n");
  print_ctx(&bob_ctx);
  axolotl_box(&alice_ctx,msg[4], &outlen, (const uint8_t*) "44444", 6);

  printf("alice\n");
  print_ctx(&alice_ctx);
  printf("bob\n");
  print_ctx(&bob_ctx);
  printf("bob receives 44444\n");
  if(axolotl_box_open(&bob_ctx, out2, &outlen2, msg[4], axolotl_box_BYTES+6)!=0) {
    // fail
    printf("fail :/\n");
    exit(1);
  }
  printf("%d %s\n", outlen2, out2);
  printf("alice\n");
  print_ctx(&alice_ctx);
  printf("bob\n");
  print_ctx(&bob_ctx);
  axolotl_box(&bob_ctx,msgx[4], &outlen, (const uint8_t*) "eeeee", 6);
  printf("alice receives aaaaa\n");
  printf("alice\n");
  print_ctx(&alice_ctx);
  printf("bob\n");
  print_ctx(&bob_ctx);
  if(axolotl_box_open(&alice_ctx, out2, &outlen2, msgx[0], axolotl_box_BYTES+6)!=0) {
    // fail
    printf("fail :/\n");
    exit(1);
  }
  printf("%d %s\n", outlen2, out2);
  printf("alice receives ccccc\n");
  printf("alice\n");
  print_ctx(&alice_ctx);
  printf("bob\n");
  print_ctx(&bob_ctx);
  if(axolotl_box_open(&alice_ctx, out2, &outlen2, msgx[2], axolotl_box_BYTES+6)!=0) {
    // fail
    printf("fail :/\n");
    exit(1);
  }
  printf("%d %s\n", outlen2, out2);
  printf("alice receives eeeee\n");
  if(axolotl_box_open(&alice_ctx, out2, &outlen2, msgx[4], axolotl_box_BYTES+6)!=0) {
    // fail
    printf("fail :/\n");
    exit(1);
  }
  printf("%d %s\n", outlen2, out2);
  printf("bob receives 33333\n");
  printf("alice\n");
  print_ctx(&alice_ctx);
  printf("bob\n");
  print_ctx(&bob_ctx);
  if(axolotl_box_open(&bob_ctx, out2, &outlen2, msg[3], axolotl_box_BYTES+6)!=0) {
    // fail
    printf("fail :/\n");
    exit(1);
  }
  printf("%d %s\n", outlen2, out2);

  printf("alice receives ddddd\n");
  printf("alice\n");
  print_ctx(&alice_ctx);
  printf("bob\n");
  print_ctx(&bob_ctx);
  if(axolotl_box_open(&alice_ctx, out2, &outlen2, msgx[3], axolotl_box_BYTES+6)!=0) {
    // fail
    printf("fail :/\n");
    exit(1);
   }
  printf("%d %s\n", outlen2, out2);

  printf("bob receives 22222\n");
  printf("alice\n");
  print_ctx(&alice_ctx);
  printf("bob\n");
  print_ctx(&bob_ctx);
  if(axolotl_box_open(&bob_ctx, out2, &outlen2, msg[2], axolotl_box_BYTES+6)!=0) {
    // fail
    printf("fail :/\n");
    exit(1);
  }
  printf("%d %s\n", outlen2, out2);

  printf("alice receives bbbbb\n");
  printf("alice\n");
  print_ctx(&alice_ctx);
  printf("bob\n");
  print_ctx(&bob_ctx);
  if(axolotl_box_open(&alice_ctx, out2, &outlen2, msgx[1], axolotl_box_BYTES+6)!=0) {
    // fail
    printf("fail :/\n");
    exit(1);
   }
  printf("%d %s\n", outlen2, out2);

  printf("bob receives 00000\n");
  printf("alice\n");
  print_ctx(&alice_ctx);
  printf("bob\n");
  print_ctx(&bob_ctx);
  if(axolotl_box_open(&bob_ctx, out2, &outlen2, msg[0], axolotl_box_BYTES+6)!=0) {
    // fail
    printf("fail :/\n");
    exit(1);
  }
  printf("%d %s\n", outlen2, out2);
  return 0;
}
