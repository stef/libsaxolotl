#include "axolotl.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
  Axolotl_ctx alice_ctx, bob_ctx;
  Axolotl_KeyPair alice_id, bob_id;
  Axolotl_PreKey alice_prekey, bob_prekey;

  // init long-term identity keys
  axolotl_genid(&alice_id);
  axolotl_genid(&bob_id);

  axolotl_prekey(&alice_prekey, &alice_ctx, &alice_id);
  axolotl_prekey(&bob_prekey, &bob_ctx, &bob_id);

  // both derive the ctx from their exchanged prekey msg
  axolotl_handshake(&alice_ctx, &bob_prekey);
  axolotl_handshake(&bob_ctx, &alice_prekey);

  uint8_t out[4096], out2[4096];
  int outlen,outlen2;
  axolotl_box(&alice_ctx, out, &outlen, (const uint8_t *) "howdy", 6);
  if(axolotl_box_open(&bob_ctx, out2, &outlen2, out, outlen)!=0) {
    // fail
    printf("fail :/\n");
    exit(1);
  }
  printf("%d %s\n", outlen2, out2);
  return 0;
}
