#include "axolotl.h"
#include <stdio.h>
#include <stdlib.h>

int main(void) {
  Axolotl_ctx alice_ctx, bob_ctx;
  Axolotl_KeyPair alice_id, bob_id;
  Axolotl_InitMsg alice_init, bob_init;

  // init long-term identity keys
  axolotl_genid(&alice_id);
  axolotl_genid(&bob_id);

  axolotl_setup(&alice_init, &alice_ctx, &alice_id);
  axolotl_setup(&bob_init, &bob_ctx, &bob_id);

  // both derive the ctx from their exchanged init msg
  axolotl_accept(&alice_ctx, &bob_init);
  axolotl_accept(&bob_ctx, &alice_init);

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
