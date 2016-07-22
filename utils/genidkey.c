#include "axolotl.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(void) {
  Axolotl_KeyPair id;

  // init long-term identity keys
  axolotl_genid(&id);

  write(1, &id, sizeof(id));
  return 0;
}
