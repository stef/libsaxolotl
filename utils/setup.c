#include "axolotl.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

int main(int argc, char** argv) {
  Axolotl_KeyPair id;
  Axolotl_ctx ctx;
  Axolotl_PreKey prekey;

  if(argc<2) {
    printf("%s <prefix>\n", argv[0]);
    exit(1);
  }

  // read in identity key from stdin
  read(0,&id,sizeof(id));

  axolotl_prekey(&prekey, &ctx, &id);

  size_t fname_len = strlen(argv[1]);
  char fname[fname_len+4+1];
  sprintf(fname, "%s.ctx", argv[1]);
  FILE* fd=fopen(fname, "w");
  if(fd==NULL) {
    printf("cannot open %s\n", fname);
    exit(1);
  }
  fwrite(&ctx, sizeof(ctx),1,fd);
  fclose(fd);

  sprintf(fname, "%s.pub", argv[1]);
  fd=fopen(fname, "w");
  if(fd==NULL) {
    printf("cannot open %s\n", fname);
    exit(1);
  }
  fwrite(&prekey, sizeof(prekey),1,fd);
  fclose(fd);
  return 0;
}
