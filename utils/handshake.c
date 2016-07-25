#include "axolotl.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

int main(int argc, char** argv) {
  Axolotl_ctx ctx;
  Axolotl_PreKey prekey;

  if(argc<2) {
    printf("%s <ctx> <prekey\n", argv[0]);
    exit(1);
  }

  // read in identity key from stdin
  read(0,&prekey,sizeof(prekey));

  FILE* fd=fopen(argv[1], "r+");
  if(fd==NULL) {
    printf("cannot open %s\n", argv[1]);
    exit(1);
  }
  fread(&ctx, sizeof(ctx),1,fd);

  axolotl_handshake(&ctx, &prekey);

  fseek(fd, 0, SEEK_SET);
  fwrite(&ctx, sizeof(ctx),1,fd);
  fclose(fd);
  return 0;
}
