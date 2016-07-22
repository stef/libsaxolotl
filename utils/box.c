#include "axolotl.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

int main(int argc, char** argv) {
  Axolotl_ctx ctx;

  if(argc<2) {
    printf("%s <ctx> <msg\n", argv[0]);
    exit(1);
  }

  FILE* fd=fopen(argv[1], "r+");
  if(fd==NULL) {
    printf("cannot open %s\n", argv[1]);
    exit(1);
  }
  fread(&ctx, sizeof(ctx),1,fd);

  uint8_t out[4096+128], in[4096];
  int outlen,inlen;

  if((inlen=read(0,in,sizeof(in)))>0) {
    axolotl_box(&ctx, out, &outlen, in, inlen);
  }
  write(1,out,outlen);

  fseek(fd, 0, SEEK_SET);
  fwrite(&ctx, sizeof(ctx),1,fd);
  fclose(fd);
  return 0;
}
