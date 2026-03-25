#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUFFER_SIZE 1024
#define MAX_WAITING 128

int main(void) {
  unsigned char *buffer = malloc(BUFFER_SIZE);
  int err = 0;
  int sock;
  struct sockaddr_in address;
  socklen_t address_len = sizeof(address);

  address.sin_family = AF_INET;
  address.sin_port = 54364;
  address.sin_addr.s_addr = INADDR_LOOPBACK;

  if (buffer == NULL) {
    perror("failed to allocate memory");
    return 1;
  }

  /* create socket for IPv4 */
  sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (sock == -1) {
    perror("failed to create socket");
    free(buffer);
    return sock;
  }

  printf("listening for clients\n");

  for (;;) {
    recvfrom(sock, buffer, BUFFER_SIZE, 0, (struct sockaddr *)&address,
             &address_len);

    printf("%d.%d.%d.%d\n", address.sin_addr.s_addr & 0xff,
           address.sin_addr.s_addr >> 8 & 0xff,
           address.sin_addr.s_addr >> 16 & 0xff,
           address.sin_addr.s_addr >> 24 & 0xff);

    printf("%02x %02x %02x %02x\n", buffer[0], buffer[1], buffer[2], buffer[3]);
  }

cleanup:
  close(sock);
  free(buffer);
  return err;
}
