#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUFFER_SIZE 1024
#define TCP_HEADER_LEN (6 * 4)
#define INVALID_HEADER -1
#define OTHER_DESTINATION -2

/* struct ip_header {
  unsigned char version : 4;
  unsigned char header_len_word : 4;
  unsigned char type_of_service;
  unsigned short total_length;
  unsigned short identification;
  unsigned char reserved_flag : 1;
  unsigned char dont_fragment : 1;
  unsigned char more_fragment : 1;
  unsigned short fragment_offset : 13;
  unsigned char time_to_live;
  unsigned char protocol;
  unsigned short header_checksum;
  unsigned long source_address;
  unsigned long destination_address;
  unsigned long options;
}; */

struct ip_header {
  unsigned char version;
  unsigned char header_len_in_byte;
  unsigned char type_of_service;
  unsigned short total_length;
  unsigned short identification;
  unsigned char dont_fragment;
  unsigned char more_fragment;
  unsigned short fragment_offset;
  unsigned char time_to_live;
  unsigned char protocol;
  unsigned short header_checksum;
  unsigned long source_address;
  unsigned long destination_address;
  unsigned long options;
};

struct ipv4_pseudo_header {
  unsigned long source_address;
  unsigned long destination_address;
  unsigned char zero;
  unsigned char protocol;
  /*
   * The TCP header length plus the data length in octets,
   * and it does not count the 12 octets of the pseudo-header.
   */
  unsigned short tcp_length;
};

struct tcp_header {
  unsigned short source_port;
  unsigned short destination_port;
  unsigned long sequence_number;
  unsigned long ack_number;
  /* data_offset is in the upper 4 bits */
  unsigned char data_offset;
  unsigned char control_bits;
  unsigned short window;
  unsigned short checksum;
  unsigned short urgent_pointer;
  unsigned long options;
};

unsigned short calc_checksum(const unsigned char *const buffer,
                             const unsigned char header_len_byte) {
  unsigned long sum = 0;
  unsigned char word_index;

  for (word_index = 0; word_index < header_len_byte; word_index += 2) {
    /* add word to sum */
    sum += (unsigned short)buffer[word_index] << 8 | buffer[word_index + 1];

    /* wrap around carry */
    if (sum > 0xffff) {
      sum = (sum & 0xffff) + 1;
    }
  }

  /* ones compliment */
  return ~sum;
}

/* @param buffer: the checksum of the Datagram Header is cleared
 * @return Datagram Header length in bytes, INVALID_HEADER or
 * OTHER_DESTINATION
 */
int receive_from(unsigned char *const buffer, const unsigned long buffer_len,
                 const unsigned long address) {
  unsigned char header_len_in_byte;
  unsigned short fragment_id;
  unsigned short fragment_offset;
  unsigned short checksum;
  unsigned short calculated_checksum;
  unsigned long source_address;
  unsigned long destination_address;

  /* the smallest possible header is 20 bytes */
  if (buffer_len < 20) {
    return INVALID_HEADER;
  }

  /* # Internet Protocol Header
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |Version|  IHL  |Type of Service|          Total Length         |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |         Identification        |Flags|      Fragment Offset    |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |  Time to Live |    Protocol   |         Header Checksum       |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                       Source Address                          |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                    Destination Address                        |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                    Options                    |    Padding    |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   */

  /* check if version is IPv4 */
  if ((buffer[0] & 0xf0) != 0x40) {
    return OTHER_DESTINATION;
  }

  header_len_in_byte = (buffer[0] & 0xf) * 4;

  /* 0 = may Fragment, 1 = don’t Fragment. */
  if (buffer[6] >> 6 & 1) {
  }

  /* 0 = last Fragment, 1 = more Fragments. */
  if (buffer[6] >> 5 & 1) {
  }

  fragment_id = (unsigned short)buffer[4] << 8 | buffer[5];
  fragment_offset = (unsigned short)(buffer[6] & 0x1f) << 8 | buffer[7];

  /* check if protocol is TCP */
  if (buffer[9] != 6) {
    return OTHER_DESTINATION;
  }

  checksum = (unsigned short)buffer[10] << 8 | buffer[11];

  /* set checksum field to zero */
  buffer[10] = 0;
  buffer[11] = 0;
  calculated_checksum = calc_checksum(buffer, header_len_in_byte);

  if (checksum != calculated_checksum) {
    printf("error: checksum not matching the calculated (%04x != %04x)\n",
           checksum, calculated_checksum);
    return INVALID_HEADER;
  }

  source_address =
      buffer[12] << 24 | buffer[13] << 16 | buffer[14] << 8 | buffer[15];

  destination_address =
      buffer[16] << 24 | buffer[17] << 16 | buffer[18] << 8 | buffer[19];

  if (destination_address != address) {
    return OTHER_DESTINATION;
  }

  return header_len_in_byte;
}

int filter_tcp(unsigned char *const tcp_header_buffer,
               const unsigned long buffer_len, const unsigned short port) {
  struct tcp_header header;
  unsigned short calculated_checksum;

  if (buffer_len < TCP_HEADER_LEN) {
    return INVALID_HEADER;
  }

  /* # TCP Header
      0                   1                   2                   3
      0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |          Source Port          |       Destination Port        |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                        Sequence Number                        |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                    Acknowledgment Number                      |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |  Data |       |C|E|U|A|P|R|S|F|                               |
     | Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
     |       |       |R|E|G|K|H|T|N|N|                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |           Checksum            |         Urgent Pointer        |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                           [Options]                           |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
     |                                                               :
     :                             Data                              :
     :                                                               |
     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   */

  header.source_port =
      (unsigned short)tcp_header_buffer[0] << 8 | tcp_header_buffer[1];
  header.destination_port =
      (unsigned short)tcp_header_buffer[2] << 8 | tcp_header_buffer[3];

  if (header.destination_port != port) {
    return OTHER_DESTINATION;
  }

  header.sequence_number = tcp_header_buffer[4] << 24 |
                           tcp_header_buffer[5] << 16 |
                           tcp_header_buffer[6] << 8 | tcp_header_buffer[7];

  header.ack_number = tcp_header_buffer[8] << 24 | tcp_header_buffer[9] << 16 |
                      tcp_header_buffer[10] << 8 | tcp_header_buffer[11];

  header.data_offset = tcp_header_buffer[12] >> 4 & 0xf;

  header.control_bits = tcp_header_buffer[13];

  header.window = tcp_header_buffer[14] << 8 | tcp_header_buffer[15];

  header.checksum = tcp_header_buffer[16] << 8 | tcp_header_buffer[17];

  /* set checksum field to zero */
  tcp_header_buffer[16] = 0;
  tcp_header_buffer[17] = 0;
  /* TODO missing pseudo header */
  calculated_checksum = calc_checksum(tcp_header_buffer, TCP_HEADER_LEN);

  header.urgent_pointer = tcp_header_buffer[18] << 8 | tcp_header_buffer[19];

  header.options = tcp_header_buffer[20] << 24 | tcp_header_buffer[21] << 16 |
                   tcp_header_buffer[22] << 8 | tcp_header_buffer[23];

  if (header.checksum != calculated_checksum) {
    printf("error: checksum not matching the calculated (%04x != %04x)\n",
           header.checksum, calculated_checksum);
    return INVALID_HEADER;
  }

  return 0;
}

int main(void) {
  unsigned char *buffer = malloc(BUFFER_SIZE);
  int err = 0;
  int sock;
  int read_len;
  struct sockaddr_in address;
  const socklen_t address_len = sizeof(address);
  int datagram_start;
  struct ip_header *ip_header;

  if (buffer == NULL) {
    perror("failed to allocate memory");
    return 1;
  }

  /* create socket for IPv4 */
  sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (sock == -1) {
    perror("failed to create socket");
    free(buffer);
    buffer = NULL;
    return sock;
  }

  printf("listening for clients who send to 127.0.0.1\n");

  for (;;) {
    read_len = recv(sock, buffer, BUFFER_SIZE, 0);

    if (read_len == -1) {
      perror("failed to receive");
      continue;
    }

    printf("from: %d.%d.%d.%d\n", buffer[16], buffer[17], buffer[18],
           buffer[19]);

    /* only accept 127.0.0.1 */
    datagram_start = receive_from(buffer, read_len, 0x7f000001);

    if (datagram_start < 0) {
      continue;
    }

    /* only accept TCP to port 54333 */
    filter_tcp(buffer + datagram_start, BUFFER_SIZE - read_len, 54333);

    printf("received: %02x %02x\n", buffer[datagram_start],
           buffer[datagram_start + 1]);
  }

cleanup:
  close(sock);
  free(buffer);
  buffer = NULL;
  return err;
}
