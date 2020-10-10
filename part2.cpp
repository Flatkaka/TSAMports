
#include <sys/un.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <iomanip>
#include <arpa/inet.h>
#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sstream>
#include <fcntl.h>
#include <string>

#define u32 unsigned int
#define u16 unsigned short
#define u8 unsigned char


std::string get_byte_hexdump(void *buffer, int buflen)
{
  /**
        Author Benedikt H. Thordarson.
        Given buffer b, and length of b in bytes bufen,
        print buffer in wireshark format.
        output works for wireshark imports.
    **/

  // create byte buffer.
  unsigned char *byte_buffer = (unsigned char *)buffer;
  std::string hexdump = "";
  for (int i = 0; i < buflen; i += 16)
  {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    // show addr offset
    ss << std::setw(8) << std::hex << i;
    int j = 0;

    for (j = 0; j < 16; j++)
    {
      //break before we go out of bounds
      if (i + j == buflen)
      {
        break;
      }
      // if we are at the 8B place, inject extra space
      if (j % 8 == 0 && j != 0)
      {
        ss << " ";
      }
      //inject space
      ss << " " << std::hex << std::setw(2) << (unsigned int)byte_buffer[i + j];
    }
    // pad to length before we add our char printouts.
    while (j < 16)
    {
      ss << "   ";
      j += 1;
    }
    // Add the char print.
    ss << "\t| ";
    for (j = 0; j < 16; j++)
    {
      // do not go out of bounds.
      if (i + j == buflen)
      {
        break;
      }
      if (j % 8 == 0 && j != 0)
      {
        ss << " ";
      }
      // if the character is not printable or is a newline, print a star.
      if (byte_buffer[i + j] == (unsigned char)'\n' || !std::isprint(byte_buffer[i + j]))
      {
        ss << "*";
      }
      else
      {
        ss << byte_buffer[i + j];
      }
    }
    // add newline and append to dump.
    ss << "\n";
    hexdump += ss.str();
  }
  return hexdump;
}

u16 ipv4_check(void *buffer, u16 len)
{
  u16 llen = len / 2;
  u16 *u16buffer = (u16 *)(buffer);
  u32 sum = 0;
  for (u16 i = 0; i < llen; i++)
  {
    u32 val = (u32)(u16buffer[i]);
    sum += val;
    sum = (sum >> 16) + (sum & 0xFFFF);
  }
  return ~((u16)sum);
}

u16 udp_check(struct iphdr *ip_header, void *buffer, u16 len)
{
  // this function calculate the udp checksum, by adding together the pseudo ip header, the udp header and its data
  u16 llen = len / 2;
  u16 *u16buffer = (u16 *)(buffer);
  u8 *u8buffer = (u8 *)(buffer);
  u32 sum = 0;
  // if thelength of the header is odd, then we must add the last byte to the sum
  if (len % 2 == 1)
  {
    u16 last = (u16)u8buffer[len - 1];
    sum += last;
  }
  // for each to bytes in the headers, add them to the sum and shift all overflow to the back
  for (u16 i = 0; i < llen; i++)
  {

    u32 val = (u32)(u16buffer[i]);
    sum += val;
    sum = (sum >> 16) + (sum & 0xFFFF);
  }

  // add the pseudo ip header to the sum
  sum += ((ip_header->saddr) >> 16) & 0xFFFF;
  sum += (ip_header->saddr) & 0xFFFF;

  sum += ((ip_header->daddr) >> 16) & 0xFFFF;
  sum += (ip_header->daddr) & 0xFFFF;

  sum += htons(ip_header->protocol);
  sum += htons(len);

  // Add the carries
  while (sum >> 16)
    sum = (sum & 0xFFFF) + (sum >> 16);
  return ~((u16)sum);
}

std::string get_checksum_from_response(char *buffer, u32 buff_len)
{
  // This function finds the desired checksum from the server response
  int index;
  std::stringstream item;
  std::string token;
  // find the index where the checksum is located in the message
  for (int i = 0; i < buff_len; i++)
  {
    item << buffer[i];
    item << buffer[i + 1];
    item << '$';
    std::getline(item, token, '$');
    if (token.compare("0x") == 0)
    {
      index = i + 2;
      break;
    }
  }
  //find the checksum we wan't
  std::stringstream ss;
  for (int j = 0; j < 4; j++)
  {
    ss << buffer[index + j];
  }
  std::string str = ss.str();
  return str;
}

std::string send_message(int sock, int sock_recv, char *send_buffer, u32 buff_len, sockaddr_in server_address, bool process_response)
{
  // This function sends the given message (in the send buffer) to a provided server and returns the response from the server
  bool delivered = false;
  char buffer[1024];
  int s;
  std::string response;
  // the server tends to drop packets so the sockets have timeouts and are repeatedly sent until and answer is received
  while (!delivered)
  {
    // send themessage to server
    s = sendto(sock, send_buffer, buff_len, 0, (sockaddr *)&server_address, sizeof(server_address));
    if (s < 0)
    {
      perror("sendto failed");
      exit(2);
    }
    // read the response from the server
    memset(buffer, 0, sizeof(buffer));
    int r = recvfrom(sock_recv, buffer, sizeof(buffer), 0x0, NULL, NULL);
    if (r != -1)
    {
      delivered = true;
      if (process_response)
      {
        // get the checksum from the message
        response = get_checksum_from_response(buffer, 1024);
      }
      else
      {
        response = std::string(buffer);
      }
    }
  }
  return response;
}

std::string get_secret_message(int sock, int sock_recv, sockaddr_in server_address, struct sockaddr_in my_addr, char *dest_addr, char *port, char *source_ip)
{
  // this function communicates with a port on the server that asks for a message with a specific checksum. The function calculates the message that results in the given
  //checksum, sends it to the server and returns the server´s response

  // the port on the server that provides checksum vlues must be provided in the arguments
  server_address.sin_port = htons(atoi(port));

  // the initial message sent to the port to receive the checksum
  std::string message = "$group_98$";

  // this variable will store thechecksum of a request with an empty message from our computer to the given port on the server
  u16 empty_check;

  // the buffer consists og the ip header, the udp header and the data (message)
  u32 buff_len = sizeof(struct iphdr) + sizeof(struct udphdr) + message.length();

  char send_buffer[buff_len];
  memset(send_buffer, 0, buff_len);
  // initialize the headers and the data
  struct iphdr *ip_header = (struct iphdr *)(send_buffer);
  struct udphdr *udp_header = (struct udphdr *)(send_buffer + sizeof(iphdr));
  char *data = (send_buffer + sizeof(struct iphdr) + sizeof(struct udphdr));

  // here we only initialize the values of the ip header that are included in a pseudo headerto be able to 
  // calculate the checksum of an empty message (stored in empty_check)
  ip_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr));
  ip_header->protocol = IPPROTO_UDP;
  ip_header->saddr = inet_addr(source_ip);
  ip_header->daddr = inet_addr(dest_addr);

  udp_header->len = htons(sizeof(udphdr));
  udp_header->dest = server_address.sin_port;
  udp_header->source = my_addr.sin_port;
  // calculate the checksum of a request with an empty message (to be able to calculate the message that creates the desired checksum later)
  empty_check = udp_check((struct iphdr *)ip_header, (u8 *)udp_header, sizeof(udphdr));

  // initialize the rest of the attributes of the two headers
  ip_header->version = 4;
  ip_header->ihl = 5;
  ip_header->ttl = 225;

  ip_header->id = htons(1337); 
  ip_header->tos = 0;
  ip_header->frag_off = 0;
  ip_header->tot_len = htons(buff_len); // not htons on mac

  u16 check = ipv4_check(ip_header, sizeof(iphdr));
  ip_header->check = check;

  udp_header->len = htons((sizeof(udphdr) + message.length()));

  memcpy(data, message.c_str(), message.length());

  udp_header->check = udp_check((struct iphdr *)ip_header, (u8 *)udp_header, ntohs(udp_header->len));

  // send a message to the port with our group number to get the checksum value
  std::string str = send_message(sock, sock_recv, send_buffer, buff_len, server_address, true);
  // change the checksum from a string to to a unsinged short, for later calculations
  u16 number = (u32)std::stoi(str, 0, 16);
  number = ntohs(number);
  // we always send a message of length two so here we create a constant that we can subtract from the message so 
  // because the length of the message will affect the checksum. If we do not subtract it the checksum will be to
  //high because the length is added in the length of the two headers
  u16 l = 4 << 8;
  // the message that will generate the desired checksum is the one´s complement of the desired checsum minus
  // the checksm of the empty message minus the length constant
  u32 u32_message = ((u16) ~(number)) + ((u16)empty_check) + ((u16) ~(l));
  // add the carriers
  u32_message = (u32_message >> 16) + (u32_message & 0xFFFF);

  u16 u16_message = (u16)u32_message;

  buff_len = sizeof(struct iphdr) + sizeof(struct udphdr) + sizeof(u16);
  // initialize the send buffer
  char send_buffer_check[buff_len];
  memset(send_buffer_check, 0, buff_len);

  ip_header = (struct iphdr *)(send_buffer_check);
  udp_header = (struct udphdr *)(send_buffer_check + sizeof(iphdr));
  data = (send_buffer_check + sizeof(struct iphdr) + sizeof(struct udphdr));

  // initialize the ip header attributes
  ip_header->version = 4;
  ip_header->ihl = 5;
  ip_header->ttl = 225;
  ip_header->protocol = IPPROTO_UDP;
  ip_header->id = htons(1337);
  ip_header->tos = 0;
  ip_header->frag_off = 0;

  ip_header->tot_len = htons(buff_len); // not htons for macOS
  ip_header->saddr = inet_addr(source_ip);
  ip_header->daddr = inet_addr(dest_addr);
  check = ipv4_check(ip_header, sizeof(iphdr));
  ip_header->check = check;

  udp_header->dest = server_address.sin_port;
  udp_header->source = my_addr.sin_port; // hmmm
  udp_header->len = htons((sizeof(udphdr) + sizeof(u16)));
  // write the message to the send buffer
  memcpy(data, &u16_message, sizeof(u16));

  check = udp_check((struct iphdr *)ip_header, (u8 *)udp_header, ntohs(udp_header->len));
  udp_header->check = check;
  // send the calculated message to the server to receivethe secret phase
  std::string secret = send_message(sock, sock_recv, send_buffer_check, buff_len, server_address, false);

  return secret;
}

std::string get_secret_port1(sockaddr_in server_address, struct sockaddr_in my_addr, char *dest_addr, char *port, char *source_ip)
{
  // This function simply sends a request to the port, provided in the arguments, that leaks information about a hidden port, and returns the hidden port
  server_address.sin_port = htons(atoi(port));
  std::string message = "Plesae give me the secret port";

  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  // Setup socket
  int sock;
  if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
  {
    perror("Failed␣to␣open␣socket");
    exit(1);
  }
  // set timeout on the socket
  if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv)) < 0)
  {
    perror("setsockopt failed\n");
    exit(1);
  }

  bool delivered = false;
  char buffer[1024];
  std::string secret;
  // the server tends to drop packets so the sockets have timeouts and are repeatedly sent until and answer is received
  while (!delivered)
  {
    int s = sendto(sock, message.c_str(), message.length(), 0, (sockaddr *)&server_address, sizeof(server_address));
    if (s < 0)
    {
      perror("sendto failed");
      exit(2);
    }

    memset(buffer, 0, sizeof(buffer));
    int r = recvfrom(sock, buffer, sizeof(buffer), 0x0, NULL, NULL);
    if (r != -1)
    {
      delivered = true;
      secret = std::string(buffer);
    }
  }
  return secret;
}

std::string get_secret_port_evil(int sock, int sock_recv, sockaddr_in server_address, struct sockaddr_in my_addr, char *dest_addr, char *port, char *source_ip)
{
  // this function sends a request with the evil bit set to the port that is sensiteve to evil bits and returns the secret port that the server sends back

  // the port on the server that provides checksum vlues must be provided in the arguments
  server_address.sin_port = htons(atoi(port));
  std::string message = "$group_98$";
  // the initial message sent to the port to receive the checksum
  u32 buff_len = sizeof(struct iphdr) + sizeof(struct udphdr) + message.length();

  char send_buffer[buff_len];
  memset(send_buffer, 0, buff_len);
  // initialize the headers and the data
  struct iphdr *ip_header = (struct iphdr *)(send_buffer);
  struct udphdr *udp_header = (struct udphdr *)(send_buffer + sizeof(iphdr));
  char *data = (send_buffer + sizeof(struct iphdr) + sizeof(struct udphdr));

  // initialize the attributes
  ip_header->version = 4;
  ip_header->ihl = 5;
  ip_header->ttl = 225;
  ip_header->protocol = IPPROTO_UDP;
  ip_header->id = htons(1337); 
  ip_header->tos = 0;
  ip_header->frag_off = 0x8000;
  ip_header->tot_len = htons(buff_len); // not htons for macOS
  ip_header->saddr = inet_addr(source_ip);
  ip_header->daddr = inet_addr(dest_addr);
  u16 check = ipv4_check(ip_header, sizeof(iphdr)); 
  ip_header->check = check;

  udp_header->dest = server_address.sin_port;
  udp_header->source = my_addr.sin_port; 
  udp_header->len = htons((sizeof(udphdr) + message.length()));
  // write the message to the send buffer
  memcpy(data, message.c_str(), message.length());

  udp_header->check = udp_check((struct iphdr *)ip_header, (u8 *)udp_header, ntohs(udp_header->len));

  // send a message with the evil bit set to the server to get the secret port
  std::string secret = send_message(sock, sock_recv, send_buffer, buff_len, server_address, false);

  return secret;
}

int main(int argc, char **argv)
{
  if (argc < 5)
  {
    printf("Usage: scanner <dest ip address> <source ip address> <port1> <port2> <port3>\n");
    exit(0);
  }
  // the destination ddress and source address must be provided in the arguments
  char *dest_ip = argv[1];
  char *source_ip = argv[2];
  // setup a raw socket
  int sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
  if (sock < 0)
  {
    perror("raw socket error");
    exit(1);
  }
  // setup a receive socket that has a timeout, requests are sent again if the timeout runs out
  struct timeval tv;
  tv.tv_sec = 1;
  tv.tv_usec = 0;
  int sock_recv = socket(AF_INET, SOCK_DGRAM, 0);
  if (sock < 0)
  {
    perror("recv socket error");
    exit(1);
  }
  // set the timeout to the socket
  if (setsockopt(sock_recv, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv, sizeof(tv)) < 0)
  {
    perror("setsockopt failed\n");
    exit(1);
  }
  // set the socket options to be able to manage the headers
  int opt = 1;
  int sso = setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
  if (sso < 0)
  {
    perror("sockopt failed");
    exit(2);
  }
  // initialize the server address
  sockaddr_in server_address;
  memset(&server_address, 0, sizeof(server_address));
  server_address.sin_family = AF_INET;
  server_address.sin_addr.s_addr = inet_addr(argv[1]);
  server_address.sin_port = htons(atoi(argv[2]));

  // initialize the source port and the source address
  struct sockaddr_in my_addr;
  int my_len = sizeof(my_addr);
  my_addr.sin_family = AF_INET;
  inet_aton(source_ip, &my_addr.sin_addr);
  my_addr.sin_port = htons(5555);
  // bind the receive socket to the source address so all responses go to that socket
  if (bind(sock_recv, (struct sockaddr *)&my_addr, my_len) < 0)
  {
    perror("bind failed");
    exit(4);
  }
  // get the first secret port to print to console
  std::string secret1 = get_secret_port1(server_address, my_addr, dest_ip, argv[3], source_ip);
  // get the second secret port to print to console
  std::string secret2 = get_secret_port_evil(sock, sock_recv, server_address, my_addr, dest_ip, argv[4], source_ip);
  // get the secret phase port to print to console
  std::string secret_phase = get_secret_message(sock, sock_recv, server_address, my_addr, dest_ip, argv[5], source_ip);

  std::cout << secret1 << std::endl;
  std::cout << secret2 << std::endl;
  std::cout << secret_phase << std::endl;
}