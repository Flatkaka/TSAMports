#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sstream>
#include <iostream>
#include <unistd.h>
#include <sys/fcntl.h>
#include <set>
#include <string.h> 


//this function scans if there are any ports availble behinde all the ports from low_port to high_port.
std::set<int> scan_for_ports(int sock, sockaddr_in server_address, int low_port,int high_port){

    char buffer[1024];        // buffer for reading from clients
    fd_set sockets;
    struct timeval tv;
    std::set<int> open_ports;

    // when we recieve a response from the server we store the address from whiich iit came in response_addr
    // to be able to see for which port the response came
    struct sockaddr_in response_addr;
    int response_addr_len = sizeof(response_addr);

    
    // Execute 3 port scans because the server tends to drop packets
    for (int i = 0; i < 3; i++)
    {
        //check if port from lower port - higer port is occupied or not.
        for (int p = low_port; p <= high_port; p++)
        {
            tv.tv_sec = 0;
            tv.tv_usec = 10000;
            server_address.sin_port = htons(p);

            std::string message = "Hello " + std::to_string(p);

            FD_SET(sock, &sockets);

            int s = sendto(sock, message.c_str(), message.size(), 0, (sockaddr *)&server_address, sizeof(server_address));

            if (s < 0)
            {
                perror("sendto failed");
                exit(2);
            }

            int n = select(sock + 1, &sockets, NULL, NULL, &tv);

            if (n <= 0)
            {
                // timeout or error in select
                // printf("port: %d closed\n", p);
            }
            else
            {
                if (FD_ISSET(sock, &sockets))
                {
                    memset(buffer, 0, sizeof(buffer));
                    int r = recvfrom(sock, buffer, sizeof(buffer), 0x0, (struct sockaddr *)&response_addr, (socklen_t *)&response_addr_len);

                    //if there is no error then we have found a port!
                    if (r != -1)
                    {
                        open_ports.insert(ntohs(response_addr.sin_port));
                    }
                }
            }
        }
    }
    return open_ports;
}



int main(int argc, char *argv[])
{
    int sock;                 // socket that is used to connect to server
    int port;                 // port of server to connect to
    int nread;                // number of bytes that server sends back
    std::string user_command; // command thatuser sends to server
    std::string output;       // response from server that will be printed to console
    //check if there are enough arrgument.
    if (argc < 3)
    {
        printf("Usage: <ip address> <lower port> <higer port>\n");
        exit(0);
    }

    // Setup client socket
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("Failed␣to␣open␣socket");
        return (-1);
    }

    // initialize the server address
    sockaddr_in server_address;
    memset(&server_address, 0, sizeof(server_address));
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr(argv[1]);

    
    std::set<int> open_ports = scan_for_ports(sock, server_address, atoi(argv[2]), atoi(argv[3]));

    // print all of the open ports
    std::cout << "The open ports on " << argv[1] << " are\n";
    for (int port : open_ports)
    {
        std::cout << port << std::endl;
    }

}
