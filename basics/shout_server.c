#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <errno.h>
#include <sys/time.h>
#include <unistd.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <arpa/inet.h>
#endif

int main(int argc, char const* argv[]){
    /*
    AL_INET - IPv4 Internet protocal\
    SOCK_DGRAM - UDP
    0 - just says that only a single protocal exist to support this particular socket, revisit socket man page for more detail
    */
    int udp_socket = socket(AF_INET, SOCK_DGRAM, 0);
    if(udp_socket == -1){
        perror("failed to initialize socket\n");
        exit(1);
    }

    // Bind the socket
    const sa_family_t SIN_FAMILY = AF_INET;
    const in_port_t SIN_PORT = 50000;
    const struct in_addr SIN_ADDR = {
        .s_addr = htonl(INADDR_LOOPBACK)
    };
    const struct sockaddr_in SOCKET_ADDRESS = {
        .sin_family = SIN_FAMILY,
        .sin_port = htons(SIN_PORT),
        .sin_addr = SIN_ADDR

    }; 
    const socklen_t SOCKET_ADDR_LEN = sizeof(SOCKET_ADDRESS);
    
    if(bind(udp_socket, (struct sockaddr *)&SOCKET_ADDRESS, SOCKET_ADDR_LEN) == -1){
        perror("failed to bind socket\n");
        exit(1);
    }

    // Set time out for recvfrom 
    struct timeval tv;
    tv.tv_sec = 5;   // seconds
    tv.tv_usec = 0;  // microseconds

    if (setsockopt(udp_socket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("error when calling setsockopt");
        exit(1);
    }


    char buffer[1024] = {0};

    // We don't care about the source ip address in this project so we pass NULL for the last two addr parameters
    ssize_t n = recvfrom(udp_socket, buffer, sizeof(buffer) - 1, 0, NULL, NULL);

    if (n < 0) {
        // errno would be different depending on machine, both means the same thing in this context
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("no data received within timeout, closing socket\n");
        } else {
            perror("error when calling recvfrom");
        }
    } else {
        buffer[n] = '\0';
        printf("received: %s\n", buffer);
    }


    if(close(udp_socket) == -1){
        perror("failed to close socket\n");
        exit(1);
    }
    return 0;

}
