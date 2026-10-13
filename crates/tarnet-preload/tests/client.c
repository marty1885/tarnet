/* A dynamically linked client: intentionally has no SOCKS implementation. */
#include <arpa/inet.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 4) return 2;
    struct addrinfo hints = {0}, *result = NULL;
    struct sockaddr_in legacy = {0};
    const struct sockaddr *address;
    socklen_t length;
    int udp = strcmp(argv[1], "udp") == 0;
    if (strcmp(argv[1], "legacy") == 0) {
        struct hostent *host = gethostbyname(argv[2]);
        if (!host) return 3;
#ifdef __APPLE__
        legacy.sin_len = sizeof(legacy);
#endif
        legacy.sin_family = AF_INET;
        legacy.sin_port = htons(atoi(argv[3]));
        memcpy(&legacy.sin_addr, host->h_addr_list[0], sizeof(legacy.sin_addr));
        address = (const struct sockaddr *)&legacy;
        length = sizeof(legacy);
    } else {
        hints.ai_family = AF_INET;
        hints.ai_socktype = udp ? SOCK_DGRAM : SOCK_STREAM;
        if (strcmp(argv[1], "ipv4") == 0 || udp) hints.ai_flags = AI_NUMERICHOST;
        int error = getaddrinfo(argv[2], argv[3], &hints, &result);
        if (error) { fprintf(stderr, "%s\n", gai_strerror(error)); return 3; }
        address = result->ai_addr;
        length = result->ai_addrlen;
    }
    int fd = socket(AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    if (strcmp(argv[1], "nonblocking") == 0) fcntl(fd, F_SETFL, O_NONBLOCK);
    if (connect(fd, address, length) < 0) { perror("connect"); return 4; }
    if (result) freeaddrinfo(result);
    if (strcmp(argv[1], "nonblocking") == 0) {
        if (!(fcntl(fd, F_GETFL) & O_NONBLOCK)) return 5;
        fcntl(fd, F_SETFL, 0);
    }
    if (write(fd, "ping", 4) != 4) return 6;
    char reply[4];
    size_t received = 0;
    while (received < sizeof(reply)) {
        ssize_t n = read(fd, reply + received, sizeof(reply) - received);
        if (n <= 0) return 7;
        received += n;
    }
    close(fd);
    return memcmp(reply, "ping", 4) == 0 ? 0 : 8;
}
