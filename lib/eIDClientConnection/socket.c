#include <errno.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32")
#else
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#ifndef SHUT_RDWR
#define SHUT_RDWR SD_BOTH
#endif

int my_closesocket(int s)
{
    if (0 != shutdown(s, SHUT_RDWR))
        return -1;

#ifdef _WIN32
    return closesocket(s);
#else
    return close(s);
#endif
}

int my_connectsocket (const char *const hostname, const char *const port)
{
    struct addrinfo hints, *res, *cur_res;
    int fd = -1, err;

#ifdef _WIN32
    WSADATA info;
    if (WSAStartup(MAKEWORD(2, 2), &info)) {
        fprintf(stderr, "Error initializing Winsock.\n");
    }
#endif

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;     /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* Stream socket */
    
    err = getaddrinfo (hostname, port, &hints, &res);
    if (err != 0) {
        fprintf(stderr, "Cannot connect to %s:%s: %s\n", hostname, port, gai_strerror(err));
        return fd;
    }
    
    /* getaddrinfo() returns a list of address structures.  Try each address
     * until we successfully connect(2).  If socket(2) (or connect(2)) fails,
     * we (close the socket and) try the next address. */
    for (cur_res = res; cur_res != NULL; cur_res = cur_res->ai_next) {
        fd = socket (cur_res->ai_family, cur_res->ai_socktype, cur_res->ai_protocol);
        if (fd == -1)
            continue;
        if (connect (fd, cur_res->ai_addr, cur_res->ai_addrlen) != -1)
            break;
        my_closesocket(fd);
    }

    if (fd == -1) {
        fprintf(stderr, "Cannot connect to %s:%s: %s\n", hostname, port, strerror(errno));
    }

    freeaddrinfo (res);

    return fd;
}
