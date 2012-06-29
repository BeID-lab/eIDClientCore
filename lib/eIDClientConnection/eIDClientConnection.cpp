# ifndef __GNUC__
typedef long ssize_t;
# endif

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32")
#else
#include <sys/socket.h>
#include <sys/types.h>
#endif

#include "eIDClientConnection.h"
#include "gnutls.c"
#include "socket.c"


typedef struct
{
    char *hostname;
    char *port;
	char *path;
    int fd;
    int secure;
    void *ssl_tls_driver_data;
} socket_st;

ssize_t my_recv (const socket_st * const sock, void *buffer, size_t buffer_size);
ssize_t my_send (const socket_st * const sock, const void *const buffer, size_t buffer_size);


struct ssl_tls_driver {
    ssize_t (*send) (const void * const driver_data, const void *const buffer, size_t buffer_size);
    ssize_t (*recv) (const void * const driver_data, void *const buffer, size_t buffer_size);
    void * (*connect) (int fd, const unsigned char *const psk, size_t psk_len, const char *const sid, const char *const hostname);
    void (*disconnect) (const void * const driver_data);
};

struct ssl_tls_driver ssl_tls_driver;


void getContent(const char* const data, const int nDataLength, const char* const bufResult, const int nBufResultLength);


extern "C" EID_CLIENT_CONNECTION_ERROR eIDClientConnectionStart(P_EIDCLIENT_CONNECTION_HANDLE hConnection,  const char *const hostname, const char *const port, const char *const path, const char *const sid, const char* const pskKey)
{
	if(0x00 == hConnection)
	{
		return EID_CLIENT_CONNECTION_SOCKET_ERROR;
	}
	else
	{
		*hConnection = 0x00;
	}

	socket_st *sock = (socket_st *) malloc(sizeof *sock);
	if(0x00 == sock)
	{
		return EID_CLIENT_CONNECTION_SOCKET_ERROR;
	}
	// initalize sock
	sock->hostname = strdup (hostname);
    sock->port = strdup(port);
    sock->path = strdup(path);
	sock->fd = 0x00;
	sock->secure = 0;
	sock->ssl_tls_driver_data = 0x00;

    /* TODO integration of user driven configuration to change SSL/TLS driver */
    ssl_tls_driver.recv = gnutls_recv;
    ssl_tls_driver.send = gnutls_send;
    ssl_tls_driver.connect = gnutls_connect;
    ssl_tls_driver.disconnect = gnutls_disconnect;

    sock->fd = my_connectsocket (sock->hostname, sock->port, sock->path);
    if (sock->fd == -1)
	{
	  eIDClientConnectionEnd((EIDCLIENT_CONNECTION_HANDLE) sock);
	  return EID_CLIENT_CONNECTION_SOCKET_ERROR;
	}

    if (strcmp(sock->port, "80") != 0 && strcmp(sock->port, "8080") != 0) 
	{
        sock->ssl_tls_driver_data = ssl_tls_driver.connect(sock->fd, (unsigned char *) pskKey, pskKey ? strlen(pskKey) : 0, sid, hostname);

        if (!sock->ssl_tls_driver_data)
		{
			eIDClientConnectionEnd((EIDCLIENT_CONNECTION_HANDLE) sock);
            return EID_CLIENT_CONNECTION_SOCKET_ERROR;
        }

        sock->secure = 1;
    }

    *hConnection = (EIDCLIENT_CONNECTION_HANDLE) sock;

	return EID_CLIENT_CONNECTION_ERROR_SUCCESS;
}

extern "C" EID_CLIENT_CONNECTION_ERROR eIDClientConnectionEnd(EIDCLIENT_CONNECTION_HANDLE hConnection)
{
    int ret;
    socket_st * sock = (socket_st *) hConnection;

	if(!sock)
		return EID_CLIENT_CONNECTION_INVALID_HANDLE;
    
    if (sock->secure) {
        ssl_tls_driver.disconnect(sock->ssl_tls_driver_data);
    }
    
    if (sock->hostname)
        free(sock->hostname);
    if (sock->port)
        free(sock->port);
    if (sock->path)
        free(sock->path);
    
    if (sock->fd != -1)
	{
      my_closesocket(sock->fd);
	}
	
	free(sock);

	return EID_CLIENT_CONNECTION_ERROR_SUCCESS;
}

extern "C" EID_CLIENT_CONNECTION_ERROR eIDClientConnectionSendRequest(EIDCLIENT_CONNECTION_HANDLE hConnection, const char* const data, char* const bufResult, int nBufResultLength)
{
    ssize_t ret;
    socket_st *sock;

    sock = (socket_st*) hConnection;
    if (!sock)
        return EID_CLIENT_CONNECTION_INVALID_HANDLE;

    ret = my_send (sock, data, strlen(data));

    ret = my_recv (sock, bufResult, nBufResultLength);

    if (ret < 0)
        return EID_CLIENT_CONNECTION_SOCKET_ERROR;

    /* TODO return the number of bytes received (ret) to caller */

    return EID_CLIENT_CONNECTION_ERROR_SUCCESS;
}

/* 
 * Wrapper around send/recv, which uses ssl/tls if needed
 */
ssize_t my_recv (const socket_st * const sock, void *buffer, size_t buffer_size)
{
    if (sock->secure)
        return ssl_tls_driver.recv (sock->ssl_tls_driver_data, buffer, buffer_size);

    return recv (sock->fd, (char *) buffer, buffer_size, MSG_WAITALL);
}

ssize_t my_send (const socket_st * const sock, const void *const buffer, size_t buffer_size)
{
    ssize_t sent;
    ssize_t ret;

    for (sent = 0; sent < buffer_size; sent += ret) {
        if (sock->secure) {
            ret = ssl_tls_driver.send(sock->ssl_tls_driver_data, buffer, buffer_size);
        } else {
            ret = send (sock->fd, (const char * const) buffer, buffer_size, 0);
        }
        if (ret < 0)
            return ret;
    }

    return sent;
}
