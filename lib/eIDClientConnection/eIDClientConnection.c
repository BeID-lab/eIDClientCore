/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

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

typedef struct {
	char *hostname;
	char *port;
	char *path;
	char *param;	
	char *sid;
	int fd;
	int secure;
	void *ssl_tls_driver_data;
} socket_st;

ssize_t my_recv(const socket_st *const sock, void *buffer, size_t buffer_size);
ssize_t my_send(const socket_st *const sock, const void *const buffer, size_t buffer_size);

int my_connectsocket(const char *const hostname, const char *const port);
int my_closesocket(int s);


struct ssl_tls_driver {
	ssize_t (*send)(const void *const driver_data, const void *const buffer, size_t buffer_size);
	ssize_t (*recv)(const void *const driver_data, void *const buffer, size_t buffer_size);
	void *(*connect)(int fd, const unsigned char *const psk, size_t psk_len, const char *const sid, const char *const hostname);
	void (*disconnect)(const void *const driver_data);
};

struct ssl_tls_driver ssl_tls_driver;

void gnutls_disconnect(const void *const driver_data);
void *gnutls_connect(int fd, const unsigned char *const psk, size_t psk_len, const char *const sid, const char *const hostname);
ssize_t gnutls_recv(const void *const driver_data, void *const buffer, size_t buffer_size);
ssize_t gnutls_send(const void *const driver_data, const void *const buffer, size_t buffer_size);

void parse_url( const char* const url, char* hostname, size_t *nHostnameLength, char* port, size_t *nPortLength, char* path, size_t *nPathLength, char* param, size_t *nParamLength) 
{
	const char *p1 = 0x00;
	const char *p2 = 0x00;
	const char *p3 = 0x00;
	const char *p4 = 0x00;

	if (!url || !*url)
		return;

	memset(hostname, 0x00, *nHostnameLength);
	memset(port, 0x00, *nPortLength);
	memset(path, 0x00, *nPathLength);
	memset(param, 0x00, *nParamLength);

	p1 = strstr(url, "://");
	if (p1)
		p1 += 3;
	else
	   	p1 = url;
	p2 = strchr(p1, ':');
	if (p2)
		p3 = strchr(p2+1, '/');
	p4 = strstr(url, "?");

	if (p2) {
		if( (p2 - p1) < *nHostnameLength)
		  strncpy(hostname,p1, p2 - p1);
		if (p3) {
			if( ( p3 - (p2 + 1)) < *nPortLength)
       		  strncpy(port, p2 + 1, p3 - (p2 + 1));
			if(p4) {
			  if( (p4-p3) < *nPathLength )
     		    strncpy(path,p3, p4-p3);
			} else {
  		      if( strlen(p3) < *nPathLength)
     		    strcpy(path, p3);
			}
		} else {
			if( strlen(p2 + 1) < *nPortLength)
     		  strcpy(port, p2 + 1);
		}

	} else {
		if (p3) {
  		    if( (p3 - p1) < *nHostnameLength)
     		  strncpy(hostname,p1, p3 - p1);
			if(p4) {
			  if( (p4-p3) < *nPathLength)
     		    strncpy(path,p3, p4-p3);
			} else {
  		      if( strlen(p3) < *nPathLength)
     		    strcpy(path, p3);
			}
		} else {
			if( strlen(p1) < *nPortLength)
     		  strcpy(port,p1);
		}
	}
	if (strlen(path) < 1)
     	strcpy(path,"");

	if(p4)
	{
		if( strlen(p4+1) < *nParamLength)
     	  strcpy(param,p4+1);
	}
	
	*nHostnameLength = strlen(hostname);
	*nPortLength = strlen(port);
	*nPathLength = strlen(path);
	*nParamLength = strlen(param);

	return;
}


EID_CLIENT_CONNECTION_ERROR eIDClientConnectionStart(P_EIDCLIENT_CONNECTION_HANDLE hConnection,  const char *const hostname, const char *const port,
		const char *const sid, const char *const pskKey)
{
	socket_st *sock;

	if (0x00 == hConnection) {
		return EID_CLIENT_CONNECTION_SOCKET_ERROR;

	} else {
		*hConnection = 0x00;
	}

	sock = (socket_st *) malloc(sizeof * sock);

	if (0x00 == sock) {
		return EID_CLIENT_CONNECTION_SOCKET_ERROR;
	}

	// initalize sock
	sock->hostname = strdup(hostname);
	sock->port = strdup(port);
	sock->path = 0x00;
	sock->param = 0x00;
	if (sid)
		sock->sid = strdup(sid);
	else
		sock->sid = NULL;
	sock->fd = 0x00;
	sock->secure = 0;
	sock->ssl_tls_driver_data = 0x00;

	if (!sock->hostname || !sock->port) {
		eIDClientConnectionEnd((EIDCLIENT_CONNECTION_HANDLE) sock);
		return EID_CLIENT_CONNECTION_SOCKET_ERROR;
	}

	/* TODO integration of user driven configuration to change SSL/TLS driver */
	ssl_tls_driver.recv = gnutls_recv;
	ssl_tls_driver.send = gnutls_send;
	ssl_tls_driver.connect = gnutls_connect;
	ssl_tls_driver.disconnect = gnutls_disconnect;
	sock->fd = my_connectsocket(sock->hostname, sock->port);

	if (sock->fd == -1) {
		eIDClientConnectionEnd((EIDCLIENT_CONNECTION_HANDLE) sock);
		return EID_CLIENT_CONNECTION_SOCKET_ERROR;
	}

	if (sock->port && strcmp(sock->port, "80") != 0 && strcmp(sock->port, "8080") != 0) {
		sock->ssl_tls_driver_data = ssl_tls_driver.connect(sock->fd, (unsigned char *) pskKey, pskKey ? strlen(pskKey) : 0, sid, hostname);
		sock->secure = 1;
	}

	*hConnection = (EIDCLIENT_CONNECTION_HANDLE) sock;
	return EID_CLIENT_CONNECTION_ERROR_SUCCESS;
}

EID_CLIENT_CONNECTION_ERROR eIDClientConnectionStart2(P_EIDCLIENT_CONNECTION_HANDLE hConnection, const char *const url, const char *const pskKey)
{
	char hostname[100];
	char port[100];
	char path[100];
	char param[1000];
	char sid[100];
	size_t nHostnameLength = sizeof(hostname);	
	size_t nPortLength = sizeof(port);
	size_t nPathLength = sizeof(path);
	size_t nParamLength = sizeof(param);
	socket_st* sock = 0x00;
	const char *p1 = 0x00;
	const char *p2 = 0x00;

	// FIXME add a lenght to url
	parse_url(url, hostname, &nHostnameLength, port, &nPortLength, path, &nPathLength, param, &nParamLength);

	p1 = strstr(param, "sessionid=");
	if(p1)
	{
		p2 = strstr(p1, "&");
		if(p2)
		{
			if(p2)
			{
  			  if( (p2-p1+10) <  sizeof(sid) )
			    strncpy(sid, p1+10, p2-p1-10);
			}
		}
		else
		{
 		  if( strlen(p1+10) < sizeof(sid))
		    strcpy(sid, p1+10);
		}
	}

	 if( EID_CLIENT_CONNECTION_SOCKET_ERROR == eIDClientConnectionStart(hConnection,  hostname, port, sid, pskKey) )
	 {
		 return EID_CLIENT_CONNECTION_SOCKET_ERROR;
	 }
	 
	 sock = (socket_st*) *hConnection;

	if (!sock)
		return EID_CLIENT_CONNECTION_INVALID_HANDLE;

	sock->path = strdup(path);
	sock->param = strdup(param);

	return EID_CLIENT_CONNECTION_ERROR_SUCCESS;
}

EID_CLIENT_CONNECTION_ERROR eIDClientConnectionEnd(EIDCLIENT_CONNECTION_HANDLE hConnection)
{
	socket_st *sock = (socket_st *) hConnection;

	if (!sock)
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

	if (sock->param)
		free(sock->param);

	if (sock->sid)
		free(sock->sid);

	if (sock->fd != -1) {
		my_closesocket(sock->fd);
	}

	free(sock);
	return EID_CLIENT_CONNECTION_ERROR_SUCCESS;
}

EID_CLIENT_CONNECTION_ERROR eIDClientConnectionSendRequest(EIDCLIENT_CONNECTION_HANDLE hConnection, const char *const data, const size_t dataLength, char *const bufResult, size_t *nBufResultLength)
{
	ssize_t ret;
	socket_st *sock;
	sock = (socket_st *) hConnection;

	if (!sock || !nBufResultLength)
		return EID_CLIENT_CONNECTION_INVALID_HANDLE;

    /* HTTP requires sockets to be closed after each successfull transmit. So
     * we have to reconnect here. */
	if (0x00 == sock->secure && (sock->port && (
					strcmp(sock->port, "80") == 0
					|| strcmp(sock->port, "8080") == 0))) {
		my_closesocket(sock->fd);
		sock->fd = my_connectsocket(sock->hostname, sock->port);

        if (sock->fd == -1) {
            eIDClientConnectionEnd((EIDCLIENT_CONNECTION_HANDLE) sock);
            return EID_CLIENT_CONNECTION_SOCKET_ERROR;
        }
	}

	memset(bufResult, 0x00, *nBufResultLength);
	ret = my_send(sock, data, dataLength);
	ret = my_recv(sock, bufResult, *nBufResultLength);

	if (ret < 0) {
		return EID_CLIENT_CONNECTION_SOCKET_ERROR;
	}

	*nBufResultLength = ret;

	/* TODO return the number of bytes received (ret) to caller */
	return EID_CLIENT_CONNECTION_ERROR_SUCCESS;
}

#if !defined(WIN32)
// _itoa isn't standard compliant :( I think to define _itoa is the best way to
// solve this problem.
#include <stdio.h>
char *_itoa(int value, char *str, int base)
{
	switch (base) {
		case 8:
			sprintf(str, "%o", value);
			break;
		case 10:
			sprintf(str, "%d", value);
			break;
		case 16:
			sprintf(str, "%x", value);
			break;
	}

	return str;
}

#endif

EID_CLIENT_CONNECTION_ERROR eIDClientConnectionSendReceivePAOS(EIDCLIENT_CONNECTION_HANDLE hConnection, const char *const data, const size_t dataLength, char *const bufResult, size_t *nBufResultLength)
{
	ssize_t ret;
	socket_st *sock = (socket_st *) hConnection;
	char buf[10000];
	char result[10000];
	size_t bufLength = 0x00;
	size_t resultLength = 10000;
	size_t contentLength = 0x00;
	char* p1 = 0x00;
	char* p2 = 0x00;
	char p3[100];
	char p4[100];
	char* p5 = 0x00;


	if (!sock || !nBufResultLength)
		return EID_CLIENT_CONNECTION_INVALID_HANDLE;
	
	memset(buf, 0x00, sizeof buf);
	memset(result, 0x00, sizeof result);
	memset(p3, 0x00, sizeof p3);
	memset(p4, 0x00, sizeof p4);

	_itoa((int)dataLength, p4, 10);

	strcat(buf, "POST ");
	if(sock->path)
	  strcat(buf, sock->path);
	if(sock->param)
	{
	  strcat(buf, "?");
	  strcat(buf, sock->param);
	}
	strcat(buf, " HTTP/1.1\r\n"); 

	strcat(buf, "Content-Length: "); 
	strcat(buf, p4); 
	strcat(buf, "\r\n");

	strcat(buf, "Accept: text/html; application/vnd.paos+xml\r\n"); 
	strcat(buf, "PAOS: ver=\"urn:liberty:2006-08\";http://www.bsi.bund.de/ecard/api/1.0/PAOS/GetNextCommand\r\n"); 

	strcat(buf, "Host: "); 
	strcat(buf, sock->hostname); 
	strcat(buf, ":"); 
	strcat(buf, sock->port); 
	strcat(buf, "\r\n");
	strcat(buf, "\r\n");

	if(dataLength > 0)
	{
		strcat(buf, data);
	}
	bufLength = strlen(buf);


	if( EID_CLIENT_CONNECTION_ERROR_SUCCESS == eIDClientConnectionSendRequest(hConnection, buf, bufLength, result, &resultLength) )
	{
		p1 = strstr(result, "Content-Length:");
		if (!p1)
			return EID_CLIENT_CONNECTION_SOCKET_ERROR;
		p1 += strlen("Content-Length:");
		p2 = strstr(p1,"\n");
		if (!p2)
			return EID_CLIENT_CONNECTION_SOCKET_ERROR;
		strncpy(p3, p1, p2-p1);
		contentLength = atoi(p3);

		p5 = strstr(result, "\r\n\r\n");
		if (!p5)
			return EID_CLIENT_CONNECTION_SOCKET_ERROR;
		p5 += strlen("\r\n\r\n");
		strncpy(bufResult, p5, contentLength);

		*nBufResultLength = strlen(bufResult);
	}
	else
	{
		return EID_CLIENT_CONNECTION_SOCKET_ERROR;
	}

	/* TODO return the number of bytes received (ret) to caller */
	return EID_CLIENT_CONNECTION_ERROR_SUCCESS;
}

/*
 * Wrapper around send/recv, which uses ssl/tls if needed
 */
ssize_t my_recv(const socket_st *const sock, void *buffer, size_t buffer_size)
{
	ssize_t received = 0;
	ssize_t r = 0;
	ssize_t available = buffer_size;

	if (!buffer_size || !buffer )
		return 0;

	do {
		if (sock->secure)
			r = ssl_tls_driver.recv(sock->ssl_tls_driver_data, buffer, available);
		else
			r = recv(sock->fd, buffer, available, 0);

		if (r >= 0) {
			received += r;
			buffer += r;
			available -= r;
		} else
			break;
	} while (available > 0 && /* FIXME should use GNUTLS_NONBLOCK instead */ r == 9000);

	return received ? received : r;
}

ssize_t my_send(const socket_st *const sock, const void *const buffer, size_t buffer_size)
{
	size_t sent;
	ssize_t ret;

	for (sent = 0; sent < buffer_size; sent += ret) {
		if (sock->secure) {
			ret = ssl_tls_driver.send(sock->ssl_tls_driver_data, buffer, buffer_size);

		} else {
			ret = send(sock->fd, buffer, buffer_size, 0);
		}

		if (ret < 0)
			return ret;
	}

	return sent;
}
