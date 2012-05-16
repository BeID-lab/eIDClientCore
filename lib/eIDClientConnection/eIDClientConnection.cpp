# ifndef __GNUC__
  typedef long ssize_t;
  typedef int  pid_t;
# endif /*!__GNUC__*/

#include <errno.h>
#include <stdlib.h>

#include <stdio.h>
#include <iostream>
#include <sstream>
#include <string>

#include <gnutls/gnutls.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>	// getaddrinfo()
#pragma comment(lib, "ws2_32")
#else
#include <netdb.h>
//#include <errno.h>
#endif

#include "eIDClientConnection.h"

#define MAX_BUF 8192

using namespace std;
/* prototypes */
typedef struct
{
    int fd;
    gnutls_session_t session;
	gnutls_psk_client_credentials_t		pskcred;
    int secure;
    char *hostname;
    char *ip;
    char *port;
	char *path;
    struct addrinfo *ptr;
    struct addrinfo *addr_info;
} socket_st;

void getContent(const char* const data, const int nDataLength, char* const bufResult, const int nBufResultLength);

ssize_t socket_recv (const socket_st * socket, void *buffer, int buffer_size);
ssize_t socket_send (const socket_st * socket, const void *buffer, int buffer_size);
bool socket_open (socket_st * hd, const char *hostname, const char *port, const char *path);
bool socket_connect (const socket_st * hd);
void socket_bye (socket_st * socket);

extern "C" EID_CLIENT_CONNECTION_ERROR eIDClientConnectionStart(P_EIDCLIENT_CONNECTION_HANDLE hConnection,  const char * const hostname, const char * const port, const char * const path, const char * const sid, const char* const pskKey)
{
	*hConnection = 0x00;

#ifdef _WIN32
    WSADATA info;
    if (WSAStartup(MAKEWORD(2,2), &info))
	{
		return EID_CLIENT_CONNECTION_WSA_STARTUP_FAILED;
    }
#endif	// _WIN32

	socket_st*	hd = (socket_st*) malloc(sizeof(socket_st));

	hd->session = 0x00;
	hd->pskcred = 0x00;
	hd->hostname = 0x00;
	hd->ip = 0x00;
	hd->port = 0x00;
	hd->path = 0x00;

    if (! socket_open (hd, hostname, port,path))
	{
		return EID_CLIENT_CONNECTION_DNS_ERROR;
	}

	if ( ! socket_connect(hd))
    {   
        return EID_CLIENT_CONNECTION_SOCKET_ERROR;
    }
    if( pskKey != 0x00 )
	{
		string strPskKey;

	    strPskKey.assign(pskKey);
	
		int status = gnutls_global_init ();
		//Initialize TLS session
		status = gnutls_init (&(hd->session), GNUTLS_CLIENT);
    
		// Pass socket to gnutls
		gnutls_transport_set_ptr (hd->session, (gnutls_transport_ptr_t) hd->fd);
    
		status = gnutls_priority_set_direct (hd->session, "NORMAL:-RSA-PSK:-RSA:-DHE-RSA:-DHE-PSK:+PSK:-DHE-DSS", NULL);
    
		gnutls_datum_t key = {NULL, 0};
		key.data = (unsigned char*) strPskKey.c_str();
		key.size = strPskKey.length();
    
		status = gnutls_psk_allocate_client_credentials (&(hd->pskcred));
		status = gnutls_psk_set_client_credentials (hd->pskcred, sid, &key, GNUTLS_PSK_KEY_HEX);
      
		// double check
		status = gnutls_credentials_set(hd->session, GNUTLS_CRD_PSK, hd->pskcred);
    
		// Perform the TLS handshake
		status = gnutls_handshake (hd->session);
		if (status < 0)
		{
			fprintf (stderr, "*** Handshake failed\n");
			const char * err = gnutls_strerror(status);
			const char * errName = gnutls_strerror_name(status);
			gnutls_perror (status);
			return EID_CLIENT_CONNECTION_TLS_HANDSHAKE_ERROR;
		}
		else
		{
			hd->secure = 1;
			printf ("- Handshake was completed\n");
		}
	}
        
    *hConnection = (EIDCLIENT_CONNECTION_HANDLE) hd;
	return EID_CLIENT_CONNECTION_ERROR_SUCCESS;
}

extern "C" EID_CLIENT_CONNECTION_ERROR eIDClientConnectionEnd(EIDCLIENT_CONNECTION_HANDLE hConnection)
{
	if(hConnection == 0x00)
	{
		return EID_CLIENT_CONNECTION_INVALID_HANDLE;
	}
    
	socket_bye((socket_st*)hConnection);
	
	free(hConnection);
	return EID_CLIENT_CONNECTION_ERROR_SUCCESS;
}

extern "C" EID_CLIENT_CONNECTION_ERROR eIDClientConnectionSendRequest(EIDCLIENT_CONNECTION_HANDLE hConnection, const char* const data, char* const bufResult, const int nBufResultLength)
{
	if(hConnection == 0x00)
	{
		return EID_CLIENT_CONNECTION_INVALID_HANDLE;
	}

	socket_st*	hd = (socket_st*)hConnection;

    int ret;
	int		len = strlen(data);
    string	strData(data,len);
//	const string&	strToSend = strData;

    ret = socket_send (hd, strData.c_str(), strData.length());
    
    if (ret > 0)
    {
		std::cout << std::endl << "send to eIdService --->" << std::endl;
		std::cout << strData.c_str() << std::endl;
    }
//    else
//        handle_error (&hd, ret);
    
        char* recBuffer = (char*)malloc(MAX_BUF + 1);
        memset (recBuffer, 0, MAX_BUF + 1);
        ret = socket_recv (hd, recBuffer, MAX_BUF);
        
        if (ret == 0)
        {
	 		std::cout << std::endl << "- Peer has closed the GnuTLS connection" << std::endl;
        }
//        else if (handle_error (&hd, ret) < 0 && user_term == 0)
//        {
//            console_print( "*** Server has terminated the connection abnormally.\n");
//            retval = 1;
//            break;
//        }
        else if (ret > 0)
        {
	 		std::cout << std::endl << "received from eIdService <---" << std::endl;
			std::cout << recBuffer << std::endl;

			memset(bufResult, 0x00, ret);
			memcpy(bufResult, recBuffer, ret);
        }

		return EID_CLIENT_CONNECTION_ERROR_SUCCESS;
}

/* Functions to manipulate sockets
 */


ssize_t socket_recv (const socket_st * socket, void *buffer, int buffer_size)
{
    int ret;
    
    if (socket->secure)
    {
        do
        {
            ret = gnutls_record_recv (socket->session, buffer, buffer_size);
        }
        while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);
    }
    else
    {        
        do
        {
            ret = recv (socket->fd, (char *)buffer, buffer_size, 0);
        }
        while (ret == -1 && errno == EINTR); //Dont know why we have to do this, but otherwise InitializeFrameworkResponse doesnt get a response with our Server
    }
    
    return ret;
}

ssize_t socket_send (const socket_st * socket, const void *buffer, int buffer_size)
{
    int ret;
    
    if (socket->secure)
    {
        do
        {
            ret = gnutls_record_send (socket->session, buffer, buffer_size);
        }
        while (ret == GNUTLS_E_AGAIN || ret == GNUTLS_E_INTERRUPTED);
    }
    else
    {
//        do
//        {
            ret = send (socket->fd, (const char*) buffer, buffer_size, 0);
 //       }
//        while (ret == -1 && errno == EINTR);
    }
    
//    if (ret > 0 && ret != buffer_size && verbose)
//    {
//        console_print("*** Only sent %d bytes instead of %d.\n", ret, buffer_size);
//    }
    return ret;
}

void socket_bye (socket_st * socket)
{
    int ret;
    if (socket->secure)
    {
        do
            ret = gnutls_bye (socket->session, GNUTLS_SHUT_RDWR);
        while (ret == GNUTLS_E_INTERRUPTED || ret == GNUTLS_E_AGAIN);
        if (ret < 0)
		{
			printf("*** gnutls_bye() error: %s\n", gnutls_strerror (ret));
		}

		gnutls_psk_free_client_credentials(socket->pskcred);

        gnutls_deinit (socket->session);
		gnutls_global_deinit();
        socket->session = NULL;
    }
    
    freeaddrinfo (socket->addr_info);
    socket->addr_info = socket->ptr = NULL;
    
    free(socket->ip);
    free(socket->hostname);
    free(socket->port);
    free(socket->path);
    
    closesocket(socket->fd);
    
    socket->fd = -1;
    socket->secure = 0;
}

bool socket_connect(const socket_st * hd)
{
    int err;
    
    printf("Connecting to '%s:%s'...\n", hd->ip, hd->port);
    
    err = connect (hd->fd, hd->ptr->ai_addr, hd->ptr->ai_addrlen);
    if (err < 0)
    {
        printf("Cannot connect to %s:%s: %s\n", hd->hostname, hd->port, strerror (errno));
        return false;
    }
    return true;
}

bool socket_open (socket_st * hd, const char *hostname, const char *port, const char *path)
{
    struct addrinfo hints, *res, *ptr;
    int sd, err;
    char buffer[MAX_BUF + 1] = { 0 };
    char portname[16] = { 0 };
    
    printf("Resolving '%s'...\n", hostname);
    
    memset (&hints, 0, sizeof (hints));
    hints.ai_socktype = SOCK_STREAM;
    if ((err = getaddrinfo (hostname, port, &hints, &res)))
    {
		
        printf( "Cannot resolve %s:%s: %s\n", hostname, port, gai_strerror (err));
        return false;
    }
    
    sd = -1;
    for (ptr = res; ptr != NULL; ptr = ptr->ai_next)
    {
        sd = socket (ptr->ai_family, ptr->ai_socktype, ptr->ai_protocol);
        if (sd == -1)
            continue;
        
        if ((err = getnameinfo (ptr->ai_addr, ptr->ai_addrlen, buffer, MAX_BUF,
                                portname, sizeof (portname),
                                NI_NUMERICHOST | NI_NUMERICSERV)) != 0)
        {
            printf("getnameinfo(): %s\n", gai_strerror (err));
            freeaddrinfo (res);
            return false;
        }
        break;
    }
    
    if (sd == -1)
    {
//        console_print( "socket(): %s\n", strerror (errno));
        return false;
    }
    
    hd->secure = 0;
    hd->fd = sd;
    hd->hostname = strdup (hostname);
    hd->ip = strdup(buffer);
    hd->port = strdup(portname);
    hd->path = strdup(path);
    hd->ptr = ptr;
    hd->addr_info = res;
    
    return true;
}
