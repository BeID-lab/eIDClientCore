/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#if HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
typedef int ssize_t;
#pragma comment(lib, "ws2_32")
#else
#include <sys/socket.h>
#include <sys/types.h>
#include <pthread.h>
#endif

#include <debug.h>
#include "eIDClientConnection.h"

#ifdef _DEBUG_TLS
#define _DEBUG
#endif

typedef enum {
	EIDCLIENT_CONNECTION_MODE_RAW,
	EIDCLIENT_CONNECTION_MODE_HTTP
} ConnectionMode;

/* Stores the Connection-Parameters independent of the type */
typedef struct {
	void * connectionHandle;
	ConnectionMode connectionMode;
} connection_st;

EID_CLIENT_CONNECTION_ERROR eIDClientConnectionEndRaw(void *connectionHandle);
EID_CLIENT_CONNECTION_ERROR eIDClientConnectionEndHttp(void *connectionHandle);
EID_CLIENT_CONNECTION_ERROR eIDClientConnectionTansceiveRaw(void *connectionHandle, const char *const data, const size_t dataLength, char *const bufResult, size_t *nBufResultLength);
EID_CLIENT_CONNECTION_ERROR eIDClientConnectionTransceiveHTTP(void *connectionHandle, const char *const data, const size_t dataLength, char *const bufResult, size_t *nBufResultLength);

ssize_t my_recv(int sock, void *buffer, size_t buffer_size);
ssize_t my_send(int sock, const void *const buffer, size_t buffer_size);
int my_connectsocket(const char *const hostname, const char *const port);
int my_closesocket(int s);

/*
 * Generic Operations
 */

//! Has to be called to close the Connection
/*!
\param hConnection The connectionHandle previously used
\return EID_CLIENT_CONNECTION_ERROR_SUCCESS on success
*/
EID_CLIENT_CONNECTION_ERROR eIDClientConnectionEnd(EIDCLIENT_CONNECTION_HANDLE hConnection)
{
	connection_st * conn = (connection_st *) hConnection;
	EID_CLIENT_CONNECTION_ERROR r = EID_CLIENT_CONNECTION_ERROR_SUCCESS;

	if(conn) {
		switch (conn->connectionMode) {
			case EIDCLIENT_CONNECTION_MODE_RAW:
				r = eIDClientConnectionEndRaw(conn->connectionHandle);
				break;
			case EIDCLIENT_CONNECTION_MODE_HTTP:
				r = eIDClientConnectionEndHttp(conn->connectionHandle);
				break;
			default:
				break;
		}
		free(conn);
	}

	return r;
}

EID_CLIENT_CONNECTION_ERROR eIDClientConnectionTransceive(EIDCLIENT_CONNECTION_HANDLE hConnection, const char *const data, const size_t dataLength, char *const bufResult, size_t *nBufResultLength)
{
	connection_st *conn = (connection_st*) hConnection;
	EID_CLIENT_CONNECTION_ERROR rVal = EID_CLIENT_CONNECTION_INVALID_HANDLE;

	if (conn) {
		switch(conn->connectionMode) {
			case EIDCLIENT_CONNECTION_MODE_RAW:
				rVal = eIDClientConnectionTansceiveRaw(conn->connectionHandle, data, dataLength, bufResult, nBufResultLength);
				break;
			case EIDCLIENT_CONNECTION_MODE_HTTP:
				rVal = eIDClientConnectionTransceiveHTTP(conn->connectionHandle, data, dataLength, bufResult, nBufResultLength);
				break;
			default:
				rVal = EID_CLIENT_CONNECTION_INVALID_HANDLE;
		}
	}

	return rVal;
}



/*
 * Operations on the HTTP layer
 */

#ifdef HAVE_LIBCURL
#include <curl/curl.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>
typedef struct {
	CURL * curlHandle;
	enum HttpHeaderInclusion includeHeader;
} http_st;

static char * psk_identity = "Client_identity"; /*Default*/
static char * psk_key;
/*Only globally initialize libcurl on the first call*/
static int numOfHttpHandles = 0;

//Originally http://curl.haxx.se/libcurl/c/CURLOPT_DEBUGFUNCTION.html 
static void curl_dump(const char *text,   FILE *stream, unsigned char *ptr, size_t size) 
{   
	size_t i;
	size_t c;
	unsigned int width=0x10;

  	fprintf(stream, "%s, %10.10ld bytes (0x%8.8lx)n", text, (long)size, (long)size);

  	for(i=0; i<size; i+= width) {   
		fprintf(stream, "%4.4lx: ", (long)i);
  		/* show hex to the left */   
		for(c = 0; c < width; c++) {   
			if(i+c < size)   
				fprintf(stream, "%02x ", ptr[i+c]);   
			else   
				fputs(" ", stream);   
		}

		/* show data on the right */   
		for(c = 0; (c < width) && (i+c < size); c++) 
			fputc( (ptr[i+c]>=0x20) && (ptr[i+c]<0x80) ? ptr[i+c] : '.', stream);

  		fputc('\n', stream); /* newline */   
	} 
}

//Originally from http://curl.haxx.se/libcurl/c/CURLOPT_DEBUGFUNCTION.html 
static int curl_my_trace(CURL *handle, curl_infotype type, char *data, size_t size,   void *userp) 
{   
	const char *text;
	(void)handle; /* prevent compiler warning */

  	switch (type) {   
		case CURLINFO_TEXT:   
			fprintf(stderr, "== Info: %s", data);
		default: /* in case a new one is introduced to shock us */   
			return 0;

		case CURLINFO_HEADER_OUT:   
			text = "=> Send header";   
			break;   
		case CURLINFO_DATA_OUT:   
			text = "=> Send data";   
			break;
		case CURLINFO_SSL_DATA_OUT:   
			text = "=> Send SSL data";
			break;   
		case CURLINFO_HEADER_IN:   
			text = "<= Recv header";   
			break;   
		case CURLINFO_DATA_IN:   
			text = "<= Recv data";   
			break;
		case CURLINFO_SSL_DATA_IN:   
			text = "<= Recv SSL data";   
			break;   
	}

  	curl_dump(text, stderr, (unsigned char *)data, size);   
	return 0; 
}

#if _WIN32
static HANDLE * lockarray;
static void lock_callback(int mode, int type,const char *file, int line)
{
  if (mode & CRYPTO_LOCK) {
	  WaitForSingleObject(lockarray[type], INFINITE);
  }
  else {
    ReleaseMutex(lockarray[type]);
  }
}
 
static unsigned long thread_id(void)
{
  unsigned long ret;
  ret = GetCurrentThreadId();
  return(ret);
}
 
static void init_locks(void)
{
  int i;
 
  lockarray=(HANDLE *)OPENSSL_malloc(CRYPTO_num_locks() *
                                            sizeof(HANDLE));
  for (i=0; i<CRYPTO_num_locks(); i++) {
	lockarray[i] = CreateMutex( 
			NULL,              // default security attributes
			FALSE,             // initially not owned
			NULL);			// No Name

  }
 
  CRYPTO_set_locking_callback((void (*)(int,int,const char *,int))lock_callback);
  //CRYPTO_set_id_callback((unsigned long (*)())thread_id);
}
 
static void kill_locks(void)
{
  int i;
 
  CRYPTO_set_locking_callback(NULL);
  for (i=0; i<CRYPTO_num_locks(); i++)
	  CloseHandle(lockarray[i]);
 
  OPENSSL_free(lockarray);
}

#else
/*Originally from http://curl.haxx.se/libcurl/c/threaded-ssl.html */
static pthread_mutex_t *lockarray;
static void lock_callback(int mode, int type, char *file, int line)
{
  if (mode & CRYPTO_LOCK) {
    pthread_mutex_lock(&(lockarray[type]));
  }
  else {
    pthread_mutex_unlock(&(lockarray[type]));
  }
}
 
static unsigned long thread_id(void)
{
  unsigned long ret;
  ret=(unsigned long)pthread_self();
  return(ret);
}
 
static void init_locks(void)
{
  int i;
 
  lockarray=(pthread_mutex_t *)OPENSSL_malloc(CRYPTO_num_locks() *
                                            sizeof(pthread_mutex_t));
  for (i=0; i<CRYPTO_num_locks(); i++) {
    pthread_mutex_init(&(lockarray[i]),NULL);
  }
 
  /*CRYPTO_set_id_callback((unsigned long (*)())thread_id);*/
  CRYPTO_set_locking_callback((void (*)())lock_callback);
}
 
static void kill_locks(void)
{
  int i;
 
  CRYPTO_set_locking_callback(NULL);
  for (i=0; i<CRYPTO_num_locks(); i++)
    pthread_mutex_destroy(&(lockarray[i]));
 
  OPENSSL_free(lockarray);
}
#endif


static unsigned int psk_client_cb(SSL *ssl, const char *hint, char *identity,
	unsigned int max_identity_len, unsigned char *psk,
	unsigned int max_psk_len)
{
	unsigned int psk_len = 0;
	int ret;
	BIGNUM *bn=NULL;

	/* lookup PSK identity and PSK key based on the given identity hint here */
	ret = BIO_snprintf(identity, max_identity_len, "%s", psk_identity);
	if (ret < 0 || (unsigned int)ret > max_identity_len)
		return 0;

	ret=BN_hex2bn(&bn, psk_key);
	if (!ret)
	{
		if (bn)
			BN_free(bn);
		return 0;
	}

	if ((unsigned int)BN_num_bytes(bn) > max_psk_len)
	{
		BN_free(bn);
		return 0;
	}

	psk_len=BN_bn2bin(bn, psk);
	BN_free(bn);
	if (psk_len == 0)
		return 0;

	return psk_len;
}

CURLcode sslctxfun(CURL *curl, void *sslctx, void *parm)
{
	SSL_CTX * ctx = (SSL_CTX *) sslctx ;
	if(psk_key)
	{
		SSL_CTX_set_psk_client_callback(ctx, psk_client_cb);
	}
	return CURLE_OK;
}

struct MemoryStruct {
	char *memory;
	size_t size;
};

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	struct MemoryStruct *mem = (struct MemoryStruct *)userp;

	mem->memory = realloc(mem->memory, mem->size + realsize + 1);
	if(mem->memory == NULL) {
		/* out of memory! */ 
		printf("not enough memory (realloc returned NULL)\n");
		return 0;
	}

	memcpy(&(mem->memory[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->memory[mem->size] = 0;

	return realsize;
}
#endif

EID_CLIENT_CONNECTION_ERROR eIDClientConnectionStartHttp(P_EIDCLIENT_CONNECTION_HANDLE hConnection, const char *const url, const char *const sid, const char *const psk, enum HttpHeaderInclusion includeHeader, enum HttpRedirect httpRedirect)
{
#ifdef HAVE_LIBCURL
	CURL *curl = 0x00;
	http_st * httpConn = 0x00;
	struct curl_slist * header = 0x00;
	CURLcode curlVal = CURLE_OK;
	connection_st * conn = 0x00; /*Stores the Connection-Parameters independent of the type*/

	if (0x00 == hConnection || 0x00 == url || '\0' == *url ) {
		return EID_CLIENT_CONNECTION_SOCKET_ERROR;
	} else {
		*hConnection = 	0x00;
	}

	conn = (connection_st *) malloc(sizeof * conn);
	if (0x00 == conn) {
		return EID_CLIENT_CONNECTION_SOCKET_ERROR;
	}

	/*Not atomic -> not threadsafe!*/
	if(1 == ++numOfHttpHandles)
	{
		//init_locks();
		curlVal = curl_global_init(CURL_GLOBAL_DEFAULT);
	}
	curl = curl_easy_init();

	if(!curl)
	{
		curl_global_cleanup();
		return EID_CLIENT_CONNECTION_CURL_ERROR;
	}

	conn->connectionMode = EIDCLIENT_CONNECTION_MODE_HTTP;
	httpConn = (http_st*) malloc(sizeof * httpConn);
	conn->connectionHandle = httpConn;
	httpConn->curlHandle = curl;
	httpConn->includeHeader = includeHeader;

	eCardCore_info(DEBUG_LEVEL_PAOS, "Initialize HTTP-Connection with URL %s", url);

	curlVal = curl_easy_setopt(curl, CURLOPT_URL, url);
	if(CURLE_OK != curlVal)
		return EID_CLIENT_CONNECTION_CURL_ERROR;
	
	//Reads cookies from file
	curl_easy_setopt(curl, CURLOPT_COOKIEFILE, EIDCC_COOKIE_FILE);
	//Writes cookies to file
	curl_easy_setopt(curl, CURLOPT_COOKIEJAR, EIDCC_COOKIE_FILE);

#ifdef SKIP_PEER_VERIFICATION
	curlVal = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	if(CURLE_OK != curlVal)
		return EID_CLIENT_CONNECTION_CURL_ERROR;
#endif

#ifdef SKIP_HOSTNAME_VERIFICATION
	curlVal = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	if(CURLE_OK != curlVal)
		return EID_CLIENT_CONNECTION_CURL_ERROR;
#endif

	/*Set Useragent because its required by some servers*/
	curlVal = curl_easy_setopt(curl, CURLOPT_USERAGENT, "eIDClientCore/1.1");
	if(CURLE_OK != curlVal)
		return EID_CLIENT_CONNECTION_CURL_ERROR;

	if(USED_DEBUG_LEVEL & DEBUG_LEVEL_SSL){
		curl_easy_setopt(curl, CURLOPT_DEBUGFUNCTION, curl_my_trace);
		/* the DEBUGFUNCTION has no effect until we enable VERBOSE */
		curlVal = curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	}

	if(httpRedirect == FollowHttpRedirect) {
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	}
	
	/*Required for multithreading*/
	curlVal |= curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1);
	if(CURLE_OK != curlVal)
		return EID_CLIENT_CONNECTION_CURL_ERROR;

	/*Setup SSL-Callback for Presharedkey*/
	curlVal |= curl_easy_setopt(curl, CURLOPT_SSL_CTX_FUNCTION, sslctxfun);
	if(CURLE_OK != curlVal)
		return EID_CLIENT_CONNECTION_CURL_ERROR;

	curlVal = curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
	if(CURLE_OK != curlVal)
		return EID_CLIENT_CONNECTION_CURL_ERROR;

	/* The following cipher suites are supported by our OpenSSL:
	 * OpenSSL_1_0_2-stable/apps/openssl ciphers 'RSAPSK' -v
	 * RSA-PSK-AES256-CBC-SHA  SSLv3 Kx=RSAPSK   Au=RSA  Enc=AES(256)  Mac=SHA1
	 * RSA-PSK-3DES-EDE-CBC-SHA SSLv3 Kx=RSAPSK   Au=RSA  Enc=3DES(168) Mac=SHA1
	 * RSA-PSK-AES128-CBC-SHA  SSLv3 Kx=RSAPSK   Au=RSA  Enc=AES(128)  Mac=SHA1
	 * RSA-PSK-RC4-SHA         SSLv3 Kx=RSAPSK   Au=RSA  Enc=RC4(128)  Mac=SHA1
	 * 
	 * I would not recommend RC4 due to security reasons.
	 */
	if(psk != NULL){
		curlVal = curl_easy_setopt(curl, CURLOPT_SSL_CIPHER_LIST, "RSA-PSK-AES256-CBC-SHA384:RSA-PSK-AES128-CBC-SHA256:RSA-PSK-AES256-CBC-SHA:RSA-PSK-AES128-CBC-SHA:RSA-PSK-3DES-EDE-CBC-SHA");
	} else {
		curlVal = curl_easy_setopt(curl, CURLOPT_SSL_CIPHER_LIST, "HIGH");
	}
	if(CURLE_OK != curlVal)
		return EID_CLIENT_CONNECTION_CURL_ERROR;

	header = curl_slist_append(header, "Expect:");
	curlVal = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header);
	if(CURLE_OK != curlVal)
		return EID_CLIENT_CONNECTION_CURL_ERROR;

	if(curlVal != CURLE_OK)
	{
		eCardCore_warn(DEBUG_LEVEL_PAOS, "curl_easy_setopt() failed: %s", curl_easy_strerror(curlVal));
		return EID_CLIENT_CONNECTION_CURL_ERROR;
	}

	if(sid)
	{
		psk_identity = (char*) malloc(strlen(sid)+1);
		strcpy(psk_identity, sid);
		printf("sid: %s\n", sid);
	}

	if(psk)
	{
		psk_key = (char*) malloc(strlen(psk)+1);
		strcpy(psk_key, psk);
		printf("psk: %s\n", psk);
	}

	*hConnection = conn;

	return EID_CLIENT_CONNECTION_ERROR_SUCCESS;
#else
	return EID_CLIENT_CONNECTION_MODE_ERROR;
#endif
}

EID_CLIENT_CONNECTION_ERROR eIDClientConnectionEndHttp(void *connectionHandle)
{
#ifdef HAVE_LIBCURL
	CURL * curlHandle = 0x00;
	http_st *httpConn = connectionHandle;

	if(!httpConn)
		return EID_CLIENT_CONNECTION_INVALID_HANDLE;

	curlHandle = httpConn->curlHandle;
	if(curlHandle)
		curl_easy_cleanup(curlHandle);

	/*Not atomic -> Not threadsafe!*/
	if(0 == --numOfHttpHandles)
	{
		curl_global_cleanup();
		//kill_locks();
	}
	free(httpConn);

	psk_key = 0x00;

	return EID_CLIENT_CONNECTION_ERROR_SUCCESS;
#else
	return EID_CLIENT_CONNECTION_MODE_ERROR;
#endif
}

EID_CLIENT_CONNECTION_ERROR eIDClientConnectionTransceiveHTTP(void *connectionHandle, const char *const data, const size_t dataLength, char *const bufResult, size_t *nBufResultLength)
{
#ifdef HAVE_LIBCURL
	http_st * hConnection = connectionHandle;
	CURL * curl = hConnection->curlHandle;
	CURLcode curlVal = CURLE_OK;
	struct MemoryStruct header;
	struct MemoryStruct body;
	header.memory = (char*) malloc(1);
	header.size = 0;
	body.memory = (char*) malloc(1);
	body.size = 0;
	
	/* For debugging curl: Display the url, which curl is going to use
	char *urlp;
	curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &urlp);
	if(urlp != NULL)
		printf("curl url: <<%s>>\n", urlp);
	*/

	//if(dataLength > 0 && data[0] == '<') /* SAML1 don't working */
	if(dataLength > 0 )
	{
		curlVal = curl_easy_setopt (curl, CURLOPT_POST, 1);
		curlVal = curl_easy_setopt (curl, CURLOPT_POSTFIELDS, data);
		curlVal = curl_easy_setopt (curl, CURLOPT_POSTFIELDSIZE, dataLength);
	}

	/* send all data to this function  */
	curlVal = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);

	/* we pass our 'chunk' struct to the callback function */
	curlVal = curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&body);

	if(hConnection->includeHeader == GetHttpHeader)
	{
		curlVal = curl_easy_setopt(curl, CURLOPT_WRITEHEADER, (void *)&header);
	}

	eCardCore_debug(DEBUG_LEVEL_PAOS, "Http Send: %.*s", dataLength, data);

	/* Perform the request*/
	curlVal = curl_easy_perform(curl);

	if(curlVal == CURLE_COULDNT_RESOLVE_HOST)
	{
		eCardCore_warn(DEBUG_LEVEL_PAOS, "curl_easy_perform() failed: %s \r\n Retrying..", curl_easy_strerror(curlVal));
		curlVal = curl_easy_perform(curl);
	}

	/* Check for errors */
	if(curlVal != CURLE_OK)
	{
		eCardCore_warn(DEBUG_LEVEL_PAOS, "curl_easy_perform() failed: %s", curl_easy_strerror(curlVal));
		return EID_CLIENT_CONNECTION_CURL_ERROR;
	}

	/*We should definitely improve the Memory Management..*/
	if(body.size + header.size >= *nBufResultLength)
	{
		return EID_CLIENT_CONNECTION_BUFF_TOO_SMALL_ERROR | (body.size + header.size + 1);
	}

	*nBufResultLength = header.size + body.size;

	if(header.size && header.memory)
	{
		memcpy(bufResult, header.memory, header.size);
	}

	if(body.size && body.memory)
	{
		memcpy(bufResult+header.size, body.memory, body.size);
	}

	bufResult[*nBufResultLength] = '\0';

	eCardCore_debug(DEBUG_LEVEL_PAOS, "Http Receive: %s", bufResult);

	/*If realloc fails, it returns a nullptr, which can be handled by free*/
	free(body.memory);
	free(header.memory);

	/* cleanup of connection takes place in eIDClientConnectionEnd */ 
	return EID_CLIENT_CONNECTION_ERROR_SUCCESS;
#else
	return EID_CLIENT_CONNECTION_MODE_ERROR;
#endif
}

EID_CLIENT_CONNECTION_ERROR eIDClientConnectionTransceivePAOS(EIDCLIENT_CONNECTION_HANDLE hConnection, const char *const data, const size_t dataLength, char *const bufResult, size_t *nBufResultLength)
{
#ifdef HAVE_LIBCURL
	connection_st *conn = (connection_st*) hConnection;
	http_st * httpConn = 0x00;
	CURL * curl = 0x00;
	struct curl_slist *header = NULL;
	CURLcode curlVal = CURLE_OK;
	EID_CLIENT_CONNECTION_ERROR rVal = EID_CLIENT_CONNECTION_ERROR_SUCCESS;

	if (!conn || !nBufResultLength || !conn->connectionHandle)
		return EID_CLIENT_CONNECTION_INVALID_HANDLE;

	if(conn->connectionMode != EIDCLIENT_CONNECTION_MODE_HTTP)
		return EID_CLIENT_CONNECTION_MODE_ERROR;

	httpConn = (http_st*)conn->connectionHandle;
	curl = httpConn->curlHandle;

	header = curl_slist_append(header, "Content-Type: application/vnd.paos+xml");
	header = curl_slist_append(header, "Accept: text/html; application/vnd.paos+xml");
	header = curl_slist_append(header, "PAOS: ver=\"urn:liberty:2006-08\";http://www.bsi.bund.de/ecard/api/1.0/PAOS/GetNextCommand");
	header = curl_slist_append(header, "Expect:");
	curlVal = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, header);

	eCardCore_debug(DEBUG_LEVEL_PAOS, "Send PAOS: %s", data);
	rVal = eIDClientConnectionTransceiveHTTP(httpConn, data, dataLength, bufResult, nBufResultLength);
	eCardCore_debug(DEBUG_LEVEL_PAOS, "Receive PAOS: %s", bufResult);

	return rVal;
#else
	return EID_CLIENT_CONNECTION_MODE_ERROR;
#endif
}



/*
 * Operations on a raw socket 
 */

EID_CLIENT_CONNECTION_ERROR eIDClientConnectionStartRaw(P_EIDCLIENT_CONNECTION_HANDLE hConnection, const char *const hostname, const char *const port, const char *const sid, const char *const pskKey)
{
	connection_st *connection = 0x00;
	int sock;

	sock = my_connectsocket(hostname, port);
	if (sock == -1) {
		return EID_CLIENT_CONNECTION_SOCKET_ERROR;
	}

	connection = (connection_st *) malloc(sizeof * connection);
	if (0x00 == connection) {
		my_closesocket(sock);
		return EID_CLIENT_CONNECTION_SOCKET_ERROR;
	}
	connection->connectionHandle = (void *) sock;
	connection->connectionMode = EIDCLIENT_CONNECTION_MODE_RAW;

	*hConnection = connection;

	return EID_CLIENT_CONNECTION_ERROR_SUCCESS;
}

EID_CLIENT_CONNECTION_ERROR eIDClientConnectionEndRaw(void *connectionHandle)
{
	int sock = (int) connectionHandle;
	EID_CLIENT_CONNECTION_ERROR r = EID_CLIENT_CONNECTION_ERROR_SUCCESS;
	if (my_closesocket(sock) == -1) {
		r = EID_CLIENT_CONNECTION_SOCKET_ERROR;
	}
	return r;
}

EID_CLIENT_CONNECTION_ERROR eIDClientConnectionTansceiveRaw(void *connectionHandle, const char *const data, const size_t dataLength, char *const bufResult, size_t *nBufResultLength)
{
	ssize_t ret;
	int sock = (int) connectionHandle;

	if (!nBufResultLength)
		return EID_CLIENT_CONNECTION_INVALID_HANDLE;

	ret = my_send(sock, data, dataLength);
	if (ret < 0) {
		return EID_CLIENT_CONNECTION_SOCKET_ERROR;
	}

	ret = my_recv(sock, bufResult, *nBufResultLength);
	if (ret < 0) {
		return EID_CLIENT_CONNECTION_SOCKET_ERROR;
	}

	*nBufResultLength = ret;

	return EID_CLIENT_CONNECTION_ERROR_SUCCESS;
}



/*
 * Wrapper around send/recv
 */

ssize_t my_recv(int sock, void *buffer, size_t buffer_size)
{
	ssize_t received = 0;
	ssize_t r = 0;
	ssize_t available = buffer_size;
	char *buf = buffer;

	if (!buffer_size || !buffer )
		return 0;

	do {
		r = recv(sock, buf, available, 0);

		if (r >= 0) {
			received += r;
			buf += r;
			available -= r;
		} else {
			//Errormsg?
			break;
		}
	} while (available > 0);

	return received ? received : r;
}

ssize_t my_send(int sock, const void *const buffer, size_t buffer_size)
{
	size_t sent;
	ssize_t ret;
	const char *buf = (const char *) buffer;

	for (sent = 0; sent < buffer_size; sent += ret) {
		ret = send(sock, buf+sent, buffer_size-sent, 0);

		if (ret < 0)
			return ret;
	}

	return sent;
}
