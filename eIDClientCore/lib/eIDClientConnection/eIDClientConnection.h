/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 *
 * This Lib can only handle 1 Connection at a time
 * -> Its also not threadsafe
 * Reasons (so far): curl_global_init in Startfunctions,
 * global PSK and Identity Variables
 */

#if !defined(__EIDCLIENTCONNECTION_INCLUDED__)
#define __EIDCLIENTCONNECTION_INCLUDED__

typedef void *EIDCLIENT_CONNECTION_HANDLE;
typedef EIDCLIENT_CONNECTION_HANDLE *P_EIDCLIENT_CONNECTION_HANDLE;

typedef unsigned long EID_CLIENT_CONNECTION_ERROR;
#define EID_CLIENT_CONNECTION_INFO					 0x41000000
#define EID_CLIENT_CONNECTION_WARN					 0x42000000
#define EID_CLIENT_CONNECTION_ERRO					 0x43000000

#define EID_CLIENT_CONNECTION_ERROR_SUCCESS              0x00000000

#define EID_CLIENT_CONNECTION_SOCKET_ERROR               EID_CLIENT_CONNECTION_ERRO + 0x00000001
#define EID_CLIENT_CONNECTION_TLS_HANDSHAKE_ERROR        EID_CLIENT_CONNECTION_ERRO + 0x00000002
#define EID_CLIENT_CONNECTION_WSA_STARTUP_FAILED         EID_CLIENT_CONNECTION_ERRO + 0x00000003
#define EID_CLIENT_CONNECTION_INVALID_HANDLE             EID_CLIENT_CONNECTION_ERRO + 0x00000004
#define EID_CLIENT_CONNECTION_DNS_ERROR                  EID_CLIENT_CONNECTION_ERRO + 0x00000005
#define EID_CLIENT_CONNECTION_CURL_ERROR                 EID_CLIENT_CONNECTION_ERRO + 0x00000006
#define EID_CLIENT_CONNECTION_MODE_ERROR                 EID_CLIENT_CONNECTION_ERRO + 0x00000007
#define EID_CLIENT_CONNECTION_BUFF_TOO_SMALL_ERROR		 EID_CLIENT_CONNECTION_ERRO + 0x00010000

enum HttpHeaderInclusion {
	GetHttpHeader = 0,
	DontGetHttpHeader = 1
};

#ifdef _WIN32
#define EIDCC_COOKIE_FILE "%temp%\eidcc_cookie_file"
#else
#define EIDCC_COOKIE_FILE "/tmp/eidcc_cookie_file"
#endif

#if defined(__cplusplus)
extern "C"
{
#endif

	/**
	 *
	 */

	EID_CLIENT_CONNECTION_ERROR eIDClientConnectionStartRaw(P_EIDCLIENT_CONNECTION_HANDLE hConnection, const char *const hostname, const char *const port, const char *const sid, const char *const pskKey);

	/*After a successfull Call to eIDClientConnectionStartHttp you MUST call eIDClientConnectionEnd*/
	EID_CLIENT_CONNECTION_ERROR eIDClientConnectionStartHttp(P_EIDCLIENT_CONNECTION_HANDLE hConnection, const char *const url, const char *const sid, const char *const pskKey, enum HttpHeaderInclusion includeHeader);

	EID_CLIENT_CONNECTION_ERROR eIDClientConnectionEnd(EIDCLIENT_CONNECTION_HANDLE hConnection);

	EID_CLIENT_CONNECTION_ERROR eIDClientConnectionTransceive(EIDCLIENT_CONNECTION_HANDLE hConnection, const char *const data, const size_t dataLength, char *const bufResult, size_t *nBufResultLength);

	/*Connection has to be established using eIDClientConnectionStartHttp*/
	EID_CLIENT_CONNECTION_ERROR eIDClientConnectionTransceivePAOS(EIDCLIENT_CONNECTION_HANDLE hConnection, const char *const data, const size_t dataLength, char *const bufResult, size_t *nBufResultLength);

	typedef EID_CLIENT_CONNECTION_ERROR(*eIDClientConnectionRaw_t)(P_EIDCLIENT_CONNECTION_HANDLE, const char *const, const char *const, const char *const, const char *const);

	typedef EID_CLIENT_CONNECTION_ERROR(*eIDClientConnectionHttp_t)(P_EIDCLIENT_CONNECTION_HANDLE, const char *const, const char *const, const char *const, int);
 
	typedef EID_CLIENT_CONNECTION_ERROR(*eIDClientConnectionEnd_t)(EIDCLIENT_CONNECTION_HANDLE);

	typedef EID_CLIENT_CONNECTION_ERROR(*eIDClientConnectionTransceive_t)(EIDCLIENT_CONNECTION_HANDLE, const char *const, const size_t, char *const, size_t *);

	typedef EID_CLIENT_CONNECTION_ERROR(*eIDClientConnectionTransceivePAOS_t)(EIDCLIENT_CONNECTION_HANDLE, const char *const, const size_t, char *const, size_t *);

#if defined(__cplusplus)
}
#endif

#endif // #if !defined(__EIDCLIENTCONNECTION_INCLUDED__)
