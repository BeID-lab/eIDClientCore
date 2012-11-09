/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#if !defined(__EIDCLIENTCONNECTION_INCLUDED__)
#define __EIDCLIENTCONNECTION_INCLUDED__


typedef void *EIDCLIENT_CONNECTION_HANDLE;
typedef EIDCLIENT_CONNECTION_HANDLE *P_EIDCLIENT_CONNECTION_HANDLE;

typedef unsigned long EID_CLIENT_CONNECTION_ERROR;

#define EID_CLIENT_CONNECTION_ERROR_FLAG                 (EID_CLIENT_CONNECTION_ERROR) 0xC0000000

#define EID_CLIENT_CONNECTION_ERROR_SUCCESS              (EID_CLIENT_CONNECTION_ERROR) 0x00000000

#define EID_CLIENT_CONNECTION_SOCKET_ERROR               (EID_CLIENT_CONNECTION_ERROR) (EID_CLIENT_CONNECTION_ERROR_FLAG | 0x00000001)
#define EID_CLIENT_CONNECTION_TLS_HANDSHAKE_ERROR        (EID_CLIENT_CONNECTION_ERROR) (EID_CLIENT_CONNECTION_ERROR_FLAG | 0x00000002)
#define EID_CLIENT_CONNECTION_WSA_STARTUP_FAILED         (EID_CLIENT_CONNECTION_ERROR) (EID_CLIENT_CONNECTION_ERROR_FLAG | 0x00000003)
#define EID_CLIENT_CONNECTION_INVALID_HANDLE             (EID_CLIENT_CONNECTION_ERROR) (EID_CLIENT_CONNECTION_ERROR_FLAG | 0x00000004)
#define EID_CLIENT_CONNECTION_DNS_ERROR                  (EID_CLIENT_CONNECTION_ERROR) (EID_CLIENT_CONNECTION_ERROR_FLAG | 0x00000005)


#if defined(__cplusplus)
extern "C"
{
#endif

	/**
	 *
	 */

	EID_CLIENT_CONNECTION_ERROR eIDClientConnectionStart(P_EIDCLIENT_CONNECTION_HANDLE hConnection, const char *const hostname, const char *const port, const char *const sid, const char *const pskKey);

	EID_CLIENT_CONNECTION_ERROR eIDClientConnectionEnd(EIDCLIENT_CONNECTION_HANDLE hConnection);

	EID_CLIENT_CONNECTION_ERROR eIDClientConnectionSendRequest(EIDCLIENT_CONNECTION_HANDLE hConnection, const char *const data, const size_t dataLength, char *const bufResult, size_t *nBufResultLength);


	typedef EID_CLIENT_CONNECTION_ERROR(*eIDClientConnectionStart_t)(P_EIDCLIENT_CONNECTION_HANDLE, const char *const, const char *const, const char *const, const char *const, const char *const);

	typedef EID_CLIENT_CONNECTION_ERROR(*eIDClientConnectionEnd_t)(EIDCLIENT_CONNECTION_HANDLE);

	typedef EID_CLIENT_CONNECTION_ERROR(*eIDClientConnectionSendRequest_)(EIDCLIENT_CONNECTION_HANDLE hConnection, const char *const, const size_t, char *const, size_t *);

#if defined(__cplusplus)
}
#endif

#endif // #if !defined(__EIDCLIENTCONNECTION_INCLUDED__)
