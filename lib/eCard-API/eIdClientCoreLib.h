// ---------------------------------------------------------------------------
// Copyright (c) 2010 Bundesdruckerei GmbH
// All rights reserved.
//
// $Id: nPAClientLib.h 682 2010-02-15 14:09:14Z rfiedler $
// ---------------------------------------------------------------------------

#if !defined(__NPACLIENTLIB_INCLUDED__)
#define __NPACLIENTLIB_INCLUDED__

typedef unsigned long NPACLIENT_ERROR;

#define NPACLIENT_ERROR_SUCCESS         (NPACLIENT_ERROR) 0x00000000

#define NPACLIENT_INFO_FLAG             (NPACLIENT_ERROR) 0xA0000000
#define NPACLIENT_WARN_FLAG             (NPACLIENT_ERROR) 0xB0000000
#define NPACLIENT_ERROR_FLAG            (NPACLIENT_ERROR) 0xC0000000

#define NPACLIENT_ERROR_IDP_INITIALIZATION_ERROR      (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000001)
#define NPACLIENT_ERROR_IDP_INSTANTIATION_ERROR       (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000002)
#define NPACLIENT_ERROR_IDP_INVALID_CONNECTION        (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000003)
#define NPACLIENT_ERROR_IDP_OPENSESSION_ERROR         (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000004)
#define NPACLIENT_ERROR_IDP_OPENSESSION_INVALID_RESPONSE (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000005)
#define NPACLIENT_ERROR_INVALID_PROTOCOL_STATE        (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000006)

#define NPACLIENT_ERROR_GENERAL_INITIALIZATION_FAILURE  (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000010)

#define NPACLIENT_ERROR_CLIENT_INSTANTIATION_ERROR    (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000050)
#define NPACLIENT_ERROR_CLIENT_INITIALIZATION_ERROR   (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000051)

#define NPACLIENT_ERROR_READ_CHAT                     (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000070)
#define NPACLIENT_ERROR_READ_VALID_FROM_DATE          (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000071)
#define NPACLIENT_ERROR_READ_VALID_TO_DATE            (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000072)
#define NPACLIENT_ERROR_READ_CERTIFICATE_DESCRIPTION  (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000073)
#define NPACLIENT_ERROR_READ_SERVICE_NAME             (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000074)
#define NPACLIENT_ERROR_READ_SERVICE_URL              (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000075)

#define NPACLIENT_ERROR_PCSC_INITIALIZATION_FAILED    (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000080)
#define NPACLIENT_ERROR_INVALID_CARD_DETECTOR         (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000081)
#define NPACLIENT_ERROR_NO_USABLE_READER_PRESENT      (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000082)
#define NPACLIENT_ERROR_TO_MANY_CARDS_FOUND           (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000083)
#define NPACLIENT_ERROR_NO_VALID_CARD_FOUND           (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000084)
#define NPACLIENT_ERROR_PROTCOL_INITIALIZATION_FAILD  (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000085)
#define NPACLIENT_ERROR_PACE_FAILED                   (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000086)
#define NPACLIENT_ERROR_TA_INITIALIZATION_FAILD       (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000087)
#define NPACLIENT_ERROR_TA_FAILED                     (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000088)
#define NPACLIENT_ERROR_CREATE_SIGNATURE_ERROR        (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000089)
#define NPACLIENT_ERROR_SEND_SIGNATURE_ERROR          (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000090)
#define NPACLIENT_ERROR_CA_FAILED                     (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000091)
#define NPACLIENT_ERROR_CA_SERVER_FAILED              (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000092)

#define NPACLIENT_ERROR_INVALID_PARAMETER1            (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000100)
#define NPACLIENT_ERROR_INVALID_PARAMETER2            (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000101)
#define NPACLIENT_ERROR_INVALID_PARAMETER3            (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000102)
#define NPACLIENT_ERROR_INVALID_PARAMETER4            (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000103)
#define NPACLIENT_ERROR_INVALID_PARAMETER5            (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000104)
#define NPACLIENT_ERROR_INVALID_PARAMETER6            (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000105)
#define NPACLIENT_ERROR_INVALID_PARAMETER7            (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000106)
#define NPACLIENT_ERROR_INVALID_PARAMETER8            (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000107)
#define NPACLIENT_ERROR_INVALID_PARAMETER9            (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000108)

#define NPACLIENT_ERROR_READ_FAILED                   (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000200)
#define NPACLIENT_ERROR_READ_INVALID_RETURN_VALUE     (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000201)

#define NPACLIENT_ERROR_TRANSMISSION_ERROR            (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000300)
#define NPACLIENT_ERROR_NO_TERMINAL_CERTIFICATE       (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000301)
#define NPACLIENT_ERROR_NO_CERTIFICATE_DESCRIPTION    (NPACLIENT_ERROR) (NPACLIENT_ERROR_FLAG | 0x00000302)

typedef void* NPACLIENT_HANDLE;
typedef NPACLIENT_HANDLE* PNPACLIENT_HANDLE;

typedef unsigned long NPACLIENT_STATE;

#define NPACLIENT_STATE_INITIALIZE        (NPACLIENT_STATE) 0x00000001
#define NPACLIENT_STATE_GOT_PACE_INFO     (NPACLIENT_STATE) 0x00000002
#define NPACLIENT_STATE_PACE_PERFORMED    (NPACLIENT_STATE) 0x00000003
#define NPACLIENT_STATE_TA_PERFORMED      (NPACLIENT_STATE) 0x00000004
#define NPACLIENT_STATE_CA_PERFORMED      (NPACLIENT_STATE) 0x00000005
#define NPACLIENT_STATE_READ_ATTRIBUTES   (NPACLIENT_STATE) 0x00000006

typedef long long chat_t;

typedef struct nPADataBuffer
{
  unsigned char* pDataBuffer;
  unsigned long bufferSize;
} nPADataBuffer_t;

/**
 *
 */
typedef struct AuthenticationParams
{
  const char* m_serverAddress;
  const char* m_sessionIdentifier;
  const char* m_binding;
  const char* m_pathSecurityProtocol;
  const char* m_pathSecurityParameters;
  const char* m_refreshAddress;
  const char* m_pin;
  const char* m_userSelectedChat;
  void*       m_extension; //Global Tester Params for example

  /**
   *
   */
  AuthenticationParams(
    void) : m_serverAddress(0x00), m_sessionIdentifier(0x00), m_binding(0x00),
    m_pathSecurityProtocol(0x00), m_pathSecurityParameters(0x00), m_refreshAddress(0x00),
    m_pin(0), m_userSelectedChat(0x00), m_extension(0x00) { /* */ }
} AuthenticationParams_t;

#if defined(__cplusplus)
extern "C"
{
#endif

#if defined(WIN32) || defined(WINCE)// Windows related stuff
#   if defined(ECARD_EXPORTS)
#       define ECARD_API __declspec(dllexport)
#   else
#       define ECARD_API __declspec(dllimport)
#   endif
#   define __STDCALL__ __stdcall
#else // Linux related stuff
#   define ECARD_API
#   define __STDCALL__
#endif

/*!
 * @brief 
 *
 * @param 
 * @param 
 *
 * @return void
 */
typedef void (*nPAeIdProtocolStateCallback_t)(
  const NPACLIENT_STATE state,
  const NPACLIENT_ERROR error);

/*!
 * @brief 
 *
 * @param 
 * @param 
 *
 * @return NPACLIENT_ERROR_
 */
typedef NPACLIENT_ERROR (*nPAeIdUserInteractionCallback_t)(
  const long long chatFromCertificate,
  const long long chatRequired,
  const long long chatOptional,
  const char* const certificateDescription,
  const char* const serviceName,
  const char* const serviceURL,
  long long& chatUserSelected,
  char* const bufPIN,
  const int nBufLength);

NPACLIENT_ERROR __STDCALL__ nPAeIdPerformAuthenticationProtocolPcSc(
  const char* const IdpAddress,
  const char* const SessionIdentifier,
  const char* const PathSecurityParameters,
  const nPAeIdUserInteractionCallback_t fnUserInteractionCallback,
  const nPAeIdProtocolStateCallback_t fnCurrentStateCallback);

typedef NPACLIENT_ERROR (*nPAeIdPerformAuthenticationProtocolPcSc_t)(
  const char* const IdpAddress,
  const char* const SessionIdentifier,
  const char* const PathSecurityParameters,
  const nPAeIdUserInteractionCallback_t fnUserInteractionCallback,
  const nPAeIdProtocolStateCallback_t fnCurrentStateCallback);

#if defined(__cplusplus)
}
#endif

#endif // #if !defined(__NPACLIENTLIB_INCLUDED__)
