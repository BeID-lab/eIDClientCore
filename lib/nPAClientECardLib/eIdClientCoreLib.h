// ---------------------------------------------------------------------------
// Copyright (c) 2010 Bundesdruckerei GmbH
// All rights reserved.
//
// $Id: nPAClientLib.h 682 2010-02-15 14:09:14Z rfiedler $
// ---------------------------------------------------------------------------

#if !defined(__NPACLIENTLIB_INCLUDED__)
#define __NPACLIENTLIB_INCLUDED__

//#include "nPAClientError.h"
//#include "nPAClientTypes.h"

#include <time.h>

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

#define IN
#define OUT
#define OPTIONAL

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

/**
 *
 */
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
  const char* m_cardReaderName;
  void*       m_extension; //Global Tester Params for example

  /**
   *
   */
  AuthenticationParams(
    void) : m_serverAddress(0x00), m_sessionIdentifier(0x00), m_binding(0x00),
    m_pathSecurityProtocol(0x00), m_pathSecurityParameters(0x00), m_refreshAddress(0x00),
    m_pin(0), m_userSelectedChat(0x00), m_cardReaderName(0x00), m_extension(0x00) { /* */ }
} AuthenticationParams_t;

#if defined(__cplusplus)
extern "C"
{
#endif

#if !defined(__APPLE__)
# define NPACLIENT_API
//# define NPACLIENT_API __stdcall
#else
# define NPACLIENT_API
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

/*!
 * @brief 
 *
 * @param 
 * @param 
 *
 * @return NPACLIENT_ERROR_
 */
NPACLIENT_ERROR NPACLIENT_API nPAeIdPerformAuthenticationProtocolPcSc(
  IN const char* const IdpAddress,
  IN const char* const SessionIdentifier,
  IN const char* const PathSecurityParameters,
  IN const nPAeIdUserInteractionCallback_t fnUserInteractionCallback,
  IN const nPAeIdProtocolStateCallback_t fnCurrentStateCallback);

///*!
// * @brief 
// *
// * @param 
// * @param 
// *
// * @return NPACLIENT_ERROR_
// */
//NPACLIENT_ERROR NPACLIENT_API nPAeIdPerformAuthenticationProtocolWithParamMap(
//  IN AuthenticationParams_t paraMap,
//  IN const nPAeIdUserInteractionCallback_t fnUserInteractionCallback,
//  IN const nPAeIdProtocolStateCallback_t fnCurrentStateCallback);
//
///*!
// * @brief This function is used to initialize the communication protocol to read
// *        out the upcoming German ID card.
// *
// * @param paraMap holds the strings from the plugin (ServerAddress, SessionIdentifier, PSK, RefreshAddress).
// * @param hClient Pointer to the resulting handle. This handle will be used in all further API calls.
// *
// * @return NPACLIENT_ERROR_SUCCESS The protocol is initialized properly. All other values indicating
// *         an error.
// */
//NPACLIENT_ERROR NPACLIENT_API nPAInitializeProtocol(
//  IN AuthenticationParams_t* paraMap,
//  OUT PNPACLIENT_HANDLE hClient);
//
///*!
// * @brief This function returns all the data needed for the PACE dialog.
// *
// * @param hClient Handle to an valid nPA client, created by @see nPAInitializeProtocol.
// * @param chatFromCertificate Pointer to the CHAT, read out from the terminal certificate.
// * @param certificateValidFrom Pointer to the start date of the terminal certificate. 
// * @param certificateValidTo Pointer to the end date of the terminal certificate.
// * @param certificateDescription Pointer to an nPADataBuffer_t structure that holds the certificate
// *                               description.
// * @param serviceName Pointer to an nPADataBuffer_t structure that holds the name of the service.
// * @param serviceURL Pointer to an nPADataBuffer_t structure that holds the URL of the service.
// *
// * @return NPACLIENT_ERROR_SUCCESS The function performs successfully.  All other values indicating
// *         an error.
// */
//NPACLIENT_ERROR NPACLIENT_API nPAQueryPACEInfos(
//  IN NPACLIENT_HANDLE hClient,
//  OUT chat_t* chatFromCertificate,
//  OUT time_t* certificateValidFrom,
//  OUT time_t* certificateValidTo,
//  OUT nPADataBuffer_t* certificateDescription,
//  OUT nPADataBuffer_t* serviceName,
//  OUT nPADataBuffer_t* serviceURL);
//
///*!
// * @brief This function returns all the data needed for the PACE dialog.
// *
// * @param hClient Handle to an valid nPA client, created by @see nPAInitializeProtocol.
// * @param chatFromCertificate Pointer to the CHAT, read out from the terminal certificate.
// * @param chatRequired
// * @param chatOptional
// * @param certificateValidFrom Pointer to the start date of the terminal certificate. 
// * @param certificateValidTo Pointer to the end date of the terminal certificate.
// * @param certificateDescription Pointer to an nPADataBuffer_t structure that holds the certificate
// *                               description.
// * @param serviceName Pointer to an nPADataBuffer_t structure that holds the name of the service.
// * @param serviceURL Pointer to an nPADataBuffer_t structure that holds the URL of the service.
// *
// * @return NPACLIENT_ERROR_SUCCESS The function performs successfully.  All other values indicating
// *         an error.
// */
//NPACLIENT_ERROR NPACLIENT_API nPAQueryPACEInfos2(
//  IN NPACLIENT_HANDLE hClient,
//  OUT nPADataBuffer_t* chatFromCertificate,
//  OUT nPADataBuffer_t* chatRequired,
//  OUT nPADataBuffer_t* chatOptional,
//  OUT time_t* certificateValidFrom,
//  OUT time_t* certificateValidTo,
//  OUT nPADataBuffer_t* certificateDescription,
//  OUT nPADataBuffer_t* serviceName,
//  OUT nPADataBuffer_t* serviceURL);
//
///*!
// * @brief This function performs the PACE protocol to establish the first
// *        secure messaging channel between the client and the nPA.
// *
// * @param hClient Handle to an valid nPA client, created by @see nPAInitializeProtocol.
// * @param password Pointer to an 0-Terminated string which holds the password provided by the user.
// * @param chatSelectedByUser The CHAT value selected by the user.
// * @param retryCounter Pointer to the retry counter of the card. This feature isn't implemented yet.
// *
// * @return NPACLIENT_ERROR_SUCCESS The PACE protocol was performed successfully. All other values 
// *         indicating an error.
// */
//NPACLIENT_ERROR NPACLIENT_API nPAPerformPACE(
//  IN NPACLIENT_HANDLE hClient,
//  IN const char* password,
//  IN chat_t chatSelectedByUser,
//  IN unsigned char* retryCounter /*unused*/);
//
///*!
// * @brief This function is used to perform the terminal authentication protocol.
// *
// * @param hClient Handle to an valid nPA client, created by @see nPAInitializeProtocol.
// *
// * @return NPACLIENT_ERROR_SUCCESS The terminal authentication protocol was performed successfully.
// *          All other values indicating an error.
// */
//NPACLIENT_ERROR NPACLIENT_API nPAPerformTerminalAuthentication(
//  IN NPACLIENT_HANDLE hClient);
//
///*!
// * @brief This function is used to perform the chip authentication protocol.
// *
// * @param hClient Handle to an valid nPA client, created by @see nPAInitializeProtocol.
// *
// * @return NPACLIENT_ERROR_SUCCESS The chip authentication protocol was performed successfully.
// *         All other values indicating an error.
// */
//NPACLIENT_ERROR NPACLIENT_API nPAPerformChipAuthentication(
//  IN NPACLIENT_HANDLE hClient);
//
///*!
// * @brief This function reads out all requested attributes from the nPA. After the reading process
// *        the resulting SAML 2.0 token will be issued by the IdP and returned to the caller.
//
// * @param hClient Handle to an valid nPA client, created by @see nPAInitializeProtocol.
// * @param samlEncodedAttributes Pointer to an nPADataBuffer_t structure that holds the 
// *        SAML 2.0 response.
// *
// * @return NPACLIENT_ERROR_SUCCESS All requested attributes are read successfully.
// *         All other values indicating an error.
// */
//NPACLIENT_ERROR NPACLIENT_API nPAReadAttributes(
//  IN NPACLIENT_HANDLE hClient,
//  OUT nPADataBuffer_t* samlEncodedAttributes);
//
///*!
// * @brief This function is used to free an allocated nPADataBuffer_t structure.
// *
// * @param dataBuffer A pointer to an nPADataBuffer_t structure to free.
// *
// * @return NPACLIENT_ERROR_SUCCESS The buffer was freed successfully. All other values 
// *         indicating an error.
// */
//NPACLIENT_ERROR NPACLIENT_API nPAFreeDataBuffer(
//  IN nPADataBuffer_t* dataBuffer);
//
///*!
// * @brief This function finalizes the communication protocol and frees all allocated 
// *        resources. The hClient handle becomes invalid after a call to this function.
// *
// * @param hClient Handle to an valid nPA client, created by @see nPAInitializeProtocol.
// *
// * @return NPACLIENT_ERROR_SUCCESS The protocol is finalized properly. All other values 
// *         indicating an error.
// */
//NPACLIENT_ERROR NPACLIENT_API nPAFinalizeProtocol(
//  IN NPACLIENT_HANDLE hClient);

typedef NPACLIENT_ERROR (*nPAeIdPerformAuthenticationProtocolPcSc_t)(
  const char* const IdpAddress,
  const char* const SessionIdentifier,
  const char* const PathSecurityParameters,
  const nPAeIdUserInteractionCallback_t fnUserInteractionCallback,
  const nPAeIdProtocolStateCallback_t fnCurrentStateCallback);

//typedef NPACLIENT_ERROR (*nPAeIdPerformAuthenticationProtocolWithParamMap_t)(
//  AuthenticationParams_t paraMap,
//  const nPAeIdUserInteractionCallback_t fnUserInteractionCallback,
//  const nPAeIdProtocolStateCallback_t fnCurrentStateCallback);
//
//typedef NPACLIENT_ERROR (*nPAInitializeProtocol_t)(
//  AuthenticationParams_t* paraMap,
//  PNPACLIENT_HANDLE hClient);
//
//typedef NPACLIENT_ERROR (*nPAQueryPACEInfos_t)(
//  NPACLIENT_HANDLE hClient,
//  chat_t* chatFromCertificate,
//  time_t* certificateValidFrom,
//  time_t* certificateValidTo,
//  nPADataBuffer_t* certificateDescription,
//  nPADataBuffer_t* serviceName,
//  nPADataBuffer_t* serviceURL);
//
//typedef NPACLIENT_ERROR (*nPAQueryPACEInfos2_t)(
//  NPACLIENT_HANDLE hClient,
//  nPADataBuffer_t* chatFromCertificate,
//  nPADataBuffer_t* chatRequired,
//  nPADataBuffer_t* chatOptional,
//  time_t* certificateValidFrom,
//  time_t* certificateValidTo,
//  nPADataBuffer_t* certificateDescription,
//  nPADataBuffer_t* serviceName,
//  nPADataBuffer_t* serviceURL);
//
//typedef NPACLIENT_ERROR (*nPAPerformPACE_t)(
//  NPACLIENT_HANDLE hClient,
//  const char* password,
//  chat_t chatSelectedByUser,
//  unsigned char* retryCounter /*unused*/);
//
//typedef NPACLIENT_ERROR (*nPAPerformTerminalAuthentication_t)(
//  NPACLIENT_HANDLE hClient);
//
//typedef NPACLIENT_ERROR (*nPAPerformChipAuthentication_t)(
//  NPACLIENT_HANDLE hClient);
//
//typedef NPACLIENT_ERROR (*nPAReadAttributes_t)(
//  NPACLIENT_HANDLE hClient,
//  nPADataBuffer_t* samlEncodedAttributes);
//
//typedef NPACLIENT_ERROR (*nPAFreeDataBuffer_t)(
//  nPADataBuffer_t* dataBuffer);
//
//typedef NPACLIENT_ERROR (*nPAFinalizeProtocol_t)(
//  NPACLIENT_HANDLE hClient);

#if defined(__cplusplus)
}
#endif

#endif // #if !defined(__NPACLIENTLIB_INCLUDED__)
