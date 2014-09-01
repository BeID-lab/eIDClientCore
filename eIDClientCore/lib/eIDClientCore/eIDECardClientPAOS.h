/*
 * Copyright (C) 2013 Bundesdruckerei GmbH
 */

#if !defined(__EIDECARDCLIENTPAOS_INCLUDED__)
#define __EIDECARDCLIENTPAOS_INCLUDED__

#include "eIDClientCore.h"
#include "eIDClientConnection.h"

typedef unsigned long EID_ECARD_CLIENT_PAOS_ERROR;

#define EID_ECARD_CLIENT_PAOS_ERROR_FLAG                 (EID_ECARD_CLIENT_PAOS_ERROR) 0xC0000000

#define EID_ECARD_CLIENT_PAOS_ERROR_SUCCESS              (EID_ECARD_CLIENT_PAOS_ERROR) 0x00000000

#define EID_ECARD_CLIENT_PAOS_CONNECTION_ERROR           (EID_ECARD_CLIENT_PAOS_ERROR) (EID_ECARD_CLIENT_PAOS_ERROR_FLAG | 0x00000001)
#define EID_ECARD_CLIENT_PAOS_PARSER_ERROR               (EID_ECARD_CLIENT_PAOS_ERROR) (EID_ECARD_CLIENT_PAOS_ERROR_FLAG | 0x00000002)

#if defined(__cplusplus)
extern "C"
{
#endif

	EID_ECARD_CLIENT_PAOS_ERROR startPAOS(EIDCLIENT_CONNECTION_HANDLE hConnection,
                                          const char* const cSessionID);

    EID_ECARD_CLIENT_PAOS_ERROR getEACSessionInfo(EIDCLIENT_CONNECTION_HANDLE hConnection,
                                                  const char* const cSessionID,
                                                  nPADataBuffer_t* const requiredCHAT,
                                                  nPADataBuffer_t* const optionalCHAT,
                                                  nPADataBuffer_t* const authAuxData,
                                                  nPADataBuffer_t* const cert,
                                                  nPADataBuffer_t* const certDescRaw,
                                                  nPADataBuffer_t* const transactionInfo);
 
    EID_ECARD_CLIENT_PAOS_ERROR getTerminalAuthenticationData(EIDCLIENT_CONNECTION_HANDLE hConnection,
                                                              const nPADataBuffer_t efCardAccess,
                                                              const nPADataBuffer_t selectedCHAT,
                                                              const nPADataBuffer_t cvCACHAR,
                                                              const nPADataBuffer_t idPICC,
                                                              nPADataBuffer_t** list_certificates,
                                                              unsigned long* const list_size,
                                                              nPADataBuffer_t* const Puk_IFD_DH_CA);

    EID_ECARD_CLIENT_PAOS_ERROR createSignature(EIDCLIENT_CONNECTION_HANDLE hConnection,
                                                const nPADataBuffer_t toBeSigned,
                                                nPADataBuffer_t* const signature);
    
    EID_ECARD_CLIENT_PAOS_ERROR EAC2OutputCardSecurity(EIDCLIENT_CONNECTION_HANDLE hConnection,
                                                       const nPADataBuffer_t efCardSecurity,
                                                       const nPADataBuffer_t AuthToken,
                                                       const nPADataBuffer_t Nonce,
                                                       nPADataBuffer_t** list_apdus,
                                                       unsigned long* const list_size);

    EID_ECARD_CLIENT_PAOS_ERROR readAttributes(EIDCLIENT_CONNECTION_HANDLE hConnection,
                                               const nPADataBuffer_t* list_inApdus,
                                               const unsigned long list_inApdus_size,
                                               nPADataBuffer_t **new_list_inApdus,
                                               unsigned long *new_list_inApdus_size);

	typedef EID_ECARD_CLIENT_PAOS_ERROR (*startPAOS_t)(EIDCLIENT_CONNECTION_HANDLE, const char* const);
    
	typedef EID_ECARD_CLIENT_PAOS_ERROR (*getEACSessionInfo_t)(EIDCLIENT_CONNECTION_HANDLE, const char* const, nPADataBuffer_t* const, nPADataBuffer_t* const, nPADataBuffer_t* const, nPADataBuffer_t* const, nPADataBuffer_t* const);
    
    typedef EID_ECARD_CLIENT_PAOS_ERROR (*getTerminalAuthenticationData_t)(EIDCLIENT_CONNECTION_HANDLE, const nPADataBuffer_t, const nPADataBuffer_t, const char* const, const nPADataBuffer_t, nPADataBuffer_t**, unsigned long* const, nPADataBuffer_t* const);
    
    typedef EID_ECARD_CLIENT_PAOS_ERROR (*createSignature_t)(EIDCLIENT_CONNECTION_HANDLE, const nPADataBuffer_t, nPADataBuffer_t* const);
    
    typedef EID_ECARD_CLIENT_PAOS_ERROR (*EAC2OutputCardSecurity_t)(EIDCLIENT_CONNECTION_HANDLE, const nPADataBuffer_t, const nPADataBuffer_t, const nPADataBuffer_t, nPADataBuffer_t**, unsigned long* const);
    
    typedef EID_ECARD_CLIENT_PAOS_ERROR (*readAttributes_t)(EIDCLIENT_CONNECTION_HANDLE, nPADataBuffer_t* , const unsigned long);
    
#if defined(__cplusplus)
}
#endif

#endif // #if !defined(__EIDECARDCLIENTPAOS_INCLUDED__)
