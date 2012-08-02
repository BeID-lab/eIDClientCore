// ---------------------------------------------------------------------------
// Copyright (c) 2010 Bundesruckerei GmbH
// All rights reserved.
//
// $Id: nPAClientLib.cpp 717 2010-02-26 09:20:30Z rfiedler $
// ---------------------------------------------------------------------------

/*!
 * @file nPAClient.cpp
 */

#include "eIdClientCoreLib.h"
#include "eIdECardClient.h"
#include "nPAClient.h"

#include <eCardStatus.h>
#include <eCardCore.h>

using namespace Bundesdruckerei::nPA;

#include <cassert>

/*
 *
 */
extern "C" NPACLIENT_ERROR NPACLIENT_API nPAInitializeProtocol(
  AuthenticationParams_t* authParams,
  PNPACLIENT_HANDLE hClient)
{
  try 
  {
    ECARD_PROTOCOL usedProtocol        = PROTOCOL_PCSC;
//      ECARD_PROTOCOL usedProtocol        = PROTOCOL_EXTERNAL_LIB;

    CharMap paraMap;
    paraMap[(char *) "ServerAddress"]           = (char**) &authParams->m_serverAddress;
    paraMap[(char *) "SessionIdentifier"]       = (char**) &authParams->m_sessionIdentifier;
    paraMap[(char *) "Binding"]                 = (char**) &authParams->m_binding;
    paraMap[(char *) "PathSecurity-Protocol"]   = (char**) &authParams->m_pathSecurityProtocol;
    paraMap[(char *) "PathSecurity-Parameters"] = (char**) &authParams->m_pathSecurityParameters;
    paraMap[(char *) "RefreshAddress"]          = (char**) &authParams->m_refreshAddress;

    // TODO use the correct parameters
    IIdP* pIdP = eIdECardClient::createInstance(&paraMap);

    assert(0x00 != pIdP);

    if (0x00 == pIdP)
      return NPACLIENT_ERROR_IDP_INSTANTIATION_ERROR;

    if (!pIdP->open())
    {
      delete pIdP;
      return NPACLIENT_ERROR_IDP_INITIALIZATION_ERROR;
    }

    // Create the nPAClient object
    nPAClient* pnPAClient = nPAClient::createInstance(pIdP);
    assert(0x00 != pnPAClient);

    if (0x00 == pnPAClient)
      return NPACLIENT_ERROR_CLIENT_INSTANTIATION_ERROR;

    NPACLIENT_ERROR error = NPACLIENT_ERROR_SUCCESS;
    if (NPACLIENT_ERROR_SUCCESS != (error = pnPAClient->initialize(&paraMap, usedProtocol)))
    {
      delete pnPAClient;

      return error;
    }

    *hClient = pnPAClient;
  }
  catch (...)
  {
    return NPACLIENT_ERROR_GENERAL_INITIALIZATION_FAILURE;
  }
   
  return NPACLIENT_ERROR_SUCCESS; 
}

/*
 *
 */
extern "C" NPACLIENT_ERROR NPACLIENT_API nPAFinalizeProtocol(
  NPACLIENT_HANDLE hClient)
{
  assert(0x00 != hClient);

  // Check for the validity of the parameters.
  if (0x00 == hClient)
    return NPACLIENT_ERROR_INVALID_PARAMETER1;

  // Cast the handle to an pointer to an nPAClient object.
  // I know it's very unsafe :(
  nPAClient* pnPAClient = (nPAClient*) hClient;

  // Delete the object.
  delete pnPAClient;

  return NPACLIENT_ERROR_SUCCESS;
}

/*
 *
 */
extern "C" NPACLIENT_ERROR NPACLIENT_API nPAQueryPACEInfos(
  NPACLIENT_HANDLE hClient,
  chat_t* chatFromCertificate,
  time_t* certificateValidFrom,
  time_t* certificateValidTo,
  nPADataBuffer_t* certificateDescription,
  nPADataBuffer_t* serviceName,
  nPADataBuffer_t* serviceURL)
{
  assert(0x00 != hClient);
  assert(0x00 != chatFromCertificate);
  assert(0x00 != certificateValidFrom);
  assert(0x00 != certificateValidTo);
  assert(0x00 != certificateDescription);
  assert(0x00 != serviceName);
  assert(0x00 != serviceURL);

  // Check for the validity of the parameters.
  if (0x00 == hClient)
    return NPACLIENT_ERROR_INVALID_PARAMETER1;
  if (0x00 == chatFromCertificate)
    return NPACLIENT_ERROR_INVALID_PARAMETER2;
  if (0x00 == certificateValidFrom)
    return NPACLIENT_ERROR_INVALID_PARAMETER3;
  if (0x00 == certificateValidTo)
    return NPACLIENT_ERROR_INVALID_PARAMETER4;
  if (0x00 == certificateDescription)
    return NPACLIENT_ERROR_INVALID_PARAMETER5;
  if (0x00 == serviceName)
    return NPACLIENT_ERROR_INVALID_PARAMETER6;
  if (0x00 == serviceURL)
    return NPACLIENT_ERROR_INVALID_PARAMETER7;
  if (0x00 != certificateDescription->pDataBuffer)
    return NPACLIENT_ERROR_INVALID_PARAMETER5;
  if (0x00 != serviceName->pDataBuffer)
    return NPACLIENT_ERROR_INVALID_PARAMETER6;
  if (0x00 != serviceURL->pDataBuffer)
    return NPACLIENT_ERROR_INVALID_PARAMETER7;

  // Cast the handle to an pointer to an nPAClient object.
  // I know it's very unsafe :(
  nPAClient* pnPAClient = (nPAClient*) hClient;

  // Query the CHAT date of the terminal certificate. The CHAT 
  // should be displayed to the user by the UI component.
  if (!pnPAClient->getCHAT(*chatFromCertificate))
  {
    // @TODO: Log event ...
    return NPACLIENT_ERROR_READ_CHAT; 
  }

  // Query the start date of the terminal certificate. The date 
  // should be displayed to the user by the UI component.
  if (!pnPAClient->getValidFromDate(*certificateValidFrom))
  { 
    // @TODO: Log event ...
    return NPACLIENT_ERROR_READ_VALID_FROM_DATE;
  }

  // Query the expiration date of the terminal certificate. The date 
  // should be displayed to the user by the UI component.
  if (!pnPAClient->getValidToDate(*certificateValidTo))
  {  
    // @TODO: Log event ...
    return NPACLIENT_ERROR_READ_VALID_TO_DATE;
  }

  // Query the certificate description of the requesting service. 
  // The certificate description should be displayed to the user 
  // by the UI component.
  if (!pnPAClient->getCertificateDescription(*certificateDescription))
  {  
    // @TODO: Log event ...
    return NPACLIENT_ERROR_READ_CERTIFICATE_DESCRIPTION;
  }

  // Query the name of the requesting service. The name should be displayed
  // to the user by the UI component.
  if (!pnPAClient->getServiceName(*serviceName))
  {  
    // @TODO: Log event ...
    return NPACLIENT_ERROR_READ_SERVICE_NAME;
  }

  // Query the URL of the requesting service. The URL should be displayed
  // to the user by the UI component.
  if (!pnPAClient->getServiceURL(*serviceURL))
  {  
    // @TODO: Log event ...
//    return NPACLIENT_ERROR_READ_SERVICE_NAME;
  }

  // @TODO: Log event ...
  return NPACLIENT_ERROR_SUCCESS;
}
/*
 *
 */
extern "C" NPACLIENT_ERROR NPACLIENT_API nPAQueryPACEInfos2(
  NPACLIENT_HANDLE hClient,
  nPADataBuffer_t* chatFromCertificate,
  nPADataBuffer_t* chatRequired,
  nPADataBuffer_t* chatOptional,
  time_t* certificateValidFrom,
  time_t* certificateValidTo,
  nPADataBuffer_t* certificateDescription,
  nPADataBuffer_t* serviceName,
  nPADataBuffer_t* serviceURL)
{
	assert(0x00 != chatFromCertificate);
	assert(0x00 != chatRequired);
	assert(0x00 != chatOptional);

  if (0x00 != chatFromCertificate->pDataBuffer)
    return NPACLIENT_ERROR_INVALID_PARAMETER5;
  if (0x00 != chatRequired->pDataBuffer)
    return NPACLIENT_ERROR_INVALID_PARAMETER5;
  if (0x00 != chatOptional->pDataBuffer)
    return NPACLIENT_ERROR_INVALID_PARAMETER5;

  chat_t chatFromCertificate2 = 0;
  time_t certificateValidFrom2 = 0;
  time_t certificateValidTo2 = 0;
  nPADataBuffer_t certificateDescription2 = {0x00, 0};
  NPACLIENT_ERROR ret = nPAQueryPACEInfos(hClient, &chatFromCertificate2, &certificateValidFrom2,
	  &certificateValidTo2, &certificateDescription2, serviceName, serviceURL);

  // Cast the handle to an pointer to an nPAClient object.
  // I know it's very unsafe :(
  nPAClient* pnPAClient = (nPAClient*) hClient;

  // Query the CHAT date of the terminal certificate. The CHAT 
  // should be displayed to the user by the UI component.
  if (!pnPAClient->getCHAT2(*chatFromCertificate))
  {
    // @TODO: Log event ...
    return NPACLIENT_ERROR_READ_CHAT; 
  }

  // Query the required CHAT date. The CHAT 
  // should be displayed to the user by the UI component.
  if (!pnPAClient->getRequiredCHAT(*chatRequired))
  {
    // @TODO: Log event ...
    return NPACLIENT_ERROR_READ_CHAT; 
  }

  // Query the optional CHAT date. The CHAT 
  // should be displayed to the user by the UI component.
  if (!pnPAClient->getOptionalCHAT(*chatOptional))
  {
    // @TODO: Log event ...
    return NPACLIENT_ERROR_READ_CHAT; 
  }

   // Query the start date of the terminal certificate. The date 
  // should be displayed to the user by the UI component.
  if (!pnPAClient->getValidFromDate(*certificateValidFrom))
  { 
    // @TODO: Log event ...
    return NPACLIENT_ERROR_READ_VALID_FROM_DATE;
  }

  // Query the expiration date of the terminal certificate. The date 
  // should be displayed to the user by the UI component.
  if (!pnPAClient->getValidToDate(*certificateValidTo))
  {  
    // @TODO: Log event ...
    return NPACLIENT_ERROR_READ_VALID_TO_DATE;
  }

  // Query the certificate description of the requesting service. 
  // The certificate description should be displayed to the user 
  // by the UI component.
//  if (!pnPAClient->getCertificateDescriptionRaw(*certificateDescription))
  if (!pnPAClient->getCertificateDescription(*certificateDescription))	// terms of usage
  {  
    // @TODO: Log event ...
    return NPACLIENT_ERROR_READ_CERTIFICATE_DESCRIPTION;
  }

  return ret;
}

extern "C" NPACLIENT_ERROR NPACLIENT_API nPAPerformPACE(
  NPACLIENT_HANDLE hClient,
  const char* password,
  chat_t chatSelectedByUser,
  nPADataBuffer_t &certificateDescription,
  unsigned char* retryCounter /*unused*/)
{
  NPACLIENT_ERROR error = NPACLIENT_ERROR_SUCCESS;

  assert(0x00 != hClient);
  assert(0x00 != password);

  if (0x00 == hClient)
    return NPACLIENT_ERROR_INVALID_PARAMETER1;

  // Cast the handle to an pointer to an nPAClient object.
  // I know it's very unsafe :(
  nPAClient* pnPAClient = (nPAClient*) hClient;

  try {
	  error = pnPAClient->performPACE(password, chatSelectedByUser, certificateDescription, retryCounter);
  } catch (...) {
	  return NPACLIENT_ERROR_PACE_FAILED;
  }

  if (error != NPACLIENT_ERROR_SUCCESS)
  {
    // @TODO: Log event ...
    return error;
  }

  // @TODO: Log event ...
  return NPACLIENT_ERROR_SUCCESS;
}

/*
 *
 */
NPACLIENT_ERROR NPACLIENT_API nPAPerformTerminalAuthentication(
  NPACLIENT_HANDLE hClient)
{
  NPACLIENT_ERROR error = NPACLIENT_ERROR_SUCCESS;

  assert(0x00 != hClient);
 
  if (0x00 == hClient)
    return NPACLIENT_ERROR_INVALID_PARAMETER1;

  // Cast the handle to an pointer to an nPAClient object.
  // I know it's very unsafe :(
  nPAClient* pnPAClient = (nPAClient*) hClient;

  if ((error = pnPAClient->performTerminalAuthentication()) != NPACLIENT_ERROR_SUCCESS)
  {
    // @TODO: Log event ...
    return error;
  }

  // @TODO: Log event ...
  return NPACLIENT_ERROR_SUCCESS;
}

/*
 *
 */
NPACLIENT_ERROR NPACLIENT_API nPAPerformChipAuthentication(
  NPACLIENT_HANDLE hClient)
{
  NPACLIENT_ERROR error = NPACLIENT_ERROR_SUCCESS;

  assert(0x00 != hClient);

  if (0x00 == hClient)
    return NPACLIENT_ERROR_INVALID_PARAMETER1;

  // Cast the handle to an pointer to an nPAClient object.
  // I know it's very unsafe :(
  nPAClient* pnPAClient = (nPAClient*) hClient;

  if ((error = pnPAClient->performChipAuthentication()) != NPACLIENT_ERROR_SUCCESS)
  {
    // @TODO: Log event ...
    return error;
  }

  // @TODO: Log event ...
  return NPACLIENT_ERROR_SUCCESS;
}

/*
 *
 */
NPACLIENT_ERROR NPACLIENT_API nPAReadAttributes(
  IN NPACLIENT_HANDLE hClient,
  OUT nPADataBuffer_t* samlEncodedAttributes)
{
  NPACLIENT_ERROR error = NPACLIENT_ERROR_SUCCESS;

  assert(0x00 != hClient);
  assert(0x00 != samlEncodedAttributes);

  if (0x00 == hClient)
    return NPACLIENT_ERROR_INVALID_PARAMETER1;
  if (0x00 == samlEncodedAttributes)
    return NPACLIENT_ERROR_INVALID_PARAMETER2;

  // Cast the handle to an pointer to an nPAClient object.
  // I know it's very unsafe :(
  nPAClient* pnPAClient = (nPAClient*) hClient;
 
  if ((error = pnPAClient->readAttributed(*samlEncodedAttributes)) != NPACLIENT_ERROR_SUCCESS)
  {
    // @TODO: Log event ...
    return error;
  }
 
  // @TODO: Log event ...  
  return NPACLIENT_ERROR_SUCCESS;
}

/*!
 * @brief This function finalizes the communication protocol and frees all allocated 
 *        resources. The hClient handle becomes invalid after a call to this function.
 *
 * @param hClient The handle to close.
 *
 * @return NPACLIENT_ERROR_SUCCESS The protocol is finalized properly.
 */
extern "C" NPACLIENT_ERROR NPACLIENT_API nPAFreeDataBuffer(
  nPADataBuffer_t* pDataBuffer)
{
  assert(0x00 != pDataBuffer);

  // The given buffer isn't valid.
  if (0x00 == pDataBuffer)
    return NPACLIENT_ERROR_INVALID_PARAMETER1;

  // Free the memory and set the members to initial values.
  delete [] pDataBuffer->pDataBuffer;
  pDataBuffer->pDataBuffer = 0x00;
  pDataBuffer->bufferSize = 0;

  return NPACLIENT_ERROR_SUCCESS;
}

/*
 *
 */
extern "C" NPACLIENT_ERROR NPACLIENT_API nPAeIdPerformAuthenticationProtocolWithParamMap(
  IN AuthenticationParams_t paraMap,
  IN const nPAeIdUserInteractionCallback_t fnUserInteractionCallback,
  IN const nPAeIdProtocolStateCallback_t fnCurrentStateCallback)
{
  assert(0x00 != fnUserInteractionCallback);
  assert(0x00 != fnCurrentStateCallback);

  NPACLIENT_ERROR error = NPACLIENT_ERROR_SUCCESS;
  NPACLIENT_ERROR errorCallBack = NPACLIENT_ERROR_SUCCESS;
  NPACLIENT_HANDLE hnPAClient = 0x00;

  nPADataBuffer_t bufChatFromCertificate = {0x00, 0};
  nPADataBuffer_t bufChatRequired = {0x00, 0};
  nPADataBuffer_t bufChatOptional = {0x00, 0};

  nPADataBuffer_t certificateDescription = {0x00, 0};
  nPADataBuffer_t serviceName = {0x00, 0};
  nPADataBuffer_t serviceURL = {0x00, 0};
  nPADataBuffer_t samlEncodedAttributes = {0x00, 0};

//  nPAeIdPACEParams_t paramPACE;

  chat_t chatFromCertificate = 0x0000000000000000;
  chat_t chatRequired = 0x0000000000000000;
  chat_t chatOptional = 0x0000000000000000;
  chat_t userSelectedChat = 0x0000000000000000;
  time_t certificateValidFrom = 0;
  time_t certificateValidTo = 0;

  std::string	strCertificateDescription;
  std::string	strServiceName;
  std::string	strServiceURL;

  std::string	strPIN;

  // Initialize the nPA access
  error = nPAInitializeProtocol(&paraMap, &hnPAClient);
  
  fnCurrentStateCallback(NPACLIENT_STATE_INITIALIZE, error);

  if(error != NPACLIENT_ERROR_SUCCESS)
  {
	  return error;
  }

  if ((error = nPAQueryPACEInfos2(hnPAClient, &bufChatFromCertificate, &bufChatRequired, &bufChatOptional, &certificateValidFrom,
    &certificateValidTo, &certificateDescription, &serviceName, &serviceURL)) == NPACLIENT_ERROR_SUCCESS)
  {
    chatFromCertificate = 0x0000000000000000;
    if(bufChatFromCertificate.bufferSize == 5)
    {
	  chatFromCertificate += (long long) *(bufChatFromCertificate.pDataBuffer) << 32;
	  chatFromCertificate += (long long) *(bufChatFromCertificate.pDataBuffer + 1) << 24;
	  chatFromCertificate += (long long) *(bufChatFromCertificate.pDataBuffer + 2) << 16;
	  chatFromCertificate += (long long) *(bufChatFromCertificate.pDataBuffer + 3) << 8;
	  chatFromCertificate += (long long) *(bufChatFromCertificate.pDataBuffer + 4);
    }
    chatRequired = 0x0000000000000000;
    if(bufChatRequired.bufferSize == 5)
    {
	  chatRequired += (long long) *(bufChatRequired.pDataBuffer) << 32;
	  chatRequired += (long long) *(bufChatRequired.pDataBuffer + 1) << 24;
	  chatRequired += (long long) *(bufChatRequired.pDataBuffer + 2) << 16;
	  chatRequired += (long long) *(bufChatRequired.pDataBuffer + 3) << 8;
	  chatRequired += (long long) *(bufChatRequired.pDataBuffer + 4);
    }
    chatOptional = 0x0000000000000000;
    if(bufChatOptional.bufferSize == 5)
    {
	  chatOptional += (long long) *(bufChatOptional.pDataBuffer) << 32;
	  chatOptional += (long long) *(bufChatOptional.pDataBuffer + 1) << 24;
	  chatOptional += (long long) *(bufChatOptional.pDataBuffer + 2) << 16;
	  chatOptional += (long long) *(bufChatOptional.pDataBuffer + 3) << 8;
	  chatOptional += (long long) *(bufChatOptional.pDataBuffer + 4);
    }
	if(certificateDescription.bufferSize > 0)
	{
		strCertificateDescription.assign((const char*)certificateDescription.pDataBuffer, certificateDescription.bufferSize);
	}
	if(serviceName.bufferSize > 0)
	{
		strServiceName.assign((const char*)serviceName.pDataBuffer, serviceName.bufferSize);
	}
	if(serviceURL.bufferSize > 0)
	{
		strServiceURL.assign((const char*)serviceURL.pDataBuffer, serviceURL.bufferSize);
	}
  }

  //paramPACE.chatFromCertificate = chatFromCertificate;
  //paramPACE.chatRequired = chatRequired;
  //paramPACE.chatOptional = chatOptional;
  //
  //paramPACE.certificateDescription = strCertificateDescription.c_str();
  //paramPACE.serviceName = strServiceName.c_str();
  //paramPACE.serviceURL = strServiceURL.c_str();

  fnCurrentStateCallback(NPACLIENT_STATE_GOT_PACE_INFO, error);

  if(error != NPACLIENT_ERROR_SUCCESS)
  {
    // We have to call this here, because  we have to free all the allocated resources.
    nPAFinalizeProtocol(hnPAClient);
    return error;
  }

  char bufPIN[10];
  memset(&bufPIN[0], 0x00, 10);
  
  fnUserInteractionCallback(chatFromCertificate, chatRequired, chatOptional,
	                        strCertificateDescription.c_str(), strServiceName.c_str(), strServiceURL.c_str(),
							userSelectedChat, &bufPIN[0], 10);

  strPIN.assign(&bufPIN[0]);
//  userSelectedChat = paramPACE.userSelectedChat;
  unsigned char retryCounter = (unsigned char) 0xFF;

  error = nPAPerformPACE(hnPAClient, strPIN.c_str(), userSelectedChat, certificateDescription, &retryCounter);

  fnCurrentStateCallback(NPACLIENT_STATE_PACE_PERFORMED, error);
  
  if( error != NPACLIENT_ERROR_SUCCESS)
  {
    // We have to call this here, because  we have to free all the allocated resources.
    nPAFinalizeProtocol(hnPAClient);
    return error;
  }

  error = nPAPerformTerminalAuthentication(hnPAClient);

  fnCurrentStateCallback(NPACLIENT_STATE_TA_PERFORMED, error);

  if( error != NPACLIENT_ERROR_SUCCESS)
  {
    // We have to call this here, because  we have to free all the allocated resources.
    nPAFinalizeProtocol(hnPAClient);
    return error;
  }

  error = nPAPerformChipAuthentication(hnPAClient);

  fnCurrentStateCallback(NPACLIENT_STATE_CA_PERFORMED, error);

  if( error != NPACLIENT_ERROR_SUCCESS)
  {
    // We have to call this here, because  we have to free all the allocated resources.
    nPAFinalizeProtocol(hnPAClient);
    return error;
  }

  error = nPAReadAttributes(hnPAClient, &samlEncodedAttributes);
  nPAFreeDataBuffer(&samlEncodedAttributes);

  fnCurrentStateCallback(NPACLIENT_STATE_READ_ATTRIBUTES, error);

  if( error != NPACLIENT_ERROR_SUCCESS)
  {
    // We have to call this here, because  we have to free all the allocated resources.
    nPAFinalizeProtocol(hnPAClient);
    return error;
  }

  nPAFinalizeProtocol(hnPAClient);

  // Free temporarily allocated data. May some of this data are not allocated so far, 
  // but we should try to deallocate them anyway.
  nPAFreeDataBuffer(&bufChatFromCertificate);
  nPAFreeDataBuffer(&bufChatRequired);
  nPAFreeDataBuffer(&bufChatOptional);
  nPAFreeDataBuffer(&certificateDescription);
  nPAFreeDataBuffer(&serviceName);
  nPAFreeDataBuffer(&serviceURL);

  return NPACLIENT_ERROR_SUCCESS; 
}

extern "C" NPACLIENT_ERROR NPACLIENT_API nPAeIdPerformAuthenticationProtocolPcSc(
  IN const char* const IdpAddress,
  IN const char* const SessionIdentifier,
  IN const char* const PathSecurityParameters,
  IN const nPAeIdUserInteractionCallback_t fnUserInteractionCallback,
  IN const nPAeIdProtocolStateCallback_t fnCurrentStateCallback)
{
    AuthenticationParams_t authParams_;
 
    authParams_.m_serverAddress     = IdpAddress;
    authParams_.m_sessionIdentifier = SessionIdentifier;
    authParams_.m_pathSecurityParameters = PathSecurityParameters;

	return nPAeIdPerformAuthenticationProtocolWithParamMap(authParams_, fnUserInteractionCallback, fnCurrentStateCallback);
}
