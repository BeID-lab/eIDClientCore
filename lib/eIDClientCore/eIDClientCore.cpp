// ---------------------------------------------------------------------------
// Copyright (c) 2010 Bundesruckerei GmbH
// All rights reserved.
//
// $Id: nPAClientLib.cpp 717 2010-02-26 09:20:30Z rfiedler $
// ---------------------------------------------------------------------------

/*!
 * @file nPAClient.cpp
 */

#include "eIDClientCore.h"
#include "eIDECardClient.h"
#include "nPAClient.h"

typedef void* NPACLIENT_HANDLE;
typedef NPACLIENT_HANDLE* PNPACLIENT_HANDLE;

using namespace Bundesdruckerei::nPA;

/*
 *
 */
extern "C" NPACLIENT_ERROR __STDCALL__ nPAInitializeProtocol(
  AuthenticationParams_t* authParams,
  ECARD_PROTOCOL usedProtocol,
  PNPACLIENT_HANDLE hClient)
{
  try 
  {
    CharMap paraMap;
    paraMap[(char *) "ServerAddress"]           = (char**) &authParams->m_serverAddress;
    paraMap[(char *) "SessionIdentifier"]       = (char**) &authParams->m_sessionIdentifier;
    paraMap[(char *) "Binding"]                 = (char**) &authParams->m_binding;
    paraMap[(char *) "PathSecurity-Protocol"]   = (char**) &authParams->m_pathSecurityProtocol;
    paraMap[(char *) "PathSecurity-Parameters"] = (char**) &authParams->m_pathSecurityParameters;
    paraMap[(char *) "RefreshAddress"]          = (char**) &authParams->m_refreshAddress;

    // TODO use the correct parameters
    IIdP* pIdP = eIdECardClient::createInstance(&paraMap);

    if (0x00 == pIdP)
      return NPACLIENT_ERROR_IDP_INSTANTIATION_ERROR;

    if (!pIdP->open())
    {
      delete pIdP;
      return NPACLIENT_ERROR_IDP_INITIALIZATION_ERROR;
    }

    // Create the nPAClient object
    nPAClient* pnPAClient = nPAClient::createInstance(pIdP);

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
extern "C" NPACLIENT_ERROR __STDCALL__ nPAFinalizeProtocol(
  NPACLIENT_HANDLE hClient)
{
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
extern "C" NPACLIENT_ERROR __STDCALL__ nPAQueryPACEInfos(
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

  // Check for the validity of the parameters.
  if (!hClient)
    return NPACLIENT_ERROR_INVALID_PARAMETER1;
  if (!chatFromCertificate || chatFromCertificate->pDataBuffer)
    return NPACLIENT_ERROR_INVALID_PARAMETER2;
  if (!chatRequired || chatRequired->pDataBuffer)
    return NPACLIENT_ERROR_INVALID_PARAMETER3;
  if (!chatOptional || chatOptional->pDataBuffer)
    return NPACLIENT_ERROR_INVALID_PARAMETER4;
  if (!certificateValidFrom)
    return NPACLIENT_ERROR_INVALID_PARAMETER5;
  if (!certificateValidTo)
    return NPACLIENT_ERROR_INVALID_PARAMETER6;
  if (!certificateDescription || chatOptional->pDataBuffer)
    return NPACLIENT_ERROR_INVALID_PARAMETER7;
  if (!serviceName || serviceName->pDataBuffer)
    return NPACLIENT_ERROR_INVALID_PARAMETER8;
  if (!serviceURL || serviceURL->pDataBuffer)
    return NPACLIENT_ERROR_INVALID_PARAMETER9;


  // Cast the handle to an pointer to an nPAClient object.
  // I know it's very unsafe :(
  nPAClient* pnPAClient = (nPAClient*) hClient;

  // Query the certificate description of the requesting service. 
  // The certificate description should be displayed to the user 
  // by the UI component.
  if (!pnPAClient->getCertificateDescription(*certificateDescription))
  {  
    return NPACLIENT_ERROR_READ_CERTIFICATE_DESCRIPTION;
  }

  // Query the name of the requesting service. The name should be displayed
  // to the user by the UI component.
  if (!pnPAClient->getServiceName(*serviceName))
  {  
    return NPACLIENT_ERROR_READ_SERVICE_NAME;
  }

  // Query the URL of the requesting service. The URL should be displayed
  // to the user by the UI component.
  if (!pnPAClient->getServiceURL(*serviceURL))
  {  
    return NPACLIENT_ERROR_READ_SERVICE_NAME;
  }

  // Query the CHAT date of the terminal certificate. The CHAT 
  // should be displayed to the user by the UI component.
  if (!pnPAClient->getCHAT(*chatFromCertificate))
  {
    return NPACLIENT_ERROR_READ_CHAT; 
  }

  // Query the required CHAT date. The CHAT 
  // should be displayed to the user by the UI component.
  if (!pnPAClient->getRequiredCHAT(*chatRequired))
  {
    return NPACLIENT_ERROR_READ_CHAT; 
  }

  // Query the optional CHAT date. The CHAT 
  // should be displayed to the user by the UI component.
  if (!pnPAClient->getOptionalCHAT(*chatOptional))
  {
    return NPACLIENT_ERROR_READ_CHAT; 
  }

   // Query the start date of the terminal certificate. The date 
  // should be displayed to the user by the UI component.
  if (!pnPAClient->getValidFromDate(*certificateValidFrom))
  { 
    return NPACLIENT_ERROR_READ_VALID_FROM_DATE;
  }

  // Query the expiration date of the terminal certificate. The date 
  // should be displayed to the user by the UI component.
  if (!pnPAClient->getValidToDate(*certificateValidTo))
  {  
    return NPACLIENT_ERROR_READ_VALID_TO_DATE;
  }

  // Query the certificate description of the requesting service. 
  // The certificate description should be displayed to the user 
  // by the UI component.
//  if (!pnPAClient->getCertificateDescriptionRaw(*certificateDescription))
  if (!pnPAClient->getCertificateDescription(*certificateDescription))	// terms of usage
  {  
    return NPACLIENT_ERROR_READ_CERTIFICATE_DESCRIPTION;
  }

  return NPACLIENT_ERROR_SUCCESS;
}

extern "C" NPACLIENT_ERROR __STDCALL__ nPAPerformPACE(
  NPACLIENT_HANDLE hClient,
  const nPADataBuffer_t *password,
  const nPADataBuffer_t *chatSelectedByUser,
  const nPADataBuffer_t *certificateDescription)
{
  NPACLIENT_ERROR error = NPACLIENT_ERROR_SUCCESS;

  if (0x00 == hClient)
    return NPACLIENT_ERROR_INVALID_PARAMETER1;

  // Cast the handle to an pointer to an nPAClient object.
  // I know it's very unsafe :(
  nPAClient* pnPAClient = (nPAClient*) hClient;

  try {
	  error = pnPAClient->performPACE(password, chatSelectedByUser, certificateDescription);
  } catch (...) {
	  return NPACLIENT_ERROR_PACE_FAILED;
  } 

  return error;
}

/*
 *
 */
NPACLIENT_ERROR __STDCALL__ nPAPerformTerminalAuthentication(
  NPACLIENT_HANDLE hClient)
{
    NPACLIENT_ERROR error;

    if (0x00 == hClient)
        return NPACLIENT_ERROR_INVALID_PARAMETER1;

    // Cast the handle to an pointer to an nPAClient object.
    // I know it's very unsafe :(
    nPAClient* pnPAClient = (nPAClient*) hClient;

    try {
        error = pnPAClient->performTerminalAuthentication();
    } catch (...) {
        return NPACLIENT_ERROR_TA_FAILED;
    }

    return error;
}

/*
 *
 */
NPACLIENT_ERROR __STDCALL__ nPAPerformChipAuthentication(
  NPACLIENT_HANDLE hClient)
{
    NPACLIENT_ERROR error;

    if (0x00 == hClient)
        return NPACLIENT_ERROR_INVALID_PARAMETER1;

    // Cast the handle to an pointer to an nPAClient object.
    // I know it's very unsafe :(
    nPAClient* pnPAClient = (nPAClient*) hClient;

    try {
        error = pnPAClient->performChipAuthentication();
    } catch (...) {
        return NPACLIENT_ERROR_CA_FAILED;
    }

    return error;
}

/*
 *
 */
NPACLIENT_ERROR __STDCALL__ nPAReadAttributes(
  NPACLIENT_HANDLE hClient)
{
  NPACLIENT_ERROR error;

  if (0x00 == hClient)
    return NPACLIENT_ERROR_INVALID_PARAMETER1;

  // Cast the handle to an pointer to an nPAClient object.
  // I know it's very unsafe :(
  nPAClient* pnPAClient = (nPAClient*) hClient;
 
  try {
      error = pnPAClient->readAttributed();
  } catch (...) {
      return NPACLIENT_ERROR_READ_FAILED;
  }

  return error;
}

/*!
 * @brief This function finalizes the communication protocol and frees all allocated 
 *        resources. The hClient handle becomes invalid after a call to this function.
 *
 * @param hClient The handle to close.
 *
 * @return NPACLIENT_ERROR_SUCCESS The protocol is finalized properly.
 */
extern "C" NPACLIENT_ERROR __STDCALL__ nPAFreeDataBuffer(
  nPADataBuffer_t* pDataBuffer)
{
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
extern "C" NPACLIENT_ERROR __STDCALL__ nPAeIdPerformAuthenticationProtocolWithParamMap(
  AuthenticationParams_t paraMap,
  ECARD_PROTOCOL usedProtocol,
  const nPAeIdUserInteractionCallback_t fnUserInteractionCallback,
  const nPAeIdProtocolStateCallback_t fnCurrentStateCallback)
{
  if (!fnUserInteractionCallback)
      return NPACLIENT_ERROR_INVALID_PARAMETER3;
  if (!fnCurrentStateCallback)
      return NPACLIENT_ERROR_INVALID_PARAMETER4;

  SPDescription_t description;
  UserInput_t input = { 0, PI_PIN, NULL, NULL };

  NPACLIENT_ERROR error = NPACLIENT_ERROR_SUCCESS;
  NPACLIENT_HANDLE hnPAClient = 0x00;

  nPADataBuffer_t bufChatFromCertificate = {0x00, 0};
  nPADataBuffer_t bufChatRequired = {0x00, 0};
  nPADataBuffer_t bufChatOptional = {0x00, 0};

  nPADataBuffer_t certificateDescription = {0x00, 0};
  nPADataBuffer_t serviceName = {0x00, 0};
  nPADataBuffer_t serviceURL = {0x00, 0};

//  nPAeIdPACEParams_t paramPACE;

  time_t certificateValidFrom = 0;
  time_t certificateValidTo = 0;

  enum DescriptionType description_type = DT_PLAIN;

  // Initialize the nPA access
  error = nPAInitializeProtocol(&paraMap, usedProtocol, &hnPAClient);
  if (hnPAClient) {
	  nPAClient* pnPAClient = (nPAClient*) hnPAClient;

	  if (pnPAClient->passwordIsRequired())
          input.pin_required = 1;
	  else
		  input.pin_required = 0;
  }
  
  fnCurrentStateCallback(NPACLIENT_STATE_INITIALIZE, error);

  if(error != NPACLIENT_ERROR_SUCCESS)
  {
	  return error;
  }

  if ((error = nPAQueryPACEInfos(hnPAClient, &bufChatFromCertificate,
				  &bufChatRequired, &bufChatOptional, &certificateValidFrom,
				  &certificateValidTo, &certificateDescription, &serviceName,
				  &serviceURL)) == NPACLIENT_ERROR_SUCCESS)
  {
	  description.description_type = &description_type;
	  description.chat_required = &bufChatRequired;
	  description.chat_optional = &bufChatOptional;
	  description.valid_from = &certificateValidFrom;
	  description.valid_to = &certificateValidTo;
	  description.description = &certificateDescription;
	  description.name = &serviceName;
	  description.url = &serviceURL;
  }

  fnCurrentStateCallback(NPACLIENT_STATE_GOT_PACE_INFO, error);

  if(error != NPACLIENT_ERROR_SUCCESS)
  {
    // We have to call this here, because  we have to free all the allocated resources.
    nPAFinalizeProtocol(hnPAClient);
    return error;
  }
  
  fnUserInteractionCallback(&description, &input);

  error = nPAPerformPACE(hnPAClient, input.pin, input.chat_selected, &certificateDescription);

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

  error = nPAReadAttributes(hnPAClient);

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

extern "C" NPACLIENT_ERROR __STDCALL__ nPAeIdPerformAuthenticationProtocolPcSc(
  const char* const IdpAddress,
  const char* const SessionIdentifier,
  const char* const PathSecurityParameters,
  const nPAeIdUserInteractionCallback_t fnUserInteractionCallback,
  const nPAeIdProtocolStateCallback_t fnCurrentStateCallback)
{
    AuthenticationParams_t authParams_;
 
    authParams_.m_serverAddress     = IdpAddress;
    authParams_.m_sessionIdentifier = SessionIdentifier;
    authParams_.m_pathSecurityParameters = PathSecurityParameters;

	return nPAeIdPerformAuthenticationProtocolWithParamMap(authParams_, PROTOCOL_PCSC, fnUserInteractionCallback, fnCurrentStateCallback);
}
