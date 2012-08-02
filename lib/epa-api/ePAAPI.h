// ---------------------------------------------------------------------------
// Copyright (c) 2009 Bundesdruckerei GmbH
// All rights reserved.
//
// $Id: ePAAPI.h 1289 2011-09-06 09:29:44Z dietrfra $
// ---------------------------------------------------------------------------

#if !defined(__EPAAPI_INCLUDED__)
#define __EPAAPI_INCLUDED__

#include <vector>
#include "eCardCore.h"

/**
 * @file ePAAPI.h
 * @brief This file describes the ePA-API. The ePA-API is used to communicate with 
 *        the ePA card and to perform all needed protocols to access the ePA.
 */


/**
 * @struct KEY_REFERENCE
 */
typedef enum KEY_REFERENCE_t
{
  MRZ = 1,
  CAN,
  PIN,
  PUK
} KEY_REFERENCE;

/**
 * @brief Perform the PACE protocol. For further information look at
 *        EAC 2.01.
 *
 * @param hCard         [IN] Handle to an valid ePA card.
 * @param keyReference  [IN] The reference to the key which is to be used. @see KEY_REFERENCE
 * @param chat          [IN] The CHAT (may be restricted by the user) to be used.
 * @param password      [IN] The password provided by the user.
 * @param efCardAccess  [IN] The content of the EF.CardAccess file.
 * @param car_cvca      [OUT] The CAR of the CVCA stored into the chip.
 * @param x_Puk_ICC_DH2 [OUT] The x part of PuK.ICC.DH2. This part will be needed while the terminal authentication.
 *
 * @return ECARD_SUCCESS if successfully. All other values indication an error.
 *
 * @since 1.0
 */
ECARD_STATUS __STDCALL__ ePAPerformPACE(
  IN ECARD_HANDLE hCard,
  IN KEY_REFERENCE keyReference,
  IN const std::vector<unsigned char>& chat,
  IN const std::vector<unsigned char>& certificate_description,
  IN const std::vector<unsigned char>& password,
  IN const std::vector<unsigned char>& efCardAccess,
  IN OUT std::vector<unsigned char>& car_cvca,
  IN OUT std::vector<unsigned char>& x_Puk_ICC_DH2,
  OUT unsigned char* PINCount);

/**
 * @brief Perform the Terminal Authentication protocol. For further information look at
 *        EAC 2.01.
 *
 * @param hCard               [IN] Handle to an valid ePA card.
 * @param efCardAccess        [IN] The content of the EF.CardAccess file.
 * @param car_cvca            [IN] The CAR of the CVCA stored into the chip.
 * @param list_certificates   [IN] The raw list of link certificates and DVCA certificate.
 * @param terminalCertificate [IN] The raw certificate of the terminal.
 * @param x_Puk_ICC_DH_CA     [IN] The x part of PuK.IFD_DH_CA. This data is part of the public key used for the chip 
 *                                 authentication and will be created on the eID server. @see eIDServer.cpp function createChipAuthenticationKey
 * @param toBeSigned          [IN][OUT] The data which will be signed by the eID server.
 *
 * @return ECARD_SUCCESS if successfully. All other values indication an error.
 *
 * @since 1.0
 */
ECARD_STATUS __STDCALL__ ePAPerformTA(
  IN ECARD_HANDLE hCard,
  IN const std::vector<unsigned char>& efCardAccess,
  IN const std::vector<unsigned char>& car_cvca,
  IN const std::vector<std::vector<unsigned char> >& list_certificates,
  IN const std::vector<unsigned char>& terminalCertificate,
  IN const std::vector<unsigned char>& x_Puk_IFD_DH_CA,
  IN const std::vector<unsigned char>& authenticatedAuxiliaryData,
  IN OUT std::vector<unsigned char>& toBeSigned);

/**
 * @brief Send the signature data to the chip. The signature will be created on 
 *        the eID server @see eIDServer.cpp function createServerSignature.
 *
 * @param hCard     [IN] Handle to an valid ePA card.
 * @param signature [IN] The raw signature data which will be send to the chip.
 *
 * @return ECARD_SUCCESS if successfully. All other values indication an error.
 *
 * @since 1.0
 */
ECARD_STATUS __STDCALL__ ePASendSignature(
  IN ECARD_HANDLE hCard,
  IN const std::vector<unsigned char>& signature);

/**
 * @param hCard                       [IN] Handle to an valid ePA card.
 * @param x_Puk_IFD_DH                [IN] The x part of the public key used for chip authentication. @see eIDServer.cpp function createChipAuthenticationKey
 * @param y_Puk_IFD_DH                [IN] The y part of the public key used for chip authentication. @see eIDServer.cpp function createChipAuthenticationKey
 * @param GeneralAuthenticationResult [OUT] The last result from the client side chip communication. This data must be send to the eID Server to create the new
 *                                          secure messaging keys.
 *
 * @return ECARD_SUCCESS if successfully. All other values indication an error.
 *
 * @since 1.0
 */
ECARD_STATUS __STDCALL__ ePAPerformCA(
  IN ECARD_HANDLE hCard,
  IN const std::vector<unsigned char>& x_Puk_IFD_DH,
  IN const std::vector<unsigned char>& y_Puk_IFD_DH,
  IN OUT std::vector<unsigned char>& GeneralAuthenticationResult);

#endif // #if !defined(__EPAPAPI_INCLUDED__)
