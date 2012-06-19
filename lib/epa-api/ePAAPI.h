// ---------------------------------------------------------------------------
// Copyright (c) 2009 Bundesdruckerei GmbH
// All rights reserved.
//
// $Id: ePAAPI.h 1289 2011-09-06 09:29:44Z dietrfra $
// ---------------------------------------------------------------------------

#if !defined(__EPAAPI_INCLUDED__)
#define __EPAAPI_INCLUDED__

#include <eCardCore.h>
#include <list>

/**
 * @file ePAAPI.h
 * @brief This file describes the ePA-API. The ePA-API is used to communicate with 
 *        the ePA card and to perform all needed protocols to access the ePA.
 *
 * @todo: I think it will be better to bundle the runtime data (kEnc, kMac, ssc, ...) to an object wicht will be used. The user of the API should not be
 *        nerved by this data.
 */

#if defined(__cplusplus)
extern "C"
{
#endif

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
 * @param kMac          [OUT] The resulting key used for the MAC algorithm while secure messaging within the next protocol steps.
 * @param kEnc          [OUT] The resulting key used for the encryption algorithm while secure messaging within the next protocol steps.
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
  IN BYTE_INPUT_DATA chat,
  IN BYTE_INPUT_DATA certificate_description,
  IN BYTE_INPUT_DATA password,
  IN BYTE_INPUT_DATA efCardAccess,
  IN OUT BYTE_OUTPUT_DATA& kMac,
  IN OUT BYTE_OUTPUT_DATA& kEnc,
  IN OUT BYTE_OUTPUT_DATA& car_cvca,
  IN OUT BYTE_OUTPUT_DATA& x_Puk_ICC_DH2,
  OUT unsigned char* PINCount);

/**
 * @brief Perform the Terminal Authentication protocol. For further information look at
 *        EAC 2.01.
 *
 * @param hCard               [IN] Handle to an valid ePA card.
 * @param kEnc                [IN] The key used for the encryption algorithm while secure messaging.
 * @param kMac                [IN] The key used for the MAC algorithm while secure messaging.
 * @param ssc                 [IN][OUT] The send sequence counter for secure messaging. The initial value MUST be 0.
 * @param efCardAccess        [IN] The content of the EF.CardAccess file.
 * @param car_cvca            [IN] The CAR of the CVCA stored into the chip.
 * @param list_certificates   [IN] The raw list of link certificates and DVCA certificate.
 * @param terminalCertificate [IN] The raw certificate of the terminal.
 * @param x_Puk_ICC_DH2       [IN] The x part of PuK.ICC.DH2. This data will be provided by the PACE operation. @see ePAPerformPACE
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
  IN BYTE_INPUT_DATA kEnc,
  IN BYTE_INPUT_DATA kMac,
  IN OUT unsigned long long &ssc,
  IN BYTE_INPUT_DATA efCardAccess,
  IN BYTE_INPUT_DATA car_cvca,
  IN std::list<BYTE_INPUT_DATA> list_certificates,
  IN BYTE_INPUT_DATA terminalCertificate,
  IN BYTE_INPUT_DATA x_Puk_ICC_DH2,
  IN BYTE_INPUT_DATA x_Puk_IFD_DH_CA,
  IN BYTE_INPUT_DATA authenticatedAuxiliaryData,
  IN OUT BYTE_OUTPUT_DATA& toBeSigned);

/**
 * @brief Send the signature data to the chip. The signature will be created on 
 *        the eID server @see eIDServer.cpp function createServerSignature.
 *
 * @param hCard     [IN] Handle to an valid ePA card.
 * @param kEnc      [IN] The key used for the encryption algorithm while secure messaging.
 * @param kMac      [IN] The key used for the MAC algorithm while secure messaging.
 * @param ssc       [IN][OUT] The send sequence counter for secure messaging.
 * @param signature [IN] The raw signature data which will be send to the chip.
 *
 * @return ECARD_SUCCESS if successfully. All other values indication an error.
 *
 * @since 1.0
 */
ECARD_STATUS __STDCALL__ ePASendSignature(
  IN ECARD_HANDLE hCard,
  IN BYTE_INPUT_DATA kEnc,
  IN BYTE_INPUT_DATA kMac,
  IN OUT unsigned long long &ssc,
  IN BYTE_INPUT_DATA signature);

/**
 * @param hCard                       [IN] Handle to an valid ePA card.
 * @param kEnc                        [IN] The key used for the encryption algorithm while secure messaging.
 * @param kMac                        [IN] The key used for the MAC algorithm while secure messaging.
 * @param ssc                         [IN][OUT] The send sequence counter for secure messaging.
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
  IN BYTE_INPUT_DATA kEnc,
  IN BYTE_INPUT_DATA kMac,
  IN OUT unsigned long long &ssc,
  IN BYTE_INPUT_DATA x_Puk_IFD_DH,
  IN BYTE_INPUT_DATA y_Puk_IFD_DH,
  IN OUT BYTE_OUTPUT_DATA& GeneralAuthenticationResult);

/**
 *
 */
ECARD_STATUS __STDCALL__ ePASendAPDU(
  IN ECARD_HANDLE hCard,
  IN BYTE_INPUT_DATA capdu,
  IN OUT BYTE_OUTPUT_DATA& rapdu);

#if defined(__cplusplus)
}
#endif

#endif // #if !defined(__EPAPAPI_INCLUDED__)
