#if !defined(__NPAAPI_INCLUDED__)
#define __NPAAPI_INCLUDED__

#include "eCardCore/IReader.h"
#include "eCardCore/eCardStatus.h"
#include "eCardCore/eCardTypes.h"
#include "nPA-EAC/nPACard.h"
#include <vector>

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

/**
 * @file nPAAPI.h
 * @brief Communicates with the nPA card and to perform all needed protocols to
 * access the nPA.
 */


/**
 * @brief Perform the PACE protocol. For further information look at
 *        EAC 2.01.
 *
 * @param hCard         [IN] Handle to an valid nPA card.
 * @param pace_input    [IN]
 * @param car_cvca      [OUT] The CAR of the CVCA stored into the chip.
 * @param x_Puk_ICC_DH2 [OUT] The x part of PuK.ICC.DH2. This part will be needed while the terminal authentication.
 *
 * @return ECARD_SUCCESS if successfully. All other values indication an error.
 *
 * @since 1.0
 */
ECARD_STATUS __STDCALL__ ePAPerformPACE(
  Bundesdruckerei::nPA::ePACard& hCard,
  const PaceInput& pace_input,
  std::vector<unsigned char>& car_cvca,
  std::vector<unsigned char>& x_Puk_ICC_DH2,
  unsigned char* PINCount);

/**
 * @brief Perform the Terminal Authentication protocol. For further information look at
 *        EAC 2.01.
 *
 * @param hCard               [IN] Handle to an valid nPA card.
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
  Bundesdruckerei::nPA::ePACard& hCard,
  const std::vector<unsigned char>& car_cvca,
  const std::vector<std::vector<unsigned char> >& list_certificates,
  const std::vector<unsigned char>& terminalCertificate,
  const std::vector<unsigned char>& x_Puk_IFD_DH_CA,
  const std::vector<unsigned char>& authenticatedAuxiliaryData,
  std::vector<unsigned char>& toBeSigned);

/**
 * @brief Send the signature data to the chip. The signature will be created on 
 *        the eID server @see eIDServer.cpp function createServerSignature.
 *
 * @param hCard     [IN] Handle to an valid nPA card.
 * @param signature [IN] The raw signature data which will be send to the chip.
 *
 * @return ECARD_SUCCESS if successfully. All other values indication an error.
 *
 * @since 1.0
 */
ECARD_STATUS __STDCALL__ ePASendSignature(
  ICard& hCard,
  const std::vector<unsigned char>& signature);

/**
 * @param hCard                       [IN] Handle to an valid nPA card.
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
  ICard& hCard,
  const std::vector<unsigned char>& x_Puk_IFD_DH,
  const std::vector<unsigned char>& y_Puk_IFD_DH,
  std::vector<unsigned char>& GeneralAuthenticationResult);

#endif // #if !defined(__EPAPAPI_INCLUDED__)
