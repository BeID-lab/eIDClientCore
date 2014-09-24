/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

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
 * @param idPICC        [OUT] The x part of PuK.ICC.DH2. This part will be needed while the terminal authentication.
 *
 * @return ECARD_SUCCESS if successfully. All other values indication an error.
 *
 * @since 1.0
 */
ECARD_STATUS __STDCALL__ ePAPerformPACE(
	ePACard &hCard,
	const PaceInput &pace_input,
	std::vector<unsigned char>& car_cvca,
	std::vector<unsigned char>& idPICC,
	std::vector<unsigned char>& CA_OID,
	std::vector<unsigned char>& chat_used);

/**
 * @brief Perform the Terminal Authentication protocol. For further information look at
 *        EAC 2.01.
 *
 * @param hCard               [IN] Handle to an valid nPA card.
 * @param car_cvca            [IN] The CAR of the CVCA stored into the chip.
 * @param list_certificates   [IN] The raw list of link certificates and DVCA certificate.
 * @param terminalCertificate [IN] The raw certificate of the terminal.
 * @param Puk_ICC_DH_CA       [IN] This data is part of the public key used for the chip
 *                                 authentication and will be created on the eID server. @see eIDServer.cpp function createChipAuthenticationKey
 * @param toBeSigned          [IN][OUT] The data which will be signed by the eID server.
 *
 * @return ECARD_SUCCESS if successfully. All other values indication an error.
 *
 * @since 1.0
 */
ECARD_STATUS __STDCALL__ ePAPerformTA(
	ePACard &hCard,
	const std::vector<unsigned char>& car_cvca,
	const std::vector<std::vector<unsigned char> >& list_certificates,
	const std::vector<unsigned char>& terminalCertificate,
	const std::vector<unsigned char>& CA_OID,
	const std::vector<unsigned char>& Puk_IFD_DH_CA,
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
	ICard &hCard,
	const std::vector<unsigned char>& signature);

/**
 * @param hCard                       [IN] Handle to an valid nPA card.
 * @param Puk_IFD_DH                  [IN] The public key used for chip authentication. @see eIDServer.cpp function createChipAuthenticationKey
 * @param GeneralAuthenticationResult [OUT] The last result from the client side chip communication. This data must be send to the eID Server to create the new
 *                                          secure messaging keys.
 *
 * @return ECARD_SUCCESS if successfully. All other values indication an error.
 *
 * @since 1.0
 */
ECARD_STATUS __STDCALL__ ePAPerformCA(
	ICard &hCard,
	const std::vector<unsigned char>& CA_OID,
	const std::vector<unsigned char>& Puk_IFD_DH,
	std::vector<unsigned char>& GeneralAuthenticationResult);

ECARD_STATUS __STDCALL__ ePAGetRandom(
	size_t size, std::vector<unsigned char>& random_bytes);

extern "C" ECARD_STATUS __STDCALL__ encode_EstablishPACEChannelInput(
        const unsigned char pinid,
        const unsigned char *pin,
        size_t pin_len,
        const unsigned char *chat,
        size_t chat_len,
        const unsigned char *chat_required,
        size_t chat_required_len,
        const unsigned char *chat_optional,
        size_t chat_optional_len,
        const unsigned char *certificate_description,
        size_t certificate_description_len,
        const unsigned char *transaction_info_hidden,
        size_t transaction_info_hidden_len,
		unsigned char *oid_hash_transactiondata,
        size_t oid_hash_transactiondata_len,
        unsigned char **bufEstablishPACEChannelInput,
        size_t *tablishPACEChannelInput_len);

extern "C" ECARD_STATUS __STDCALL__ decode_EstablishPACEChannelOutput(
        unsigned char* const bufEstablishPACEChannelOutput,
        size_t const bufEstablishPACEChannelOutput_len,
        unsigned int* const result,
        unsigned short* const status_mse_set_at,
        unsigned char** const ef_cardaccess,
        size_t* const ef_cardaccess_len,
        unsigned char** const car_curr,
        size_t* const car_curr_len,
        unsigned char** const car_prev,
        size_t* const car_prev_len,
        unsigned char** const id_icc,
        size_t* const id_icc_len,
        unsigned char** const chat,
        size_t* const chat_len);

typedef ECARD_STATUS (*encode_EstablishPACEChannelInput_t)(
        const unsigned char pinid,
        const unsigned char *pin,
        size_t pin_len,
        const unsigned char *chat,
        size_t chat_len,
        const unsigned char *chat_required,
        size_t chat_required_len,
        const unsigned char *chat_optional,
        size_t chat_optional_len,
        const unsigned char *certificate_description,
        size_t certificate_description_len,
        const unsigned char *transaction_info_hidden,
        size_t transaction_info_hidden_len,
        unsigned char **bufEstablishPACEChannelInput,
        size_t *tablishPACEChannelInput_len);

typedef ECARD_STATUS (*decode_EstablishPACEChannelOutput_t)(
        unsigned char* const bufEstablishPACEChannelOutput,
        size_t const bufEstablishPACEChannelOutput_len,
        unsigned int* const result,
        unsigned short* const status_mse_set_at,
        unsigned char** const ef_cardaccess,
        size_t* const ef_cardaccess_len,
        unsigned char** const car_curr,
        size_t* const car_curr_len,
        unsigned char** const car_prev,
        size_t* const car_prev_len,
        unsigned char** const id_icc,
        size_t* const id_icc_len,
        unsigned char** const chat,
        size_t* const chat_len);

#endif // #if !defined(__EPAPAPI_INCLUDED__)
