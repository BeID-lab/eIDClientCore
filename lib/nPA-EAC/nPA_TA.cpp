/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#include "nPAAPI.h"
#include "nPAStatus.h"
#include "nPACard.h"
#include <debug.h>
using namespace Bundesdruckerei::nPA;

#include "eCardCore/ICard.h"
#include <SecurityInfos.h>
#include <PACEDomainParameterInfo.h>
#include "eidasn1/eIDHelper.h"
#include "eidasn1/eIDOID.h"
#include "nPACommon.h"

USING_NAMESPACE(CryptoPP)

#include <cstdio>
#include <fstream>

ECARD_STATUS __STDCALL__ perform_TA_Step_Set_CAR(
	std::vector<unsigned char> &carCVCA,
	ICard &card_)
{
	MSE mse(MSE::P1_SET | MSE::P1_VERIFY, MSE::P2_DST);
	std::vector<unsigned char> dataPart_;
	dataPart_.push_back(0x83);
	dataPart_.push_back((unsigned char) carCVCA.size());

	// Append the CAR
	for (size_t i = 0; i < carCVCA.size() ; i++)
		dataPart_.push_back(carCVCA[i]);

	mse.setData(dataPart_);
	eCardCore_info(DEBUG_LEVEL_CRYPTO, "Send MANAGE SECURITY ENVIRONMENT to set CAR for PuK.CVCA.xy.n");
	RAPDU rapdu = card_.sendAPDU(mse);

	if (rapdu.getSW() != RAPDU::ISO_SW_NORMAL)
		return ECARD_TA_STEP_A_FAILED;

	return ECARD_SUCCESS;
}

ECARD_STATUS __STDCALL__ perform_TA_Step_Verify_Certificate(
	const std::vector<unsigned char>& cvcertificate,
	ICard &card_)
{
	size_t copyOffset = 0;

	// Check for certificate header and cut off is needed
	if (cvcertificate[0] == 0x7F && cvcertificate[1] == 0x21) {
		// One length byte
		if (cvcertificate[2] == 0x81)
			copyOffset = 4;

		// Two length bytes
		if (cvcertificate[2] == 0x82)
			copyOffset = 5;

	} else if (cvcertificate[0] == 0x7F && cvcertificate[1] == 0x4E) {
		// Copy all
		copyOffset = 0;

	} else {
		// Invalid certificate format
		return ECARD_TA_STEP_B_INVALID_CERTIFCATE_FORMAT;
	}

	std::vector<unsigned char> cvcertificate_;

	// Copy the terminal certificate for further usage.
	for (size_t i = copyOffset; i < cvcertificate.size(); i++)
		cvcertificate_.push_back(cvcertificate[i]);

	PSO verify = PSO(0x00, PSO::TAG_VERIFY_CERTIFICATE);
	verify.setData(cvcertificate_);
	eCardCore_info(DEBUG_LEVEL_CRYPTO, "Send VERIFY CERTIFICATE.");
	RAPDU rapdu = card_.sendAPDU(verify);

	if (rapdu.getSW() != RAPDU::ISO_SW_NORMAL)
		return ECARD_TA_STEP_B_FAILED;

	return ECARD_SUCCESS;
}

ECARD_STATUS __STDCALL__ perform_TA_Step_E(
	const std::vector<unsigned char>& keyID,
	const std::vector<unsigned char>& x_Puk_IFD_DH,
	const std::vector<unsigned char>& authenticatedAuxiliaryData,
	ICard &card_)
{
	MSE mse(MSE::P1_SET | MSE::P1_VERIFY, MSE::P2_AT);
	// @TODO Get the right oid for TA
	std::vector<unsigned char> dataField;
	dataField.push_back(0x80); // OID for algorithm id_TA_ECDSA_SHA_1
	dataField.push_back(0x0A);
	dataField.push_back(0x04);
	dataField.push_back(0x00);
	dataField.push_back(0x7F);
	dataField.push_back(0x00);
	dataField.push_back(0x07);
	dataField.push_back(0x02);
	dataField.push_back(0x02);
	dataField.push_back(0x02);
	dataField.push_back(0x02);
	dataField.push_back(0x03);
	dataField.push_back(0x83); // keyId
	dataField.push_back((unsigned char) keyID.size());

	for (size_t i = 0; i < keyID.size(); i++)
		dataField.push_back(keyID[i]);

	dataField.push_back(0x91); // x(Puk.IFD.CA)
	dataField.push_back((unsigned char) x_Puk_IFD_DH.size());

	for (size_t i = 0; i < x_Puk_IFD_DH.size(); i++)
		dataField.push_back(x_Puk_IFD_DH[i]);

	for (size_t i = 0; i < authenticatedAuxiliaryData.size(); i++)
		dataField.push_back(authenticatedAuxiliaryData[i]);

	mse.setData(dataField);
	eCardCore_info(DEBUG_LEVEL_CRYPTO, "Send SET MSE AT for authentication.");
	RAPDU rapdu = card_.sendAPDU(mse);

	if (rapdu.getSW() != RAPDU::ISO_SW_NORMAL)
		return ECARD_TA_STEP_E_FAILED;

	return ECARD_SUCCESS;
}

#define TA_LENGTH_NONCE 8
ECARD_STATUS __STDCALL__ perform_TA_Step_F(
	std::vector<unsigned char>& RND_ICC,
	ICard &card_)
{
	GetChallenge get(GetChallenge::P1_NO_INFO);
	get.setNe(TA_LENGTH_NONCE);
	eCardCore_info(DEBUG_LEVEL_CRYPTO, "Send GET CHALLENGE to get encrypted nonce.");
	RAPDU rapdu = card_.sendAPDU(get);

	if (rapdu.getSW() != RAPDU::ISO_SW_NORMAL)
		return ECARD_TA_STEP_F_FAILED;

	RND_ICC = rapdu.getData();
	return ECARD_SUCCESS;
}

ECARD_STATUS __STDCALL__ perform_TA_Step_G(
	const std::vector<unsigned char>& signature,
	ICard &card_)
{
	ExternalAuthenticate authenticate(ExternalAuthenticate::P1_NO_INFO, ExternalAuthenticate::P2_NO_INFO);
	authenticate.setData(signature);
	eCardCore_info(DEBUG_LEVEL_CRYPTO, "EXTERNAL AUTHENTICATE for signature verification.");
	RAPDU rapdu = card_.sendAPDU(authenticate);

	if (rapdu.getSW() != RAPDU::ISO_SW_NORMAL)
		return ECARD_TA_STEP_G_FAILED;

	return ECARD_SUCCESS;
}

ECARD_STATUS __STDCALL__ ePAPerformTA(
	ePACard &hCard,
	const std::vector<unsigned char>& carCVCA,
	const std::vector<std::vector<unsigned char> >& list_certificates,
	const std::vector<unsigned char>& terminalCertificate,
	const std::vector<unsigned char>& x_Puk_IFD_DH_CA,
	const std::vector<unsigned char>& authenticatedAuxiliaryData,
	std::vector<unsigned char>& toBeSigned)
{
	ECARD_STATUS status = ECARD_SUCCESS;
	// Parse the EF.CardAccess file to get needed information.
	SecurityInfos   *secInfos_ = 0x00;

	if (ber_decode(0, &asn_DEF_SecurityInfos, (void **)&secInfos_, hCard.get_ef_cardaccess().data(), hCard.get_ef_cardaccess().size()).code != RC_OK) {
		asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
		return ECARD_EFCARDACCESS_PARSER_ERROR;
	}

	OBJECT_IDENTIFIER_t PACE_OID_ = {NULL, 0};
	AlgorithmIdentifier *PACEDomainParameterInfo_ = 0x00;

	for (int i = 0; i < secInfos_->list.count; i++) {
		OBJECT_IDENTIFIER_t oid = secInfos_->list.array[i]->protocol;
		{
			// Find the algorithm for PACE ...
			OBJECT_IDENTIFIER_t PACE_ECDH_3DES_CBC_CBC     = makeOID(id_PACE_ECDH_3DES_CBC_CBC);
			OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_128 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_128);
			OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_192 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_192);
			OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_256 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_256);

			if (PACE_ECDH_3DES_CBC_CBC == oid || PACE_ECDH_AES_CBC_CMAC_128 == oid ||
				PACE_ECDH_AES_CBC_CMAC_192 == oid || PACE_ECDH_AES_CBC_CMAC_256 == oid)
				PACE_OID_ = oid;

			asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_3DES_CBC_CBC, 1);
			asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_128, 1);
			asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_192, 1);
			asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_256, 1);
		} // Find the algorithm for PACE ...
		{
			OBJECT_IDENTIFIER_t oidCheck = makeOID(id_PACE_ECDH);

			// Find the PACEDomainParameter
			if (oidCheck == oid) {
				if (ber_decode(0, &asn_DEF_AlgorithmIdentifier, (void **)&PACEDomainParameterInfo_,
							   secInfos_->list.array[i]->requiredData.buf, secInfos_->list.array[i]->requiredData.size).code != RC_OK) {
					asn_DEF_AlgorithmIdentifier.free_struct(&asn_DEF_AlgorithmIdentifier, PACEDomainParameterInfo_, 0);
					asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
					return ECARD_EFCARDACCESS_PARSER_ERROR;
				}
			}

			asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &oidCheck, 1);
		}
	}

	size_t filler_ = 0;

	if (x_Puk_IFD_DH_CA.size() <= 32)
		filler_ = 32 - x_Puk_IFD_DH_CA.size();

	// Copy the x part of the public key for chip authentication. This key was created on the server.
	std::vector<unsigned char> x_Puk_IFD_DH_;

	for (size_t i = 0; i < filler_; i++)
		x_Puk_IFD_DH_.push_back(0x00);

	for (size_t i = 0; i < x_Puk_IFD_DH_CA.size(); i++)
		x_Puk_IFD_DH_.push_back(x_Puk_IFD_DH_CA[i]);

	/* TODO verify the chain of certificates in the middle ware */
	std::vector<unsigned char> _current_car = carCVCA;

	for (size_t i = 0; i < list_certificates.size(); i++) {
		std::string current_car;
		hexdump(DEBUG_LEVEL_CRYPTO, "CAR", _current_car.data(), _current_car.size());

		if (ECARD_SUCCESS != (status = perform_TA_Step_Set_CAR(_current_car, hCard))) {
			asn_DEF_AlgorithmIdentifier.free_struct(&asn_DEF_AlgorithmIdentifier, PACEDomainParameterInfo_, 0);
			asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
			return status;
		}

		std::vector<unsigned char> cert;
		cert = list_certificates[i];
		hexdump(DEBUG_LEVEL_CRYPTO, "certificate", cert.data(), cert.size());

		if (ECARD_SUCCESS != (status = perform_TA_Step_Verify_Certificate(cert, hCard))) {
			asn_DEF_AlgorithmIdentifier.free_struct(&asn_DEF_AlgorithmIdentifier, PACEDomainParameterInfo_, 0);
			asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
			return status;
		}

		current_car = getCHR(cert);
		_current_car = std::vector<unsigned char>(current_car.begin(), current_car.end());
	}

	std::string chrTerm_ = getCHR(terminalCertificate);
	hexdump(DEBUG_LEVEL_CRYPTO, "TERM CHR: ", chrTerm_.data(), chrTerm_.size());

	if (ECARD_SUCCESS != (status = perform_TA_Step_E(_current_car, x_Puk_IFD_DH_, authenticatedAuxiliaryData, hCard))) {
		asn_DEF_AlgorithmIdentifier.free_struct(&asn_DEF_AlgorithmIdentifier, PACEDomainParameterInfo_, 0);
		asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
		return status;
	}

	std::vector<unsigned char> RND_ICC_;

	if (ECARD_SUCCESS != (status = perform_TA_Step_F(RND_ICC_, hCard))) {
		asn_DEF_AlgorithmIdentifier.free_struct(&asn_DEF_AlgorithmIdentifier, PACEDomainParameterInfo_, 0);
		asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
		return status;
	}

	// Copy the data to the output buffer.
	toBeSigned = RND_ICC_;
	asn_DEF_AlgorithmIdentifier.free_struct(&asn_DEF_AlgorithmIdentifier, PACEDomainParameterInfo_, 0);
	asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
	return ECARD_SUCCESS;
}

ECARD_STATUS __STDCALL__ ePASendSignature(
	ICard &hCard,
	const std::vector<unsigned char>& signature)
{
	ECARD_STATUS status = ECARD_SUCCESS;

	if (ECARD_SUCCESS != (status = perform_TA_Step_G(signature, hCard)))
		return status;

	return ECARD_SUCCESS;
}
