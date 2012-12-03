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

CAPDU build_TA_Step_Set_CAR(
		std::vector<unsigned char> &carCVCA)
{
	MSE mse(MSE::P1_SET | MSE::P1_VERIFY, MSE::P2_DST);

	mse.setData(TLV_encode(0x83, carCVCA));

	return mse;
}

ECARD_STATUS __STDCALL__ process_TA_Step_Set_CAR(const RAPDU &rapdu)
{
	if (rapdu.getSW() != RAPDU::ISO_SW_NORMAL)
		return ECARD_TA_STEP_A_FAILED;

	return ECARD_SUCCESS;
}

CAPDU build_TA_Step_Verify_Certificate(
		const std::vector<unsigned char>& cvcertificate)
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
		eCardCore_warn(DEBUG_LEVEL_CRYPTO, "Invalid certificate format.");
	}

	std::vector<unsigned char> cvcertificate_;

	// Copy the terminal certificate for further usage.
	for (size_t i = copyOffset; i < cvcertificate.size(); i++)
		cvcertificate_.push_back(cvcertificate[i]);

	PSO verify = PSO(0x00, PSO::TAG_VERIFY_CERTIFICATE);
	verify.setData(cvcertificate_);
	
	return verify;
}

ECARD_STATUS __STDCALL__ process_TA_Step_Verify_Certificate(
		const RAPDU &rapdu)
{
	if (rapdu.getSW() != RAPDU::ISO_SW_NORMAL)
		return ECARD_TA_STEP_B_FAILED;

	return ECARD_SUCCESS;
}

CAPDU build_TA_Step_E(
		const std::vector<unsigned char>& keyID,
		const OBJECT_IDENTIFIER_t& CA_OID,
		const std::vector<unsigned char>& Puk_IFD_DH,
		const std::vector<unsigned char>& authenticatedAuxiliaryData)
{
	MSE mse(MSE::P1_SET | MSE::P1_VERIFY, MSE::P2_AT);
	// @TODO Get the right oid for TA
	std::vector<unsigned char> dataField, do83, do91;
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

	// keyId
	do83 = TLV_encode(0x83, keyID);
	dataField.insert(dataField.end(), do83.begin(), do83.end());

	// x(Puk.IFD.CA)
	std::vector<unsigned char> x_Puk_IFD_DH;
	OBJECT_IDENTIFIER_t ca_dh = makeOID(id_CA_DH);
	OBJECT_IDENTIFIER_t ca_ecdh = makeOID(id_CA_ECDH);
	if (ca_dh < CA_OID) {
		x_Puk_IFD_DH = Puk_IFD_DH;
	} else if (ca_ecdh < CA_OID) {
		x_Puk_IFD_DH = std::vector<unsigned char>
			(Puk_IFD_DH.begin(), Puk_IFD_DH.begin()+Puk_IFD_DH.size()/2);
	} else {
		eCardCore_warn(DEBUG_LEVEL_CRYPTO, "Invalid CA OID.");
	}
	do91 = TLV_encode(0x91, x_Puk_IFD_DH);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &ca_dh, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &ca_ecdh, 1);
	dataField.insert(dataField.end(), do91.begin(), do91.end());

	dataField.insert(dataField.end(), authenticatedAuxiliaryData.begin(),
			authenticatedAuxiliaryData.end());

	mse.setData(dataField);

	return mse;
}

ECARD_STATUS __STDCALL__ process_TA_Step_E(
		const RAPDU &rapdu)
{
	if (rapdu.getSW() != RAPDU::ISO_SW_NORMAL)
		return ECARD_TA_STEP_E_FAILED;

	return ECARD_SUCCESS;
}

#define TA_LENGTH_NONCE 8
CAPDU build_TA_Step_F(void)
{
	GetChallenge get(GetChallenge::P1_NO_INFO);
	get.setNe(TA_LENGTH_NONCE);

	return get;
}

ECARD_STATUS __STDCALL__ process_TA_Step_F(
		std::vector<unsigned char>& RND_ICC,
		const RAPDU &rapdu)
{
	if (rapdu.getSW() != RAPDU::ISO_SW_NORMAL)
		return ECARD_TA_STEP_F_FAILED;

	RND_ICC = rapdu.getData();

	return ECARD_SUCCESS;
}

CAPDU build_TA_Step_G(
		const std::vector<unsigned char>& signature)
{
	ExternalAuthenticate authenticate(ExternalAuthenticate::P1_NO_INFO, ExternalAuthenticate::P2_NO_INFO);
	authenticate.setData(signature);

	return authenticate;
}

ECARD_STATUS __STDCALL__ process_TA_Step_G(const RAPDU &rapdu)
{
	if (rapdu.getSW() != RAPDU::ISO_SW_NORMAL)
		return ECARD_TA_STEP_G_FAILED;

	return ECARD_SUCCESS;
}

ECARD_STATUS __STDCALL__ ePAPerformTA(
	ePACard &hCard,
	const std::vector<unsigned char>& carCVCA,
	const std::vector<std::vector<unsigned char> >& list_certificates,
	const std::vector<unsigned char>& terminalCertificate,
	const std::vector<unsigned char>& CA_OID,
	const std::vector<unsigned char>& Puk_IFD_DH_CA,
	const std::vector<unsigned char>& authenticatedAuxiliaryData,
	std::vector<unsigned char>& toBeSigned)
{
	ECARD_STATUS status = ECARD_SUCCESS;
	const OBJECT_IDENTIFIER_t ca_oid = {(unsigned char *) CA_OID.data(), CA_OID.size()};
	vector<CAPDU> capdus;

	/* build all APDUs */

	/* TODO verify the chain of certificates in the middle ware */
	std::vector<unsigned char> _current_car = carCVCA;
	for (size_t i = 0; i < list_certificates.size(); i++) {
		std::string current_car;
		hexdump(DEBUG_LEVEL_CRYPTO, "CAR", _current_car.data(), _current_car.size());

		capdus.push_back(build_TA_Step_Set_CAR(_current_car));

		std::vector<unsigned char> cert;
		cert = list_certificates[i];
		hexdump(DEBUG_LEVEL_CRYPTO, "certificate", cert.data(), cert.size());

		capdus.push_back(build_TA_Step_Verify_Certificate(cert));

		current_car = getCHR(cert);
		_current_car = std::vector<unsigned char>(current_car.begin(), current_car.end());
	}

	std::string chrTerm_ = getCHR(terminalCertificate);
	hexdump(DEBUG_LEVEL_CRYPTO, "TERM CHR: ", chrTerm_.data(), chrTerm_.size());

	capdus.push_back(build_TA_Step_E(_current_car, ca_oid, Puk_IFD_DH_CA, authenticatedAuxiliaryData));
	capdus.push_back(build_TA_Step_F());


	/* transmit all apdus */

	vector<RAPDU> rapdus = hCard.sendAPDUs(capdus);
	if (rapdus.size() != capdus.size())
		return ECARD_EFCARDACCESS_PARSER_ERROR;


	/* process all RAPDUs */

	size_t rapdu_index = 0;
	for (size_t i = 0; i < list_certificates.size(); i++) {
		if (ECARD_SUCCESS != (status = process_TA_Step_Set_CAR(rapdus[rapdu_index])))
			return status;
		rapdu_index++;

		if (ECARD_SUCCESS != (status = process_TA_Step_Verify_Certificate(rapdus[rapdu_index])))
			return status;
		rapdu_index++;
	}

	if (ECARD_SUCCESS != (status = process_TA_Step_E(rapdus[rapdu_index])))
		return status;
	rapdu_index++;

	std::vector<unsigned char> RND_ICC_;
	if (ECARD_SUCCESS != (status = process_TA_Step_F(RND_ICC_,
					rapdus[rapdu_index])))
		return status;
	rapdu_index++;

	// Copy the data to the output buffer.
	toBeSigned = RND_ICC_;

	return status;
}

ECARD_STATUS __STDCALL__ ePASendSignature(
	ICard &hCard,
	const std::vector<unsigned char>& signature)
{
	return process_TA_Step_G(hCard.sendAPDU(build_TA_Step_G(signature)));
}
