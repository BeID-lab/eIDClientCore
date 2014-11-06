/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#include "nPAAPI.h"
#include "nPAStatus.h"
#include "nPACard.h"
#include <debug.h>

#include "eCardCore/ICard.h"
#include "SecurityInfos.h"
#include "PACEDomainParameterInfo.h"
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
		return EAC_TA_STEP_A_FAILED;

	return EAC_SUCCESS;
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
		return EAC_TA_STEP_B_FAILED;

	return EAC_SUCCESS;
}

CAPDU build_TA_Step_E(
		const std::vector<unsigned char>& keyID,
		const OBJECT_IDENTIFIER_t& CA_OID,
		const std::vector<unsigned char>& Puk_IFD_DH,
		const std::vector<unsigned char>& authenticatedAuxiliaryData)
{
	MSE mse(MSE::P1_SET | MSE::P1_VERIFY, MSE::P2_AT);
	// @TODO Get the right oid for TA
	std::vector<unsigned char> dataField, do83, do91, encoded_Puk_IFD_DH;
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
	encoded_Puk_IFD_DH.push_back(0x04);
	encoded_Puk_IFD_DH.insert(encoded_Puk_IFD_DH.end(), Puk_IFD_DH.begin(),	Puk_IFD_DH.end());
	do91 = TLV_encode(0x91, calculate_ID_ICC(encoded_Puk_IFD_DH));
	dataField.insert(dataField.end(), do91.begin(), do91.end());

	dataField.insert(dataField.end(), authenticatedAuxiliaryData.begin(), authenticatedAuxiliaryData.end());
	
	mse.setData(dataField);

	return mse;
}

ECARD_STATUS __STDCALL__ process_TA_Step_E(
		const RAPDU &rapdu)
{
	if (rapdu.getSW() != RAPDU::ISO_SW_NORMAL)
		return EAC_TA_STEP_E_FAILED;

	return EAC_SUCCESS;
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
		return EAC_TA_STEP_F_FAILED;

	RND_ICC = rapdu.getData();

	return EAC_SUCCESS;
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
		return EAC_TA_STEP_G_FAILED;

	return EAC_SUCCESS;
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

	try {

		const OBJECT_IDENTIFIER_t ca_oid = {(unsigned char *) DATA(CA_OID), static_cast<int>(CA_OID.size())};

		/*Hack for later compare*/
		int appendTACert = 0;

		/* build all APDUs */
		std::vector<CAPDU> capdus;

		/* TODO verify the chain of certificates in the middle ware */
		std::vector<unsigned char> _current_car = carCVCA;
		std::string current_car;
		if(!list_certificates.empty()){
			for (size_t i = 0; i < list_certificates.size(); i++) {
				hexdump(DEBUG_LEVEL_CRYPTO, "CAR", DATA(_current_car), _current_car.size());
	
				capdus.push_back(build_TA_Step_Set_CAR(_current_car));
	
				std::vector<unsigned char> cert;
				cert = list_certificates[i];
				hexdump(DEBUG_LEVEL_CRYPTO, "certificate", DATA(cert), cert.size());
	
				capdus.push_back(build_TA_Step_Verify_Certificate(cert));
	
				current_car = getCHR(cert);
				_current_car = std::vector<unsigned char>(current_car.begin(), current_car.end());
			}
		}

		std::string chrTerm_ = getCHR(terminalCertificate);
		/*Test if last Certificate is the Terminal Certificate
		  Otherwise we have to append it to our list*/
		if(current_car.compare(chrTerm_))
		{
			appendTACert++;

			/*To Do: Delete the code duplication by using a method*/
			hexdump(DEBUG_LEVEL_CRYPTO, "CAR", DATA(_current_car), _current_car.size());

			capdus.push_back(build_TA_Step_Set_CAR(_current_car));

			std::vector<unsigned char> cert;
			cert = terminalCertificate;
			hexdump(DEBUG_LEVEL_CRYPTO, "certificate", DATA(cert), cert.size());

			capdus.push_back(build_TA_Step_Verify_Certificate(cert));

			current_car = getCHR(cert);
			_current_car = std::vector<unsigned char>(current_car.begin(), current_car.end());
		}
		hexdump(DEBUG_LEVEL_CRYPTO, "TERM CHR: ", DATA(chrTerm_), chrTerm_.size());

		capdus.push_back(build_TA_Step_E(_current_car, ca_oid, Puk_IFD_DH_CA, authenticatedAuxiliaryData));
		capdus.push_back(build_TA_Step_F());


		/* process all RAPDUs */
		std::vector<RAPDU> rapdus = hCard.transceive(capdus);

		if (rapdus.size() != list_certificates.size()*2 + appendTACert*2 + 2)
			return EAC_TA_STEP_A_FAILED;

		std::vector<RAPDU>::const_iterator it = rapdus.begin();

		for (size_t i = 0; i < (capdus.size() - 2) / 2; i++) {
			if (EAC_SUCCESS != (status = process_TA_Step_Set_CAR(*it)))
				return status;
			++it;

			if (EAC_SUCCESS != (status = process_TA_Step_Verify_Certificate(*it)))
				return status;
			++it;
		}

		if (EAC_SUCCESS != (status = process_TA_Step_E(*it)))
			return status;
		++it;

		std::vector<unsigned char> RND_ICC_;
		if (EAC_SUCCESS != (status = process_TA_Step_F(RND_ICC_,
						*it)))
			return status;

		// Copy the data to the output buffer.
		toBeSigned = RND_ICC_;

		return status;

	} catch (...) {
		return EAC_TA_STEP_G_FAILED;
	}
}

ECARD_STATUS __STDCALL__ ePASendSignature(
	ICard &hCard,
	const std::vector<unsigned char>& signature)
{
	try {

		return process_TA_Step_G(hCard.transceive(build_TA_Step_G(signature)));

	} catch (...) {
		return ECARD_READER_TRANSCEIVE_FAILED;
	}
}
