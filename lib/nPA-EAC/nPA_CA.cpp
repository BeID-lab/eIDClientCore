/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#include "nPAAPI.h"
#include "nPAStatus.h"
#include "nPACard.h"
#include <debug.h>
using namespace Bundesdruckerei::nPA;

#include "nPACommon.h"
#include "eidasn1/eIDHelper.h"
#include "eidasn1/eIDOID.h"

ECARD_STATUS __STDCALL__ perform_CA_Step_B(
	ICard &ePA_)
{
	MSE mse = MSE(MSE::P1_SET | MSE::P1_COMPUTE, MSE::P2_AT);
	// Build up command data field
	std::vector<unsigned char> dataPart_;
	dataPart_.push_back(0x80);
	dataPart_.push_back(0x0A);
	dataPart_.push_back(0x04);
	dataPart_.push_back(0x00);
	dataPart_.push_back(0x7F);
	dataPart_.push_back(0x00);
	dataPart_.push_back(0x07);
	dataPart_.push_back(0x02);
	dataPart_.push_back(0x02);
	dataPart_.push_back(0x03);
	dataPart_.push_back(0x02);
	dataPart_.push_back(0x02); // This is id_CA_ECDH_AES_CBC_CMAC_128
	mse.setData(dataPart_);
	eCardCore_info(DEBUG_LEVEL_CRYPTO, "Send MANAGE SECURITY ENVIRONMENT to set cryptographic algorithm for CA.");
	// Do the dirty work.
	RAPDU MseSetAT_Result_ = ePA_.sendAPDU(mse);

	if (MseSetAT_Result_.getSW() != 0x9000)
		return ECARD_CA_STEP_B_FAILED;

	return ECARD_SUCCESS;
}

ECARD_STATUS __STDCALL__ perform_CA_Step_C(
	ICard &ePA_,
	const OBJECT_IDENTIFIER_t& CA_OID,
	const std::vector<unsigned char>& Puk_IFD_DH,
	std::vector<unsigned char>& GeneralAuthenticationResult)
{
	GeneralAuthenticate authenticate = GeneralAuthenticate(
										   GeneralAuthenticate::P1_NO_INFO, GeneralAuthenticate::P2_NO_INFO);
	authenticate.setNe(CAPDU::DATA_SHORT_MAX);

	std::vector<unsigned char> puk;
	OBJECT_IDENTIFIER_t ca_dh = makeOID(id_CA_DH);
	OBJECT_IDENTIFIER_t ca_ecdh = makeOID(id_CA_ECDH);
	if (ca_dh < CA_OID) {
		puk = Puk_IFD_DH;
	} else if (ca_ecdh < CA_OID) {
		puk.push_back(0x04);
		puk.insert(puk.end(), Puk_IFD_DH.begin(), Puk_IFD_DH.end());
	} else {
		eCardCore_warn(DEBUG_LEVEL_CRYPTO, "Invalid CA OID.");
	}
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &ca_dh, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &ca_ecdh, 1);

	authenticate.setData(TLV_encode(0x7C, TLV_encode(0x80, puk)));

	eCardCore_info(DEBUG_LEVEL_CRYPTO, "Send GENERAL AUTHENTICATE for key agreement.");
	RAPDU GenralAuthenticate_Result_ = ePA_.sendAPDU(authenticate);

	if (GenralAuthenticate_Result_.getSW() != 0x9000)
		return ECARD_CA_STEP_B_FAILED;

	std::vector<unsigned char> result = GenralAuthenticate_Result_.getData();
	GeneralAuthenticationResult = result;
	return ECARD_SUCCESS;
}

ECARD_STATUS __STDCALL__ ePAPerformCA(
	ICard &hCard,
	const std::vector<unsigned char>& CA_OID,
	const std::vector<unsigned char>& Puk_IFD_DH,
	std::vector<unsigned char>& GeneralAuthenticationResult)
{
	ECARD_STATUS status_ = ECARD_SUCCESS;
	const OBJECT_IDENTIFIER_t ca_oid = {(unsigned char *) CA_OID.data(), CA_OID.size()};

	if (ECARD_SUCCESS != (status_ = perform_CA_Step_B(hCard)))
		return status_;

	if (ECARD_SUCCESS != (status_ = perform_CA_Step_C(hCard, ca_oid, Puk_IFD_DH, GeneralAuthenticationResult)))
		return status_;

	return ECARD_SUCCESS;
}
