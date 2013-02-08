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

static CAPDU build_CA_Step_B(const OBJECT_IDENTIFIER_t& CA_OID)
{
	MSE mse = MSE(MSE::P1_SET | MSE::P1_COMPUTE, MSE::P2_AT);
	// Build up command data field
	std::vector<unsigned char> oid(CA_OID.buf, CA_OID.buf+CA_OID.size);;
	mse.setData(TLV_encode(0x80, oid));

	return mse;
}

static ECARD_STATUS process_CA_Step_B(const RAPDU& rapdu)
{
	if (rapdu.getSW() != RAPDU::ISO_SW_NORMAL)
		return ECARD_CA_STEP_B_FAILED;

	return ECARD_SUCCESS;
}

static CAPDU build_CA_Step_C(const OBJECT_IDENTIFIER_t& CA_OID,
	const std::vector<unsigned char>& Puk_IFD_DH)
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

	return authenticate;
}

static ECARD_STATUS process_CA_Step_C(const RAPDU rapdu,
	std::vector<unsigned char>& GeneralAuthenticationResult)
{
	if (rapdu.getSW() != RAPDU::ISO_SW_NORMAL)
		return ECARD_CA_STEP_B_FAILED;

	GeneralAuthenticationResult = rapdu.getData();

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

	vector<CAPDU> capdus;
	capdus.push_back(build_CA_Step_B(ca_oid));
	capdus.push_back(build_CA_Step_C(ca_oid, Puk_IFD_DH));

	vector<RAPDU> rapdus = hCard.transceive(capdus);
	vector<RAPDU>::const_iterator it = rapdus.begin();

	switch (rapdus.size()) {
		case 0:
			/* step B failed */
			return ECARD_CA_STEP_B_FAILED;
		case 1:
			/* step C failed */
			return ECARD_CA_STEP_B_FAILED;
		case 2:
			/* OK */
			break;
		default:
			/* too many rapdus */
			return ECARD_CA_STEP_B_FAILED;
	}
	if (ECARD_SUCCESS != (status_ = process_CA_Step_B(*it)))
		return status_;
	++it;

	if (ECARD_SUCCESS != (status_ = process_CA_Step_C(*it,
					GeneralAuthenticationResult)))
		return status_;

	return ECARD_SUCCESS;
}
