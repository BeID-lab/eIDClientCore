/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#include "nPACommon.h"

#include "nPAAPI.h"
#include "nPAStatus.h"
#include "nPACard.h"
#include <debug.h>

#include "eidasn1/eIDHelper.h"
#include "eidasn1/eIDOID.h"

CAPDU build_CA_Step_B(const OBJECT_IDENTIFIER_t& CA_OID, const unsigned char sessionid)
{
	MSE mse = MSE(MSE::P1_SET | MSE::P1_COMPUTE, MSE::P2_AT);
	// Build up command data field
	std::vector<unsigned char> oid(CA_OID.buf, CA_OID.buf+CA_OID.size);;
	std::vector<unsigned char> data = TLV_encode(0x80, oid);
	if (sessionid) {
		data.push_back(0xE0);
		data.push_back(0x03);
		data.push_back(0x81);
		data.push_back(0x01);
		data.push_back(sessionid);
	}
	mse.setData(data);

	return mse;
}

ECARD_STATUS process_CA_Step_B(const RAPDU& rapdu)
{
	if (rapdu.getSW() != RAPDU::ISO_SW_NORMAL)
		return EAC_CA_STEP_B_FAILED;

	return EAC_SUCCESS;
}

CAPDU build_CA_Step_C(const std::vector<unsigned char>& Puk_IFD_DH)
{
	GeneralAuthenticate authenticate = GeneralAuthenticate(
			GeneralAuthenticate::P1_NO_INFO, GeneralAuthenticate::P2_NO_INFO);
	authenticate.setNe(CAPDU::DATA_SHORT_MAX);

	std::vector<unsigned char> puk;
	puk.push_back(0x04);
	puk.insert(puk.end(), Puk_IFD_DH.begin(), Puk_IFD_DH.end());
	
	authenticate.setData(TLV_encode(0x7C, TLV_encode(0x80, puk)));

	return authenticate;
}

ECARD_STATUS process_CA_Step_C(const RAPDU rapdu,
	std::vector<unsigned char>& GeneralAuthenticationResult)
{
	if (rapdu.getSW() != RAPDU::ISO_SW_NORMAL)
		return EAC_CA_STEP_B_FAILED;

	GeneralAuthenticationResult = rapdu.getData();

	return EAC_SUCCESS;
}

ECARD_STATUS __STDCALL__ ePAPerformCA(
	ICard &hCard,
	const std::vector<unsigned char>& CA_OID,
	const std::vector<unsigned char>& Puk_IFD_DH,
	std::vector<unsigned char>& GeneralAuthenticationResult)
{
	try {

		ECARD_STATUS status_ = ECARD_SUCCESS;
		const OBJECT_IDENTIFIER_t ca_oid = {(unsigned char *) DATA(CA_OID), static_cast<int>(CA_OID.size())};

		std::vector<CAPDU> capdus;
		capdus.push_back(build_CA_Step_B(ca_oid, 0));
		capdus.push_back(build_CA_Step_C(Puk_IFD_DH));

		std::vector<RAPDU> rapdus = hCard.transceive(capdus);
		std::vector<RAPDU>::const_iterator it = rapdus.begin();

		switch (rapdus.size()) {
			case 0:
				/* step B failed */
				return EAC_CA_STEP_B_FAILED;
			case 1:
				/* step C failed */
				return EAC_CA_STEP_B_FAILED;
			case 2:
				/* OK */
				break;
			default:
				/* too many rapdus */
				return EAC_CA_STEP_B_FAILED;
		}
		if (EAC_SUCCESS != (status_ = process_CA_Step_B(*it)))
			return status_;
		++it;

		if (EAC_SUCCESS != (status_ = process_CA_Step_C(*it,
						GeneralAuthenticationResult)))
			return status_;

		return EAC_SUCCESS;

	} catch (...) {
		return EAC_CA_STEP_B_FAILED;
	}
}
