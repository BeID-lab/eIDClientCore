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
#include <ECParameters.h>
#include "nPACommon.h"

#include <cstdio>

std::vector<unsigned char> generateSKPACE_FromPassword(
	const std::vector<unsigned char>& password,
	PaceInput::PinID keyReference)
{
	std::vector<unsigned char> result;
	unsigned char c_mrz[] = { 0x00, 0x00, 0x00, 0x01 };
	unsigned char c_can[] = { 0x00, 0x00, 0x00, 0x02 };
	unsigned char c_pin[] = { 0x00, 0x00, 0x00, 0x03 };
	unsigned char c_puk[] = { 0x00, 0x00, 0x00, 0x04 };
	SHA1 paceH;
	// Hash the full password
	paceH.Update(password.data(), password.size());

	switch (keyReference) {
		case PaceInput::mrz:
			paceH.Update(c_mrz, 4);
			break;
		case PaceInput::can:
			paceH.Update(c_can, 4);
			break;
		case PaceInput::pin:
			paceH.Update(c_pin, 4);
			break;
		case PaceInput::puk:
			paceH.Update(c_puk, 4);
			break;
		case PaceInput::undef:
		default:
			eCardCore_warn(DEBUG_LEVEL_CRYPTO, "Unknown PACE secret.");
	}

	// Get the first 16 bytes from result
	result.resize(20);
	paceH.Final(result.data());
	result.resize(16);
	hexdump(DEBUG_LEVEL_CRYPTO, "###-> INPUT PIN", password.data(), password.size());
	hexdump(DEBUG_LEVEL_CRYPTO, "###-> SKPACE", result.data(), result.size());
	return result;
}

std::vector<unsigned char> decryptRNDICC_AES(
	const vector<unsigned char>&  encryptedRNDICC,
	const vector<unsigned char>& skPACE)
{
	hexdump(DEBUG_LEVEL_CRYPTO, "###-> SKPACE in decryptRNDICC_AES", (void *) skPACE.data(), skPACE.size());
	hexdump(DEBUG_LEVEL_CRYPTO, "###-> encryptedRNDICC", (void *) encryptedRNDICC.data(), encryptedRNDICC.size());
	unsigned char iv_[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	std::vector<unsigned char> result_;
	CBC_Mode<AES>::Decryption AESCBC_decryption;

	if (false == AESCBC_decryption.IsValidKeyLength(skPACE.size()))
		return result_;

	result_.resize(encryptedRNDICC.size());
	AESCBC_decryption.SetKeyWithIV(skPACE.data(), skPACE.size(), iv_);
	AESCBC_decryption.ProcessData(result_.data(), encryptedRNDICC.data(), encryptedRNDICC.size());
	hexdump(DEBUG_LEVEL_CRYPTO, "###-> RNDICC", result_.data(), result_.size());
	return result_;
}

std::vector<unsigned char> calculate_PuK_IFD_DH2(
	const OBJECT_IDENTIFIER_t &OID_,
	const std::vector<unsigned char>& PrK_IFD_DH1,
	const std::vector<unsigned char>& PrK_IFD_DH2,
	const std::vector<unsigned char>& PuK_ICC_DH1,
	const std::vector<unsigned char>& rndICC_)
{
	OBJECT_IDENTIFIER_t PACE_ECDH_3DES_CBC_CBC	 = makeOID(id_PACE_ECDH_3DES_CBC_CBC);
	OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_128 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_128);
	OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_192 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_192);
	OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_256 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_256);

	std::vector<unsigned char> result_buffer;

	if (OID_ == PACE_ECDH_3DES_CBC_CBC ||
		OID_ == PACE_ECDH_AES_CBC_CMAC_128 ||
		OID_ == PACE_ECDH_AES_CBC_CMAC_192 ||
		OID_ ==  PACE_ECDH_AES_CBC_CMAC_256) {
		ECP::Point Puk_ICC_DH1_ = vector2point(PuK_ICC_DH1);

		hexdump(DEBUG_LEVEL_CRYPTO, "###-> PrK.IFD.DH1 in calculate_PuK_IFD_DH2", (void *) PrK_IFD_DH1.data(), PrK_IFD_DH1.size());
		hexdump(DEBUG_LEVEL_CRYPTO, "###-> rndICC in calculate_PuK_IFD_DH2", (void *) rndICC_.data(), rndICC_.size());
		Integer k(PrK_IFD_DH1.data(), PrK_IFD_DH1.size());
		Integer rndICC(rndICC_.data(), rndICC_.size());
		Integer a("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9h");
		Integer b("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6h");
		Integer Mod("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377h");
		ECP ecp(Mod, a, b);
		// Calculate: H = PrK.IFD.DH1 * PuK.ICC.DH1
		ECP::Point H_ = ecp.Multiply(k, Puk_ICC_DH1_);
		Integer X("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262h");
		Integer Y("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997h");
		ECP::Point G(X, Y);
		ECP::Point G_temp = ecp.ScalarMultiply(G, rndICC);
		ECP::Point G1 = ecp.Add(G_temp, H_);
		hexdump(DEBUG_LEVEL_CRYPTO, "###-> PrK.IFD.DH2 in calculate_PuK_IFD_DH2", (void *) PrK_IFD_DH2.data(), PrK_IFD_DH2.size());
		Integer k1(PrK_IFD_DH2.data(), PrK_IFD_DH2.size());
		ECP::Point result = ecp.Multiply(k1, G1);
		result_buffer = point2vector(result);
	}

	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_3DES_CBC_CBC, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_128, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_192, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_256, 1);

	return result_buffer;
}

static CAPDU build_PACE_Step_B(
	const OBJECT_IDENTIFIER_t &PACE_OID_,
	const PaceInput::PinID keyReference,
	const std::vector<unsigned char>& chat)
{
	vector<unsigned char> data, do80, do83, key_ref;
	MSE mse = MSE(MSE::P1_SET | MSE::P1_COMPUTE | MSE::P1_VERIFY, MSE::P2_AT);
	hexdump(DEBUG_LEVEL_CRYPTO, "###-> PACE OID", PACE_OID_.buf, PACE_OID_.size);
	hexdump(DEBUG_LEVEL_CRYPTO, "###-> CHAT", chat.data(), chat.size());
	hexdump(DEBUG_LEVEL_CRYPTO, "###-> KEY REF", &keyReference, 1);

	// Append OID
	do80 = TLV_encode(0x80, vector<unsigned char> (PACE_OID_.buf, PACE_OID_.buf + PACE_OID_.size));
	data.insert(data.end(), do80.begin(), do80.end());

	// Append Key reference
	if (PaceInput::mrz == keyReference) key_ref.push_back(0x01);
	if (PaceInput::can == keyReference) key_ref.push_back(0x02);
	if (PaceInput::pin == keyReference) key_ref.push_back(0x03);
	if (PaceInput::puk == keyReference) key_ref.push_back(0x04);
	do83 = TLV_encode(0x83, key_ref);
	data.insert(data.end(), do83.begin(), do83.end());

	// Append CHAT
	data.insert(data.end(), chat.begin(), chat.end());
	mse.setData(data);

	return mse;
}

ECARD_STATUS __STDCALL__ process_PACE_Step_B(
		const RAPDU& rapdu)
{
	if (rapdu.getSW() != RAPDU::ISO_SW_NORMAL) {
		if ((rapdu.getSW() >> 4) == 0x63C) {
			eCardCore_warn(DEBUG_LEVEL_CRYPTO, "%u tries left.", rapdu.getSW() & 0xf);
		} else {
			return ECARD_PACE_STEP_B_FAILED;
		}
	}

	return ECARD_SUCCESS;
}

CAPDU build_PACE_Step_C(void)
{
	GeneralAuthenticate authenticate(0x00, 0x00);
	authenticate.setCLA(CAPDU::CLA_CHAINING);
	authenticate.setNe(CAPDU::DATA_SHORT_MAX);
	authenticate.setData(TLV_encode(0x7C, vector<unsigned char> ()));

	return authenticate;
}

ECARD_STATUS __STDCALL__ process_PACE_Step_C(
	   	const RAPDU& rapdu,
		const OBJECT_IDENTIFIER_t &PACE_OID_,
		const PaceInput::PinID keyReference,
		const std::vector<unsigned char>& password,
		std::vector<unsigned char>& rndICC)
{
	if (!rapdu.isOK())
		return ECARD_PACE_STEP_C_FAILED;

	// Now compute the SK.PACE.xyz key from the given password.
	// SK.PACE is used to decrypt the RND.ICC value from the
	std::vector<unsigned char> skPACE_ = generateSKPACE_FromPassword(password, keyReference);
	OBJECT_IDENTIFIER_t PACE_ECDH_3DES_CBC_CBC	 = makeOID(id_PACE_ECDH_3DES_CBC_CBC);
	OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_128 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_128);
	OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_192 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_192);
	OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_256 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_256);
	std::vector<unsigned char> encryptedRNDICC;

	for (size_t i = 4; i < rapdu.getData().size(); i++)
		encryptedRNDICC.push_back(rapdu.getData()[i]);

	// the RAPDU carries the encrypted RND.ICC value
	if (PACE_OID_ == PACE_ECDH_AES_CBC_CMAC_128 ||
		PACE_OID_ == PACE_ECDH_AES_CBC_CMAC_192 ||
		PACE_OID_ ==  PACE_ECDH_AES_CBC_CMAC_256)
		rndICC = decryptRNDICC_AES(encryptedRNDICC, skPACE_);

	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_3DES_CBC_CBC, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_128, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_192, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_256, 1);

	if (0x00 == rndICC.size())
		return ECARD_PACE_STEP_C_DECRYPTION_FAILED;

	return ECARD_SUCCESS;
}

ECARD_STATUS __STDCALL__ perform_PACE_Step_D(
	std::vector<unsigned char> PuK_IFD_DH1_,
	ICard &card_,
	std::vector<unsigned char> &Puk_ICC_DH1_)
{
	GeneralAuthenticate authenticate(0x00, 0x00);
	authenticate.setCLA(CAPDU::CLA_CHAINING);
	authenticate.setNe(CAPDU::DATA_SHORT_MAX);

	authenticate.setData(TLV_encode(0x7C, TLV_encode(0x81, PuK_IFD_DH1_)));
	eCardCore_info(DEBUG_LEVEL_CRYPTO, "Send GENERAL AUTHENTICATE to Map Nonce");
	RAPDU rapdu = card_.transceive(authenticate);

	if (!rapdu.isOK())
		return ECARD_PACE_STEP_D_FAILED;

	unsigned int tag;
	vector<unsigned char> tlv_puk;

	if (!TLV_decode(rapdu.getData(), &tag, tlv_puk).empty() || tag != 0x7C)
		return ECARD_PACE_STEP_D_FAILED;

	if (!TLV_decode(tlv_puk, &tag, Puk_ICC_DH1_).empty() || tag != 0x82)
		return ECARD_PACE_STEP_D_FAILED;

	return ECARD_SUCCESS;
}

ECARD_STATUS __STDCALL__ perform_PACE_Step_E(
	const std::vector<unsigned char> PuK_IFD_DH2_,
	ICard &card_,
	std::vector<unsigned char> &Puk_ICC_DH2_)
{
	GeneralAuthenticate authenticate(0x00, 0x00);
	authenticate.setCLA(CAPDU::CLA_CHAINING);
	authenticate.setNe(CAPDU::DATA_SHORT_MAX);

	// Append command data field
	authenticate.setData(TLV_encode(0x7C, TLV_encode(0x83, PuK_IFD_DH2_)));
	eCardCore_info(DEBUG_LEVEL_CRYPTO, "Send GENERAL AUTHENTICATE to Perform Key Agreement");
	RAPDU rapdu = card_.transceive(authenticate);

	if (!rapdu.isOK())
		return ECARD_PACE_STEP_E_FAILED;

	unsigned int tag;
	vector<unsigned char> tlv_puk;

	if (!TLV_decode(rapdu.getData(), &tag, tlv_puk).empty() || tag != 0x7C)
		return ECARD_PACE_STEP_D_FAILED;

	if (!TLV_decode(tlv_puk, &tag, Puk_ICC_DH2_).empty() || tag != 0x84)
		return ECARD_PACE_STEP_D_FAILED;

	return ECARD_SUCCESS;
}

ECARD_STATUS __STDCALL__ perform_PACE_Step_F(
	const std::vector<unsigned char>& macedPuk_ICC_DH2,
	const std::vector<unsigned char>& macedPuk_IFD_DH2,
	ICard &card_,
	std::string &car_cvca)
{
	GeneralAuthenticate authenticate(0x00, 0x00);
	authenticate.setNe(CAPDU::DATA_SHORT_MAX);

	authenticate.setData(TLV_encode(0x7C, TLV_encode(0x85, macedPuk_ICC_DH2)));
	eCardCore_info(DEBUG_LEVEL_CRYPTO, "Send GENERAL AUTHENTICATE to perform explicit authentication");
	RAPDU rapdu = card_.transceive(authenticate);

	if (!rapdu.isOK())
		return ECARD_PACE_STEP_F_FAILED;

	std::vector<unsigned char> data_ = rapdu.getData();
	hexdump(DEBUG_LEVEL_CRYPTO, "###-> Last PACE result", data_.data(), data_.size());

	if (data_.size() < 14 || data_.size() < 14 + data_[13])
		return ECARD_PACE_STEP_F_FAILED;

	for (size_t i = 4; i < 12; i++) {
		if (macedPuk_IFD_DH2[i - 4] != data_[i])
			return ECARD_PACE_STEP_F_VERIFICATION_FAILED;
	}

	if (data_.size() > 12 && 0x87 == data_[12]) {
		for (size_t i = 14; i < 14 + data_[13]; i++)
			car_cvca.push_back((char) data_[i]);
	}

	return ECARD_SUCCESS;
}

ECARD_STATUS __STDCALL__ ePAPerformPACE(
	ePACard &ePA_,
	const PaceInput &pace_input,
	std::vector<unsigned char>& car_cvca,
	std::vector<unsigned char>& idPICC,
	std::vector<unsigned char>& ca_oid)
{
	OBJECT_IDENTIFIER_t PACE_OID_ = {NULL, 0};
	OBJECT_IDENTIFIER_t CA_OID_ = {NULL, 0};

	// Parse the EF.CardAccess
	SecurityInfos *secInfos_ = 0x00;
	if (ber_decode(0, &asn_DEF_SecurityInfos, (void **)&secInfos_, ePA_.get_ef_cardaccess().data(), ePA_.get_ef_cardaccess().size()).code != RC_OK) {
		asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
		return ECARD_EFCARDACCESS_PARSER_ERROR;
	}

	// Find the algorithm identifiers for PACE and CA...
	OBJECT_IDENTIFIER_t pace = makeOID(id_PACE);
	OBJECT_IDENTIFIER_t ca_dh = makeOID(id_CA_DH);
	OBJECT_IDENTIFIER_t ca_ecdh = makeOID(id_CA_ECDH);
	for (size_t i = 0; i < secInfos_->list.count; i++) {
		OBJECT_IDENTIFIER_t oid = secInfos_->list.array[i]->protocol;

		if (pace < oid) {
			PACE_OID_ = oid;
		}
		if (ca_dh < oid || ca_ecdh < oid) {
			CA_OID_ = oid;
		}
	}
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &pace, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &ca_dh, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &ca_ecdh, 1);


	if (ePA_.getSubSystem()->supportsPACE()) {
		eCardCore_info(DEBUG_LEVEL_CRYPTO, "Reader supports PACE");
		PaceOutput output = ePA_.getSubSystem()->establishPACEChannel(pace_input);
		car_cvca = output.get_car_curr();
		idPICC = output.get_id_icc();

	} else {
		eCardCore_info(DEBUG_LEVEL_CRYPTO, "Reader does not support PACE. Will establish PACE channel.");


		ECARD_STATUS status = ECARD_SUCCESS;

		ePA_.send(build_PACE_Step_B(PACE_OID_, pace_input.get_pin_id(), pace_input.get_chat()));

		eCardCore_info(DEBUG_LEVEL_CRYPTO, "Send GENERAL AUTHENTICATE to get RND.ICC");
		ePA_.send(build_PACE_Step_C());

		if (ECARD_SUCCESS != (status = process_PACE_Step_B(ePA_.receive()))) {
			asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
			return status;
		}

		std::vector<unsigned char> rndICC_;
		if (ECARD_SUCCESS != (status = process_PACE_Step_C(ePA_.receive(),
						PACE_OID_, pace_input.get_pin_id(),
						pace_input.get_pin(), rndICC_))) {
			asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
			return status;
		}

		std::vector<unsigned char> PrK_IFD_DH1_ = generate_PrK_IFD_DHx(PACE_OID_);
		std::vector<unsigned char> PuK_IFD_DH1_ = calculate_PuK_IFD_DH1(PACE_OID_, PrK_IFD_DH1_);
		std::vector<unsigned char> PuK_ICC_DH1_;

		if (ECARD_SUCCESS != (status = perform_PACE_Step_D(PuK_IFD_DH1_, ePA_, PuK_ICC_DH1_))) {
			asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
			return status;
		}

		std::vector<unsigned char> PrK_IFD_DH2_ = generate_PrK_IFD_DHx(PACE_OID_);
		std::vector<unsigned char> PuK_IFD_DH2_ = calculate_PuK_IFD_DH2(PACE_OID_,
			   	PrK_IFD_DH1_, PrK_IFD_DH2_, PuK_ICC_DH1_, rndICC_);
		std::vector<unsigned char> PuK_ICC_DH2_;

		if (ECARD_SUCCESS != (status = perform_PACE_Step_E(PuK_IFD_DH2_, ePA_, PuK_ICC_DH2_))) {
			asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
			return status;
		}

		hexdump(DEBUG_LEVEL_CRYPTO, "###-> PuK_IFD_DH2_", PuK_IFD_DH2_.data(), PuK_IFD_DH2_.size());
		hexdump(DEBUG_LEVEL_CRYPTO, "###-> PuK_ICC_DH2_", PuK_ICC_DH2_.data(), PuK_ICC_DH2_.size());

		std::vector<unsigned char> KIFD_ICC_ = calculate_KIFD_ICC(PACE_OID_, PrK_IFD_DH2_, PuK_ICC_DH2_);

		hexdump(DEBUG_LEVEL_CRYPTO, "###-> KIFD/ICC", KIFD_ICC_.data(), KIFD_ICC_.size());

		std::vector<unsigned char> kMac_ = calculate_SMKeys(KIFD_ICC_, true);
		hexdump(DEBUG_LEVEL_CRYPTO, "###-> kMac_", kMac_.data(), kMac_.size());
		std::vector<unsigned char> kEnc_ = calculate_SMKeys(KIFD_ICC_, false);
		hexdump(DEBUG_LEVEL_CRYPTO, "###-> kEnc_", kEnc_.data(), kEnc_.size());

		std::vector<unsigned char> toBeMaced_PuK_ICC_DH2_ = generate_compressed_PuK(PACE_OID_, PuK_ICC_DH2_);
		hexdump(DEBUG_LEVEL_CRYPTO, "###-> toBeMaced_PuK_ICC_DH2_", toBeMaced_PuK_ICC_DH2_.data(), toBeMaced_PuK_ICC_DH2_.size());
		std::vector<unsigned char> Maced_PuK_ICC_DH2_ = calculateMAC(toBeMaced_PuK_ICC_DH2_, kMac_);
		hexdump(DEBUG_LEVEL_CRYPTO, "###-> Maced_PuK_ICC_DH2_", Maced_PuK_ICC_DH2_.data(), Maced_PuK_ICC_DH2_.size());

		std::vector<unsigned char> toBeMaced_PuK_IFD_DH2_ = generate_compressed_PuK(PACE_OID_, PuK_IFD_DH2_);
		hexdump(DEBUG_LEVEL_CRYPTO, "###-> toBeMaced_PuK_IFD_DH2_", toBeMaced_PuK_IFD_DH2_.data(), toBeMaced_PuK_IFD_DH2_.size());
		std::vector<unsigned char> Maced_PuK_IFD_DH2_ = calculateMAC(toBeMaced_PuK_IFD_DH2_, kMac_);
		hexdump(DEBUG_LEVEL_CRYPTO, "###-> Maced_PuK_IFD_DH2_", Maced_PuK_IFD_DH2_.data(), Maced_PuK_IFD_DH2_.size());
		std::string car_cvca_;


		if (ECARD_SUCCESS != (status = perform_PACE_Step_F(Maced_PuK_ICC_DH2_,
						Maced_PuK_IFD_DH2_, ePA_, car_cvca_))) {
			asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
			return status;
		}

		ePA_.setKeys(kEnc_, kMac_);
		car_cvca = std::vector<unsigned char> (car_cvca_.begin(), car_cvca_.end());

		idPICC = calculate_ID_ICC(PACE_OID_, PuK_ICC_DH2_);

		hexdump(DEBUG_LEVEL_CRYPTO, "###-> ID ICC", idPICC.data(), idPICC.size());
	}

	ca_oid.assign(CA_OID_.buf, CA_OID_.buf + CA_OID_.size);

	asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);

	return ECARD_SUCCESS;
}
