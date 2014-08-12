/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#include "nPAAPI.h"
#include "nPAStatus.h"
#include "nPACard.h"
#include <debug.h>

#include "eCardCore/ICard.h"
#include <SecurityInfos.h>
#include "PACEDomainParameterInfo.h"
#include "eidasn1/eIDHelper.h"
#include "eidasn1/eIDOID.h"
#include <ECParameters.h>
#include "nPACommon.h"
#include <CertificateDescription.h>
#include <EstablishPACEChannelInput.h>
#include <EstablishPACEChannelOutput.h>

#include <cstdio>

ECARD_STATUS __STDCALL__ ePAGetRandom(
	size_t size, std::vector<unsigned char>& random_bytes)
{
	/* TODO only initialize rng once, then use the pseudo random bits */
	AutoSeededRandomPool rng;
	random_bytes.resize(size);
	rng.GenerateBlock(DATA(random_bytes), random_bytes.size());
	return ECARD_SUCCESS;
}

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
	paceH.Update(DATA(password), password.size());

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
	paceH.Final(DATA(result));
	result.resize(16);
	hexdump(DEBUG_LEVEL_CRYPTO, "###-> INPUT PIN", DATA(password), password.size());
	hexdump(DEBUG_LEVEL_CRYPTO, "###-> SKPACE", DATA(result), result.size());
	return result;
}

std::vector<unsigned char> decryptRNDICC_AES(
	const std::vector<unsigned char>&  encryptedRNDICC,
	const std::vector<unsigned char>& skPACE)
{
	hexdump(DEBUG_LEVEL_CRYPTO, "###-> SKPACE in decryptRNDICC_AES", (void *) DATA(skPACE), skPACE.size());
	hexdump(DEBUG_LEVEL_CRYPTO, "###-> encryptedRNDICC", (void *) DATA(encryptedRNDICC), encryptedRNDICC.size());
	unsigned char iv_[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	std::vector<unsigned char> result_;
	CBC_Mode<AES>::Decryption AESCBC_decryption;

	if (false == AESCBC_decryption.IsValidKeyLength(skPACE.size()))
		return result_;

	result_.resize(encryptedRNDICC.size());
	AESCBC_decryption.SetKeyWithIV(DATA(skPACE), skPACE.size(), iv_);
	AESCBC_decryption.ProcessData(DATA(result_), DATA(encryptedRNDICC), encryptedRNDICC.size());
	hexdump(DEBUG_LEVEL_CRYPTO, "###-> RNDICC", DATA(result_), result_.size());
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

	OBJECT_IDENTIFIER_t PACE_DH_3DES_CBC_CBC	 = makeOID(id_PACE_DH_3DES_CBC_CBC);
	OBJECT_IDENTIFIER_t PACE_DH_AES_CBC_CMAC_128 = makeOID(id_PACE_DH_AES_CBC_CMAC_128);
	OBJECT_IDENTIFIER_t PACE_DH_AES_CBC_CMAC_192 = makeOID(id_PACE_DH_AES_CBC_CMAC_192);
	OBJECT_IDENTIFIER_t PACE_DH_AES_CBC_CMAC_256 = makeOID(id_PACE_DH_AES_CBC_CMAC_256);

	std::vector<unsigned char> result_buffer;

	if (OID_ == PACE_ECDH_3DES_CBC_CBC ||
		OID_ == PACE_ECDH_AES_CBC_CMAC_128 ||
		OID_ == PACE_ECDH_AES_CBC_CMAC_192 ||
		OID_ ==  PACE_ECDH_AES_CBC_CMAC_256) {
		ECP::Point Puk_ICC_DH1_ = vector2point(PuK_ICC_DH1);

		hexdump(DEBUG_LEVEL_CRYPTO, "###-> PrK.IFD.DH1 in calculate_PuK_IFD_DH2", (void *) DATA(PrK_IFD_DH1), PrK_IFD_DH1.size());
		hexdump(DEBUG_LEVEL_CRYPTO, "###-> rndICC in calculate_PuK_IFD_DH2", (void *) DATA(rndICC_), rndICC_.size());
		Integer k(DATA(PrK_IFD_DH1), PrK_IFD_DH1.size());
		Integer rndICC(DATA(rndICC_), rndICC_.size());
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
		hexdump(DEBUG_LEVEL_CRYPTO, "###-> PrK.IFD.DH2 in calculate_PuK_IFD_DH2", (void *) DATA(PrK_IFD_DH2), PrK_IFD_DH2.size());
		Integer k1(DATA(PrK_IFD_DH2), PrK_IFD_DH2.size());
		ECP::Point result = ecp.Multiply(k1, G1);
		result_buffer = point2vector(result);
	} else if (OID_ == PACE_DH_3DES_CBC_CBC ||
			OID_ == PACE_DH_AES_CBC_CMAC_128 ||
			OID_ == PACE_DH_AES_CBC_CMAC_192 ||
			OID_ ==  PACE_DH_AES_CBC_CMAC_256) {
		DH dh = get_std_dp_0();

		if (PrK_IFD_DH1.size() != dh.PrivateKeyLength()
			   	|| PuK_ICC_DH1.size() != dh.PublicKeyLength()
			   	|| PrK_IFD_DH2.size() != dh.PrivateKeyLength()) {
			eCardCore_warn(DEBUG_LEVEL_CRYPTO,
				   	"No valid public or private key for mapping (%d/%d, %d/%d, %d/%d).",
					PrK_IFD_DH1.size(), dh.PrivateKeyLength(),
					PuK_ICC_DH1.size(), dh.PublicKeyLength(),
					PrK_IFD_DH2.size(), dh.PrivateKeyLength());
			return result_buffer;
		}

		std::vector<unsigned char> h_vector;
		h_vector.resize(dh.AgreedValueLength());
		if (!dh.Agree(DATA(h_vector), DATA(PrK_IFD_DH1), DATA(PuK_ICC_DH1))) {
			eCardCore_warn(DEBUG_LEVEL_CRYPTO, "Key agreement for mapping failed.");
			return result_buffer;
		}
		Integer h(DATA(h_vector), h_vector.size());

		Integer s(DATA(rndICC_), rndICC_.size());

		Integer tmp = a_exp_b_mod_c(dh.GetGroupParameters().GetGenerator(), s,
				dh.GetGroupParameters().GetModulus());

		Integer g_ephemeral = a_times_b_mod_c(tmp, h, dh.GetGroupParameters().GetModulus());

		dh.AccessGroupParameters().SetSubgroupGenerator(g_ephemeral);

		AutoSeededRandomPool rng;
		result_buffer.resize(dh.PublicKeyLength());
		dh.GeneratePublicKey(rng, DATA(PrK_IFD_DH2), DATA(result_buffer));
	}

	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_3DES_CBC_CBC, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_128, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_192, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_256, 1);

	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_DH_3DES_CBC_CBC, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_DH_AES_CBC_CMAC_128, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_DH_AES_CBC_CMAC_192, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_DH_AES_CBC_CMAC_256, 1);

	return result_buffer;
}

static CAPDU build_PACE_Step_B(
	const OBJECT_IDENTIFIER_t &PACE_OID_,
	const PaceInput::PinID keyReference,
	const std::vector<unsigned char>& chat)
{
	std::vector<unsigned char> data, do80, do83, key_ref;
	MSE mse = MSE(MSE::P1_SET | MSE::P1_COMPUTE | MSE::P1_VERIFY, MSE::P2_AT);
	hexdump(DEBUG_LEVEL_CRYPTO, "###-> PACE OID", PACE_OID_.buf, PACE_OID_.size);
	hexdump(DEBUG_LEVEL_CRYPTO, "###-> CHAT", DATA(chat), chat.size());
	hexdump(DEBUG_LEVEL_CRYPTO, "###-> KEY REF", &keyReference, 1);

	// Append OID
	do80 = TLV_encode(0x80, std::vector<unsigned char> (PACE_OID_.buf, PACE_OID_.buf + PACE_OID_.size));
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

/*
TODO: Change Code when we support PACE with CAN
*/
ECARD_STATUS __STDCALL__ process_PACE_Step_B(
		const RAPDU& rapdu)
{
	if (rapdu.getSW() != RAPDU::ISO_SW_NORMAL) {
		if ((rapdu.getSW() >> 4) == 0x63C) {
			if(1 == (rapdu.getSW() & 0xf))
			{
				eCardCore_warn(DEBUG_LEVEL_CRYPTO, "Only 1 try left. Abort, because we don't support PACE with CAN yet!");
				return EAC_CAN_REQUIRED;
			}

			eCardCore_warn(DEBUG_LEVEL_CRYPTO, "%u tries left.", rapdu.getSW() & 0xf);
		} else if(rapdu.getSW() == 0x6283) {
			eCardCore_warn(DEBUG_LEVEL_CARD, "The password (eID-Function) is deactivated.");
		} else {
			return EAC_PIN_DEACTIVATED;
		}
	}

	return EAC_SUCCESS;
}

CAPDU build_PACE_Step_C(void)
{
	GeneralAuthenticate authenticate(0x00, 0x00);
	authenticate.setCLA(CAPDU::CLA_CHAINING);
	authenticate.setNe(CAPDU::DATA_SHORT_MAX);
	authenticate.setData(TLV_encode(0x7C, std::vector<unsigned char> ()));

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
		return EAC_PACE_STEP_C_FAILED;

	// Now compute the SK.PACE.xyz key from the given password.
	// SK.PACE is used to decrypt the RND.ICC value from the
	std::vector<unsigned char> skPACE_ = generateSKPACE_FromPassword(password, keyReference);
	OBJECT_IDENTIFIER_t PACE_ECDH_3DES_CBC_CBC	 = makeOID(id_PACE_ECDH_3DES_CBC_CBC);
	OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_128 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_128);
	OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_192 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_192);
	OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_256 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_256);
	OBJECT_IDENTIFIER_t PACE_DH_3DES_CBC_CBC	 = makeOID(id_PACE_DH_3DES_CBC_CBC);
	OBJECT_IDENTIFIER_t PACE_DH_AES_CBC_CMAC_128 = makeOID(id_PACE_DH_AES_CBC_CMAC_128);
	OBJECT_IDENTIFIER_t PACE_DH_AES_CBC_CMAC_192 = makeOID(id_PACE_DH_AES_CBC_CMAC_192);
	OBJECT_IDENTIFIER_t PACE_DH_AES_CBC_CMAC_256 = makeOID(id_PACE_DH_AES_CBC_CMAC_256);
	std::vector<unsigned char> encryptedRNDICC;

	for (size_t i = 4; i < rapdu.getData().size(); i++)
		encryptedRNDICC.push_back(rapdu.getData()[i]);

	// the RAPDU carries the encrypted RND.ICC value
	if (PACE_OID_ == PACE_ECDH_AES_CBC_CMAC_128 ||
		PACE_OID_ == PACE_ECDH_AES_CBC_CMAC_192 ||
		PACE_OID_ ==  PACE_ECDH_AES_CBC_CMAC_256 ||
		PACE_OID_ == PACE_DH_AES_CBC_CMAC_128 ||
		PACE_OID_ == PACE_DH_AES_CBC_CMAC_192 ||
		PACE_OID_ ==  PACE_DH_AES_CBC_CMAC_256)
		rndICC = decryptRNDICC_AES(encryptedRNDICC, skPACE_);

	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_3DES_CBC_CBC, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_128, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_192, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_256, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_DH_3DES_CBC_CBC, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_DH_AES_CBC_CMAC_128, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_DH_AES_CBC_CMAC_192, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_DH_AES_CBC_CMAC_256, 1);

	if (0x00 == rndICC.size())
		return EAC_PACE_STEP_C_DECRYPTION_FAILED;

	return EAC_SUCCESS;
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
		return EAC_PACE_STEP_D_FAILED;

	unsigned int tag;
	std::vector<unsigned char> tlv_puk;

	if (!TLV_decode(rapdu.getData(), &tag, tlv_puk).empty() || tag != 0x7C)
		return EAC_PACE_STEP_D_FAILED;

	if (!TLV_decode(tlv_puk, &tag, Puk_ICC_DH1_).empty() || tag != 0x82)
		return EAC_PACE_STEP_D_FAILED;

	return EAC_SUCCESS;
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
		return EAC_PACE_STEP_E_FAILED;

	unsigned int tag;
	std::vector<unsigned char> tlv_puk;

	if (!TLV_decode(rapdu.getData(), &tag, tlv_puk).empty() || tag != 0x7C)
		return EAC_PACE_STEP_D_FAILED;

	if (!TLV_decode(tlv_puk, &tag, Puk_ICC_DH2_).empty() || tag != 0x84)
		return EAC_PACE_STEP_D_FAILED;

	return EAC_SUCCESS;
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
		return EAC_PACE_STEP_F_FAILED;

	std::vector<unsigned char> data_ = rapdu.getData();
	hexdump(DEBUG_LEVEL_CRYPTO, "###-> Last PACE result", DATA(data_), data_.size());

	if (data_.size() < 14 || data_.size() < 14 + data_[13])
		return EAC_PACE_STEP_F_FAILED;

	for (size_t i = 4; i < 12; i++) {
		if (macedPuk_IFD_DH2[i - 4] != data_[i])
			return EAC_PACE_STEP_F_VERIFICATION_FAILED;
	}

	if (data_.size() > 12 && 0x87 == data_[12]) {
		for (size_t i = 14; i < 14 + data_[13]; i++)
			car_cvca.push_back((char) data_[i]);
	}

	return EAC_SUCCESS;
}

ECARD_STATUS __STDCALL__ ePAPerformPACE(
	ePACard &ePA_,
	const PaceInput &pace_input,
	std::vector<unsigned char>& car_cvca,
	std::vector<unsigned char>& idPICC,
	std::vector<unsigned char>& ca_oid,
	std::vector<unsigned char>& chat_used)
{
	OBJECT_IDENTIFIER_t PACE_OID_ = {NULL, 0};
	OBJECT_IDENTIFIER_t CA_OID_ = {NULL, 0};

	try {

		// Parse the EF.CardAccess
		SecurityInfos *secInfos_ = 0x00;
		if (ber_decode(0, &asn_DEF_SecurityInfos, (void **)&secInfos_, DATA(ePA_.get_ef_cardaccess()), ePA_.get_ef_cardaccess().size()).code != RC_OK) {
			asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
			return EAC_EFCARDACCESS_PARSER_ERROR;
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

			if (output.get_result()){
				return ECARD_EXTERNAL_PACE_ERROR;
			}

			car_cvca = output.get_car_curr();
			idPICC = output.get_id_icc();
			chat_used = output.get_chat();
			//use chat from pace_input if chat_used from pace_output is empty
			if (chat_used.empty()){
				chat_used = pace_input.get_chat();
			}
        } else {
			eCardCore_info(DEBUG_LEVEL_CRYPTO, "Reader does not support PACE. Will establish PACE channel.");


			ECARD_STATUS status = ECARD_SUCCESS;
			chat_used = pace_input.get_chat();

			std::vector<CAPDU> capdus;
			capdus.push_back(build_PACE_Step_B(PACE_OID_, pace_input.get_pin_id(), pace_input.get_chat()));
			capdus.push_back(build_PACE_Step_C());

			std::vector<RAPDU> rapdus = ePA_.transceive(capdus);
			std::vector<RAPDU>::const_iterator it = rapdus.begin();

			switch (rapdus.size()) {
				case 2:
					/* everything OK */
					break;
				case 1:
					asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
					return EAC_PACE_STEP_C_FAILED;
				case 0:
					asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
					return EAC_PACE_STEP_B_FAILED;
				default:
					/* too many rapdus */
					asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
					return EAC_PACE_STEP_B_FAILED;
			}
			if (EAC_SUCCESS != (status = process_PACE_Step_B(*it))) {
				asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
				return status;
			}
			++it;

			std::vector<unsigned char> rndICC_;
			if (EAC_SUCCESS != (status = process_PACE_Step_C(*it,
							PACE_OID_, pace_input.get_pin_id(),
							pace_input.get_pin(), rndICC_))) {
				asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
				return status;
			}

			std::vector<unsigned char> PrK_IFD_DH1_ = generate_PrK_IFD_DHx(PACE_OID_);
			std::vector<unsigned char> PuK_IFD_DH1_ = calculate_PuK_IFD_DH1(PACE_OID_, PrK_IFD_DH1_);
			std::vector<unsigned char> PuK_ICC_DH1_;

			hexdump(DEBUG_LEVEL_CRYPTO, "###-> PrK_IFD_DH1", DATA(PrK_IFD_DH1_), PrK_IFD_DH1_.size());
			hexdump(DEBUG_LEVEL_CRYPTO, "###-> PuK_IFD_DH1", DATA(PuK_IFD_DH1_), PuK_IFD_DH1_.size());

			if (EAC_SUCCESS != (status = perform_PACE_Step_D(PuK_IFD_DH1_, ePA_, PuK_ICC_DH1_))) {
				asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
				return status;
			}

			std::vector<unsigned char> PrK_IFD_DH2_ = generate_PrK_IFD_DHx(PACE_OID_);
			std::vector<unsigned char> PuK_IFD_DH2_ = calculate_PuK_IFD_DH2(PACE_OID_,
					PrK_IFD_DH1_, PrK_IFD_DH2_, PuK_ICC_DH1_, rndICC_);
			std::vector<unsigned char> PuK_ICC_DH2_;

			if (EAC_SUCCESS != (status = perform_PACE_Step_E(PuK_IFD_DH2_, ePA_, PuK_ICC_DH2_))) {
				asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
				return status;
			}

			hexdump(DEBUG_LEVEL_CRYPTO, "###-> PuK_IFD_DH2_", DATA(PuK_IFD_DH2_), PuK_IFD_DH2_.size());
			hexdump(DEBUG_LEVEL_CRYPTO, "###-> PuK_ICC_DH2_", DATA(PuK_ICC_DH2_), PuK_ICC_DH2_.size());

			std::vector<unsigned char> KIFD_ICC_ = calculate_KIFD_ICC(PACE_OID_, PrK_IFD_DH2_, PuK_ICC_DH2_);

			hexdump(DEBUG_LEVEL_CRYPTO, "###-> KIFD/ICC", DATA(KIFD_ICC_), KIFD_ICC_.size());

			std::vector<unsigned char> kMac_ = calculate_SMKeys(KIFD_ICC_, true);
			hexdump(DEBUG_LEVEL_CRYPTO, "###-> kMac_", DATA(kMac_), kMac_.size());
			std::vector<unsigned char> kEnc_ = calculate_SMKeys(KIFD_ICC_, false);
			hexdump(DEBUG_LEVEL_CRYPTO, "###-> kEnc_", DATA(kEnc_), kEnc_.size());

			std::vector<unsigned char> toBeMaced_PuK_ICC_DH2_ = generate_compressed_PuK(PACE_OID_, PuK_ICC_DH2_);
			hexdump(DEBUG_LEVEL_CRYPTO, "###-> toBeMaced_PuK_ICC_DH2_", DATA(toBeMaced_PuK_ICC_DH2_), toBeMaced_PuK_ICC_DH2_.size());
			std::vector<unsigned char> Maced_PuK_ICC_DH2_ = calculateMAC(toBeMaced_PuK_ICC_DH2_, kMac_);
			hexdump(DEBUG_LEVEL_CRYPTO, "###-> Maced_PuK_ICC_DH2_", DATA(Maced_PuK_ICC_DH2_), Maced_PuK_ICC_DH2_.size());

			std::vector<unsigned char> toBeMaced_PuK_IFD_DH2_ = generate_compressed_PuK(PACE_OID_, PuK_IFD_DH2_);
			hexdump(DEBUG_LEVEL_CRYPTO, "###-> toBeMaced_PuK_IFD_DH2_", DATA(toBeMaced_PuK_IFD_DH2_), toBeMaced_PuK_IFD_DH2_.size());
			std::vector<unsigned char> Maced_PuK_IFD_DH2_ = calculateMAC(toBeMaced_PuK_IFD_DH2_, kMac_);
			hexdump(DEBUG_LEVEL_CRYPTO, "###-> Maced_PuK_IFD_DH2_", DATA(Maced_PuK_IFD_DH2_), Maced_PuK_IFD_DH2_.size());
			std::string car_cvca_;


			if (ECARD_SUCCESS != (status = perform_PACE_Step_F(Maced_PuK_ICC_DH2_,
							Maced_PuK_IFD_DH2_, ePA_, car_cvca_))) {
				asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
				return status;
			}

			ePA_.setKeys(kEnc_, kMac_);
			car_cvca = std::vector<unsigned char> (car_cvca_.begin(), car_cvca_.end());

			idPICC = calculate_ID_ICC(PACE_OID_, PuK_ICC_DH2_);

			hexdump(DEBUG_LEVEL_CRYPTO, "###-> ID ICC", DATA(idPICC), idPICC.size());
		}

		ca_oid.assign(CA_OID_.buf, CA_OID_.buf + CA_OID_.size);

		asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);

		return ECARD_SUCCESS;

	} catch(PACEException exc) {
		//Sad Hack until we get rid of the exceptions or use them in the whole code
		if(!strcmp("0xF0026283", exc.what()))
		{
			return EAC_PIN_DEACTIVATED;
		}
		else if(!strcmp("0xF0036982", exc.what()))
		{
			return EAC_CAN_REQUIRED;
		}
		else if(!strcmp("0xF00663C1", exc.what()))
		{
			return EAC_PIN_SECOND_FAIL;
		}
		else if(!strcmp("0xF00663C2", exc.what()))
		{
			return EAC_PIN_FIRST_FAIL;
		}

		return EAC_PACE_STEP_F_VERIFICATION_FAILED;
	} catch (...) {
		return EAC_PACE_STEP_F_VERIFICATION_FAILED;
	}
}

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
            size_t *bufEstablishPACEChannelInput_len)
{
    asn_enc_rval_t                  er;
    EstablishPACEChannelInput_t*    pEstablishPACEChannelInput = 0x00;
    uint8_t                         passwordID = pinid;
    CertificateDescription_t*       pCertificateDescription = 0x00;
    unsigned char                   buf[1000];
    size_t							bufSize = 1000;

    if(0x00 == bufEstablishPACEChannelInput)
        return ECARD_INVALID_PARAMETER_1;

    memset(&buf[0], 0x00, 1000);
    
    if (ber_decode(0, &asn_DEF_CertificateDescription, (void **)&pCertificateDescription, certificate_description, certificate_description_len).code != RC_OK)
    {
        eCardCore_debug(DEBUG_LEVEL_CLIENT, "encode_EstablishPACEChannelInput - Could not decode CertificateDescription.");
        asn_DEF_CertificateDescription.free_struct(&asn_DEF_CertificateDescription, pCertificateDescription, 0);
        return ECARD_ASN1_PARSER_ERROR;
    }
    
    pEstablishPACEChannelInput = (EstablishPACEChannelInput*) malloc(sizeof(EstablishPACEChannelInput));
    memset(pEstablishPACEChannelInput, 0x00, sizeof(EstablishPACEChannelInput));
    
    pEstablishPACEChannelInput->passwordID.buf = &passwordID;
    pEstablishPACEChannelInput->passwordID.size = sizeof(uint8_t);
    pEstablishPACEChannelInput->certificateDescription = pCertificateDescription;
    
    pEstablishPACEChannelInput->cHAT = (struct OCTET_STRING*) malloc(sizeof(struct OCTET_STRING));
    pEstablishPACEChannelInput->cHAT->buf = (unsigned char *) chat;
    pEstablishPACEChannelInput->cHAT->size = chat_len;
    
    pEstablishPACEChannelInput->cHATrequired = (struct OCTET_STRING*) malloc(sizeof(struct OCTET_STRING));
    pEstablishPACEChannelInput->cHATrequired->buf = (unsigned char *) chat_required;
    pEstablishPACEChannelInput->cHATrequired->size = chat_required_len;
    
    pEstablishPACEChannelInput->cHAToptional = (struct OCTET_STRING*) malloc(sizeof(struct OCTET_STRING));
    pEstablishPACEChannelInput->cHAToptional->buf = (unsigned char *) chat_optional;
    pEstablishPACEChannelInput->cHAToptional->size = chat_optional_len;

	pEstablishPACEChannelInput->transactionInfo = (OCTET_STRING_t*) malloc(sizeof(OCTET_STRING_t));
    pEstablishPACEChannelInput->transactionInfo->buf = (unsigned char *) transaction_info_hidden;
    pEstablishPACEChannelInput->transactionInfo->size = transaction_info_hidden_len;
    
	pEstablishPACEChannelInput->transactionInfoHashOID = (OBJECT_IDENTIFIER_t*) malloc(sizeof(OBJECT_IDENTIFIER_t));
	pEstablishPACEChannelInput->transactionInfoHashOID->buf = oid_hash_transactiondata;
	pEstablishPACEChannelInput->transactionInfoHashOID->size = oid_hash_transactiondata_len;

    
    er = der_encode_to_buffer(&asn_DEF_EstablishPACEChannelInput, pEstablishPACEChannelInput, &buf[0], bufSize);
    
    if(er.encoded == -1)
    {
        asn_DEF_CertificateDescription.free_struct(&asn_DEF_CertificateDescription, pCertificateDescription, 0);
        free(pEstablishPACEChannelInput->cHAT);
        free(pEstablishPACEChannelInput->cHATrequired);
        free(pEstablishPACEChannelInput->cHAToptional);
		free(pEstablishPACEChannelInput->transactionInfo);
		free(pEstablishPACEChannelInput->transactionInfoHashOID);
        free(pEstablishPACEChannelInput);
        eCardCore_debug(DEBUG_LEVEL_CLIENT, "encode_EstablishPACEChannelInput - Could not encode EstablishPACEChannelInput.");
        return ECARD_ASN1_PARSER_ERROR;
    }
    
    *bufEstablishPACEChannelInput = (unsigned char*) malloc(er.encoded);
	if (!*bufEstablishPACEChannelInput)
		return ECARD_BUFFER_TO_SMALL;
    *bufEstablishPACEChannelInput_len = er.encoded;
    memcpy(*bufEstablishPACEChannelInput, &buf[0], *bufEstablishPACEChannelInput_len);
    
    asn_DEF_CertificateDescription.free_struct(&asn_DEF_CertificateDescription, pCertificateDescription, 0);
    free(pEstablishPACEChannelInput->cHAT);
	free(pEstablishPACEChannelInput->cHATrequired);
	free(pEstablishPACEChannelInput->cHAToptional);
	free(pEstablishPACEChannelInput->transactionInfo);
	free(pEstablishPACEChannelInput->transactionInfoHashOID);
    free(pEstablishPACEChannelInput);
    
    return ECARD_SUCCESS;
}

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
        size_t* const chat_len)
{
    asn_enc_rval_t                  er;
    EstablishPACEChannelOutput_t*   pEstablishPACEChannelOutput = 0x00;
    unsigned char                   buf[1000];
    size_t                          bufSize = 1000;

    if(0x00 == result)
        return ECARD_INVALID_PARAMETER_1;
    if(0x00 == status_mse_set_at)
        return ECARD_INVALID_PARAMETER_1;
    if(0x00 == ef_cardaccess)
        return ECARD_INVALID_PARAMETER_1;
    if(0x00 == car_curr)
        return ECARD_INVALID_PARAMETER_1;
    if(0x00 == car_prev)
        return ECARD_INVALID_PARAMETER_1;
    if(0x00 == id_icc)
        return ECARD_INVALID_PARAMETER_1;
    if(0x00 == chat)
        return ECARD_INVALID_PARAMETER_1;
    
    if (ber_decode(0, &asn_DEF_EstablishPACEChannelOutput, (void **)&pEstablishPACEChannelOutput, bufEstablishPACEChannelOutput, bufEstablishPACEChannelOutput_len).code != RC_OK)
    {
        eCardCore_debug(DEBUG_LEVEL_CLIENT, "decode_EstablishPACEChannelOutput - Could not decode pEstablishPACEChannelOutput.");
        asn_DEF_EstablishPACEChannelOutput.free_struct(&asn_DEF_EstablishPACEChannelOutput, pEstablishPACEChannelOutput, 0);
        return ECARD_ASN1_PARSER_ERROR;
    }
// TODO  check byte order -> decode OCTETSTRING to unsigned int and unsigned short
    if( (0x00 != pEstablishPACEChannelOutput->errorCode.buf) && (sizeof *result == pEstablishPACEChannelOutput->errorCode.size) )
    {
        memcpy(result, pEstablishPACEChannelOutput->errorCode.buf, pEstablishPACEChannelOutput->errorCode.size);
    }
    if( (0x00 != pEstablishPACEChannelOutput->statusMSESetAT.buf) && (sizeof *status_mse_set_at == pEstablishPACEChannelOutput->statusMSESetAT.size) )
    {
        memcpy(status_mse_set_at, pEstablishPACEChannelOutput->statusMSESetAT.buf, pEstablishPACEChannelOutput->statusMSESetAT.size);
    }

    memset(&buf[0], 0x00, bufSize);
    er = der_encode_to_buffer(&asn_DEF_SecurityInfos, &pEstablishPACEChannelOutput->efCardAccess, &buf[0], bufSize);
    
    if(er.encoded == -1)
    {
        eCardCore_debug(DEBUG_LEVEL_CLIENT, "decode_EstablishPACEChannelOutput - Could not encode EstablishPACEChannelOutput->efCardAccess.");
        asn_DEF_CertificateDescription.free_struct(&asn_DEF_EstablishPACEChannelOutput, pEstablishPACEChannelOutput, 0);
        return ECARD_ASN1_PARSER_ERROR;
    }
    
    *ef_cardaccess = (unsigned char*) malloc(er.encoded);
	if (!*ef_cardaccess)
		return ECARD_BUFFER_TO_SMALL;
    *ef_cardaccess_len = er.encoded;
    memcpy(*ef_cardaccess, &buf[0], *ef_cardaccess_len);

    if(0x00 != pEstablishPACEChannelOutput->curCAR)
    {
        *car_curr = (unsigned char*) malloc(pEstablishPACEChannelOutput->curCAR->size);
		if (!*car_curr)
			return ECARD_BUFFER_TO_SMALL;
        *car_curr_len = pEstablishPACEChannelOutput->curCAR->size;
        memcpy(*car_curr, pEstablishPACEChannelOutput->curCAR->buf, *car_curr_len);
    }

    if(0x00 != pEstablishPACEChannelOutput->prevCAR)
    {
        *car_prev = (unsigned char*) malloc(pEstablishPACEChannelOutput->prevCAR->size);
		if (!*car_prev)
			return ECARD_BUFFER_TO_SMALL;
        *car_prev_len = pEstablishPACEChannelOutput->prevCAR->size;
        memcpy(*car_prev, pEstablishPACEChannelOutput->prevCAR->buf, *car_prev_len);
    }

    if(0x00 != pEstablishPACEChannelOutput->idPICC)
    {
        *id_icc = (unsigned char*) malloc(pEstablishPACEChannelOutput->idPICC->size);
		if (!*id_icc)
			return ECARD_BUFFER_TO_SMALL;
        *id_icc_len= pEstablishPACEChannelOutput->idPICC->size;
        memcpy(*id_icc, pEstablishPACEChannelOutput->idPICC->buf, *id_icc_len);
    }

    if(0x00 != pEstablishPACEChannelOutput->cHATout)
    {
        *chat = (unsigned char*) malloc(pEstablishPACEChannelOutput->cHATout->size);
		if (!*chat)
			return ECARD_BUFFER_TO_SMALL;
        *chat_len = pEstablishPACEChannelOutput->cHATout->size;
        memcpy(*chat, pEstablishPACEChannelOutput->cHATout->buf, *chat_len);
    }
            
    asn_DEF_EstablishPACEChannelOutput.free_struct(&asn_DEF_EstablishPACEChannelOutput, pEstablishPACEChannelOutput, 0);
    
    return ECARD_SUCCESS;
}
