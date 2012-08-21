/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#include "nPACard.h"
#include "nPACommon.h"
using namespace Bundesdruckerei::nPA;

/**
 */
static std::vector<unsigned char> buildDO87_AES(
	const std::vector<unsigned char>& kEnc,
	const std::vector<unsigned char>& data,
	unsigned long long ssc);

/**
 */
static std::vector<unsigned char> buildDO8E_AES(
	const std::vector<unsigned char>& kMac,
	const std::vector<unsigned char>& data,
	const std::vector<unsigned char>& do87,
	const std::vector<unsigned char>& do97,
	unsigned long long &ssc);

/*
 *
 */
ePACard::ePACard(
	IReader *hSubSystem) : ICard(hSubSystem)
{
	if (!selectMF()
		|| !readFile(SFID_EF_CARDACCESS, CAPDU::DATA_EXTENDED_MAX, m_ef_cardaccess))
		throw WrongHandle();
}

/*
 *
 */
string ePACard::getCardDescription(
	void)
{
	return "German nPA";
}

const vector<unsigned char> ePACard::get_ef_cardaccess() const
{
	return m_ef_cardaccess;
}

const vector<unsigned char> ePACard::get_ef_cardsecurity()
{
	if (m_ef_cardsecurity.empty()
		&& !readFile(SFID_EF_CARDSECURITY, CAPDU::DATA_EXTENDED_MAX, m_ef_cardsecurity))
		throw WrongHandle();

	return m_ef_cardsecurity;
}

bool ePACard::selectMF(
	void)
{
	SelectFile select(SelectFile::P1_SELECT_FID, SelectFile::P2_NO_RESPONSE);
	RAPDU response = sendAPDU(select);
	return response.isOK();
}

/*
 *
 */
bool ePACard::selectEF(
	unsigned short FID)
{
	SelectFile select(SelectFile::P1_SELECT_EF, SelectFile::P2_NO_RESPONSE, FID);
	RAPDU response = sendAPDU(select);
	return response.isOK();
}

bool ePACard::selectEF(
	unsigned short FID,
	vector<unsigned char>& fcp)
{
	SelectFile select(SelectFile::P1_SELECT_EF, SelectFile::P2_FCP_TEMPLATE, FID);
	select.setNe(CAPDU::DATA_SHORT_MAX);
	RAPDU response = sendAPDU(select);
	fcp = response.getData();
	return response.isOK();
}

/*
 *
 */
bool ePACard::selectDF(
	unsigned short FID)
{
	SelectFile select(SelectFile::P1_SELECT_DF, SelectFile::P2_NO_RESPONSE, FID);
	RAPDU response = sendAPDU(select);
	return response.isOK();
}

/*
 *
 */
bool ePACard::readFile(
	unsigned char sfid,
	size_t size,
	vector<unsigned char>& result)
{
	ReadBinary read = ReadBinary(0, sfid);
	read.setNe(size);
	RAPDU response = sendAPDU(read);
	result = response.getData();
	return response.isOK();
}

bool ePACard::readFile(
	vector<unsigned char>& result)
{
	ReadBinary read = ReadBinary();
	read.setNe(CAPDU::DATA_EXTENDED_MAX);
	RAPDU response = sendAPDU(read);
	result = response.getData();
	return response.isOK();
}

/*
 * Build up the DO87 Part of an Secure Messaging APDU according to
 * PKI for Machine Readable Travel Documents offering ICC read-only access
 * Release : 1.1
 * Date : October 01, 2004
 */
static std::vector<unsigned char> buildDO87_AES(
	const std::vector<unsigned char>& kEnc,
	const std::vector<unsigned char>& data,
	unsigned long long ssc)
{
	std::vector<unsigned char> do87;
	std::vector<unsigned char> data_ = static_cast<std::vector<unsigned char> >(data);
	data_.push_back(0x80);

	while (data_.size() % kEnc.size())
		data_.push_back(0x00);

	unsigned char iv_[] = {
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	};
	// Build the IV
	std::vector<unsigned char> ssc_;

	for (int i = 0; i < 8; i++)
		ssc_.push_back(0x00);

	ssc_.push_back((ssc << 56) & 0xFF);
	ssc_.push_back((ssc << 48) & 0xFF);
	ssc_.push_back((ssc << 40) & 0xFF);
	ssc_.push_back((ssc << 32) & 0xFF);
	ssc_.push_back((ssc << 24) & 0xFF);
	ssc_.push_back((ssc << 16) & 0xFF);
	ssc_.push_back((ssc << 8) & 0xFF);
	ssc_.push_back(ssc & 0xFF);
	Integer issc(&ssc_[0], kEnc.size());
	issc += 1;
	std::vector<unsigned char> vssc;
	vssc.resize(kEnc.size());
	issc.Encode(&vssc[0], kEnc.size());
	std::vector<unsigned char> calculatedIV_;
	CBC_Mode<AES>::Encryption AESCBC_encryption;

	if (false == AESCBC_encryption.IsValidKeyLength(kEnc.size()))
		return calculatedIV_; // Wen can return here because the resulting vector is empty.

	// This will be checked by the caller.
	calculatedIV_.resize(kEnc.size());
	AESCBC_encryption.SetKeyWithIV(&kEnc[0], kEnc.size(), iv_);
	AESCBC_encryption.ProcessData(&calculatedIV_[0], &vssc[0], vssc.size());
	CBC_Mode<AES>::Encryption AESCBC_encryption1;
	std::vector<unsigned char> encryptedData_;
	encryptedData_.resize(data_.size());
	AESCBC_encryption1.SetKeyWithIV(&kEnc[0], kEnc.size(), &calculatedIV_[0]);
	AESCBC_encryption1.ProcessData(&encryptedData_[0], &data_[0], data_.size());
	do87.push_back(0x87);
	size_t encryptedSize = encryptedData_.size() + 1; // +1 because of 0x01 before content see below "do87.push_back(0x01);"

	if (encryptedSize <= 0x80) {
		do87.push_back((unsigned char) encryptedSize);

	} else if (encryptedSize > 0x80 && encryptedSize <= 0xFF) {
		do87.push_back(0x81);
		do87.push_back((unsigned char) encryptedSize);

	} else if (encryptedSize > 0xFF && encryptedSize <= 0xFFFF) {
		do87.push_back(0x82);
		do87.push_back((encryptedSize & 0xFF00) >> 8);
		do87.push_back(encryptedSize & 0xFF);
	}

	// Append ISO padding byte
	do87.push_back(0x01);

	for (size_t z = 0; z < encryptedData_.size(); z++)
		do87.push_back(encryptedData_[z]);

	return do87;
}
/*
 * Build up the DO8E Part of an Secure Messaging APDU according to
 * PKI for Machine Readable Travel Documents offering ICC read-only access
 * Release : 1.1
 * Date : October 01, 2004
 */
static std::vector<unsigned char> buildDO8E_AES(
	const std::vector<unsigned char>& kMac,
	const std::vector<unsigned char>& data,
	const std::vector<unsigned char>& do87,
	const std::vector<unsigned char>& do97,
	unsigned long long &ssc)
{
	std::vector<unsigned char> mac;
	mac.resize(8);
	std::vector<unsigned char> data_ = static_cast<std::vector<unsigned char> >(data);
	// Do padding on data
	data_.push_back(0x80);

	while (data_.size() % kMac.size())
		data_.push_back(0x00);

	// Append the DO87 data
	for (size_t u = 0; u < do87.size(); u++)
		data_.push_back(do87[u]);

	// Append the DO97 data
	for (size_t u = 0; u < do97.size(); u++)
		data_.push_back(do97[u]);

	std::vector<unsigned char> ssc_;

	for (int i = 0; i < 8; i++)
		ssc_.push_back(0x00);

	ssc_.push_back((ssc << 56) & 0xFF);
	ssc_.push_back((ssc << 48) & 0xFF);
	ssc_.push_back((ssc << 40) & 0xFF);
	ssc_.push_back((ssc << 32) & 0xFF);
	ssc_.push_back((ssc << 24) & 0xFF);
	ssc_.push_back((ssc << 16) & 0xFF);
	ssc_.push_back((ssc << 8) & 0xFF);
	ssc_.push_back(ssc & 0xFF);
	Integer issc(&ssc_[0], kMac.size());
	issc += 1;
	std::vector<unsigned char> vssc;
	vssc.resize(kMac.size());
	issc.Encode(&vssc[0], kMac.size());
	issc.Encode(&ssc_[0], kMac.size());
	ssc = 0;
	ssc += (unsigned long long) ssc_[8] << 56;
	ssc += (unsigned long long) ssc_[9] << 48;
	ssc += (unsigned long long) ssc_[10] << 40;
	ssc += (unsigned long long) ssc_[11] << 32;
	ssc += (unsigned long long) ssc_[12] << 24;
	ssc += (unsigned long long) ssc_[13] << 16;
	ssc += (unsigned long long) ssc_[14] << 8;
	ssc += (unsigned long long) ssc_[15];

	for (size_t t = 0; t < data_.size(); t++)
		vssc.push_back(data_[t]);

	vssc.push_back(0x80);

	while (vssc.size() % kMac.size())
		vssc.push_back(0x00);

	std::vector<unsigned char> result_;
	result_.resize(vssc.size());
	CMAC<AES> cmac;
	cmac.SetKey(&kMac[0], kMac.size());
	cmac.Update(&vssc[0], vssc.size());
	cmac.Final(&result_[0]);
	result_.resize(8);
	std::vector<unsigned char> do8E;
	do8E.push_back(0x8E);
	do8E.push_back(0x08);

	for (size_t o = 0; o < result_.size(); o++)
		do8E.push_back(result_[o]);

	return do8E;
}
CAPDU ePACard::applySM(const CAPDU &capdu)
{
	std::vector<unsigned char> do87_, do8E_, do97_, Le, sm_data;
	CAPDU sm_apdu = CAPDU(capdu.getCLA() | CAPDU::CLA_SM,
						  capdu.getINS(), capdu.getP1(), capdu.getP2());

	if (!capdu.getData().empty()) {
		do87_ = buildDO87_AES(m_kEnc, capdu.getData(), m_ssc);
	}

	Le = capdu.encodedLe();

	if (!Le.empty()) {
		do97_.push_back(0x97);

		if (Le.size() > 2) {
			Le.erase(Le.begin());
		}

		do97_.push_back((unsigned char) Le.size());
		do97_.insert(do97_.end(), Le.begin(), Le.end());
	}

	/* here, sm_apdu is still a case 1 APDU with header only. */
	do8E_ = buildDO8E_AES(m_kMac, sm_apdu.asBuffer(), do87_, do97_, m_ssc);
	sm_data = do87_;
	sm_data.insert(sm_data.end(), do97_.begin(), do97_.end());
	sm_data.insert(sm_data.end(), do8E_.begin(), do8E_.end());
	sm_apdu.setData(sm_data);

	if (sm_apdu.isExtended() || capdu.isExtended())
		sm_apdu.setNe(CAPDU::DATA_EXTENDED_MAX);

	else
		sm_apdu.setNe(CAPDU::DATA_SHORT_MAX);

	return sm_apdu;
}

RAPDU ePACard::removeSM(const RAPDU &sm_rapdu)
{
	std::vector<unsigned char> response;
	std::vector<unsigned char> sm_rdata;
	// Get returned data.
	sm_rdata = sm_rapdu.getData();

	if (!verifyResponse_AES(m_kMac, sm_rdata, m_ssc))
		throw WrongSM();

	response = decryptResponse_AES(m_kEnc, sm_rdata, m_ssc);
	/* TODO compare DO99 with SW */
	return RAPDU(response, sm_rapdu.getSW());
}

RAPDU ePACard::sendAPDU(const CAPDU &cmd)
{
	if (!m_kEnc.empty() && !m_kMac.empty()
		&& !cmd.isSecure()) {
		CAPDU sm_apdu = applySM(cmd);
		RAPDU sm_rapdu = ICard::sendAPDU(sm_apdu);
		return removeSM(sm_rapdu);
	}

	return ICard::sendAPDU(cmd);
}

void ePACard::setKeys(vector<unsigned char>& kEnc, vector<unsigned char>& kMac)
{
	m_kEnc = kEnc;
	m_kMac = kMac;
	m_ssc = 0;
}

ICard *ePACardDetector::getCard(IReader *reader)
{
	try {
		return new ePACard(reader);

	} catch (...) {
	}

	return 0x00;
}

