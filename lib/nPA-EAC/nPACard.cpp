/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#include "nPACard.h"
#include "nPACommon.h"
using namespace Bundesdruckerei::nPA;

static std::vector<unsigned char> buildDO87_AES(
	const std::vector<unsigned char>& kEnc,
	const std::vector<unsigned char>& data,
	unsigned long long ssc);

static std::vector<unsigned char> buildDO8E_AES(
	const std::vector<unsigned char>& kMac,
	const std::vector<unsigned char>& data,
	const std::vector<unsigned char>& do87,
	const std::vector<unsigned char>& do97,
	unsigned long long &ssc);

static bool verifyResponse_AES(
	const std::vector<unsigned char>& kMac,
	const std::vector<unsigned char>& dataPart,
	unsigned long long &ssc);

static std::vector<unsigned char> decryptResponse_AES(
	std::vector<unsigned char>& kEnc,
	const std::vector<unsigned char>& returnedData,
	unsigned long long ssc);

ePACard::ePACard(
	IReader *hSubSystem) : ICard(hSubSystem)
{
	if (!selectMF()
		|| !readFile(SFID_EF_CARDACCESS, CAPDU::DATA_EXTENDED_MAX, m_ef_cardaccess))
		throw WrongHandle();
}

ePACard::ePACard(
	IReader *hSubSystem, const vector<unsigned char> ef_cardaccess) : ICard(hSubSystem)
{
    m_ef_cardaccess = ef_cardaccess;
}

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

bool ePACard::selectDF(
	unsigned short FID)
{
	SelectFile select(SelectFile::P1_SELECT_DF, SelectFile::P2_NO_RESPONSE, FID);
	RAPDU response = sendAPDU(select);
	return response.isOK();
}

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
	Integer issc(ssc_.data(), kEnc.size());
	std::vector<unsigned char> vssc;
	vssc.resize(kEnc.size());
	issc.Encode(vssc.data(), kEnc.size());
	std::vector<unsigned char> calculatedIV_;
	CBC_Mode<AES>::Encryption AESCBC_encryption;

	if (false == AESCBC_encryption.IsValidKeyLength(kEnc.size()))
		return calculatedIV_;

	calculatedIV_.resize(kEnc.size());
	AESCBC_encryption.SetKeyWithIV(kEnc.data(), kEnc.size(), iv_);
	AESCBC_encryption.ProcessData(calculatedIV_.data(), vssc.data(), vssc.size());
	CBC_Mode<AES>::Encryption AESCBC_encryption1;
	std::vector<unsigned char> encryptedData_;
	encryptedData_.resize(data_.size());
	AESCBC_encryption1.SetKeyWithIV(kEnc.data(), kEnc.size(), calculatedIV_.data());
	AESCBC_encryption1.ProcessData(encryptedData_.data(), data_.data(), data_.size());
	do87.push_back(0x87);
	size_t encryptedSize = encryptedData_.size() + 1; // +1 because of padding content indicator

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

	// Do padding on APDU header
	data_.push_back(0x80);
	while (data_.size() % AES::BLOCKSIZE)
		data_.push_back(0x00);

	// Append the DO87 data
	for (size_t u = 0; u < do87.size(); u++)
		data_.push_back(do87[u]);

	// Append the DO97 data
	for (size_t u = 0; u < do97.size(); u++)
		data_.push_back(do97[u]);

	// Append padding to data part
	if (!do97.empty() || !do87.empty()) {
		data_.push_back(0x80);

		while (data_.size() % AES::BLOCKSIZE)
			data_.push_back(0x00);
	}

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
	Integer issc(ssc_.data(), AES::BLOCKSIZE);
	std::vector<unsigned char> vssc;
	vssc.resize(AES::BLOCKSIZE);
	issc.Encode(vssc.data(), AES::BLOCKSIZE);
	issc.Encode(ssc_.data(), AES::BLOCKSIZE);
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

	std::vector<unsigned char> result_;
	result_.resize(vssc.size());
	CMAC<AES> cmac;
	cmac.SetKey(kMac.data(), kMac.size());
	cmac.Update(vssc.data(), vssc.size());
	cmac.Final(result_.data());
	result_.resize(8);
	std::vector<unsigned char> do8E;
	do8E.push_back(0x8E);
	do8E.push_back(0x08);

	for (size_t o = 0; o < result_.size(); o++)
		do8E.push_back(result_[o]);

	return do8E;
}

bool verifyResponse_AES(
	const std::vector<unsigned char>& kMac,
	const std::vector<unsigned char>& dataPart,
	unsigned long long &ssc)
{
	if (0x00 == dataPart.size())
		return false;

	std::vector<unsigned char> ssc_;

	for (size_t i = 0; i < AES::BLOCKSIZE - 8; i++)
		ssc_.push_back(0x00);

	ssc_.push_back((ssc << 56) & 0xFF);
	ssc_.push_back((ssc << 48) & 0xFF);
	ssc_.push_back((ssc << 40) & 0xFF);
	ssc_.push_back((ssc << 32) & 0xFF);
	ssc_.push_back((ssc << 24) & 0xFF);
	ssc_.push_back((ssc << 16) & 0xFF);
	ssc_.push_back((ssc << 8) & 0xFF);
	ssc_.push_back(ssc & 0xFF);
	Integer issc(ssc_.data(), AES::BLOCKSIZE);
	// The data buffer for the computations.
	std::vector<unsigned char> vssc;
	vssc.resize(AES::BLOCKSIZE);
	issc.Encode(vssc.data(), AES::BLOCKSIZE);
	issc.Encode(ssc_.data(), AES::BLOCKSIZE);
	ssc = 0;
	ssc += (unsigned long long) ssc_[8] << 56;
	ssc += (unsigned long long) ssc_[9] << 48;
	ssc += (unsigned long long) ssc_[10] << 40;
	ssc += (unsigned long long) ssc_[11] << 32;
	ssc += (unsigned long long) ssc_[12] << 24;
	ssc += (unsigned long long) ssc_[13] << 16;
	ssc += (unsigned long long) ssc_[14] << 8;
	ssc += (unsigned long long) ssc_[15];

	// Check for the right types of data
	if (dataPart[0] != 0x99 && dataPart[0] != 0x87) {
		return false;
	}

	// Copy all excluding the MAC value
	for (size_t i = 0; i < dataPart.size() - 10; i++)
		vssc.push_back(dataPart[i]);

	// Append padding
	vssc.push_back(0x80);
	while (vssc.size() % AES::BLOCKSIZE)
		vssc.push_back(0x00);

	std::vector<unsigned char> kMac_;

	for (size_t i = 0; i < AES::BLOCKSIZE; i++)
		kMac_.push_back(kMac[i]);

	std::vector<unsigned char> calculatedMAC_ = calculateMAC(vssc, kMac_);

	// Compare the calculated MAC against the returned MAC. If equal all is fine ;)
	if (memcmp(&dataPart[dataPart.size() - 8], calculatedMAC_.data(), 8)) {
		return false;
	}

	return true;
}

std::vector<unsigned char> decryptResponse_AES(
	std::vector<unsigned char>& kEnc,
	const std::vector<unsigned char>& returnedData,
	unsigned long long ssc)
{
	std::vector<unsigned char> result_;

	if (returnedData[0] == 0x87) {
		size_t len = 0;
		int offset = 0;

		if (0x81 == returnedData[1]) {
			len = returnedData[2];
			offset = 4;

		} else if (0x82 == returnedData[1]) {
			len = returnedData[2] << 8;
			len += returnedData[3];
			offset = 5;

		} else {
			len = returnedData[1];
			offset = 3;
		}

		// Build the IV
		std::vector<unsigned char> ssc_;

		for (size_t i = 0; i < 8; i++)
			ssc_.push_back(0x00);

		ssc_.push_back((ssc << 56) & 0xFF);
		ssc_.push_back((ssc << 48) & 0xFF);
		ssc_.push_back((ssc << 40) & 0xFF);
		ssc_.push_back((ssc << 32) & 0xFF);
		ssc_.push_back((ssc << 24) & 0xFF);
		ssc_.push_back((ssc << 16) & 0xFF);
		ssc_.push_back((ssc << 8) & 0xFF);
		ssc_.push_back(ssc & 0xFF);
		std::vector<unsigned char> calculatedIV_;
		CBC_Mode<AES>::Encryption AESCBC_encryption;

		if (false == AESCBC_encryption.IsValidKeyLength(kEnc.size()))
			return calculatedIV_;
		unsigned char iv_[] = {
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
		};
		calculatedIV_.resize(kEnc.size());
		AESCBC_encryption.SetKeyWithIV(kEnc.data(), kEnc.size(), iv_);
		AESCBC_encryption.ProcessData(calculatedIV_.data(), ssc_.data(), ssc_.size());
		CBC_Mode<AES>::Decryption AESCBC_decryption;
		std::vector<unsigned char> decrypted;
		decrypted.resize(len - 1);
		AESCBC_decryption.SetKeyWithIV(kEnc.data(), kEnc.size(), calculatedIV_.data());
		AESCBC_decryption.ProcessData(decrypted.data(), &returnedData[offset], len - 1);
		size_t padOffset = 0;

		for (size_t i = decrypted.size() - 1; i > 0; i--) {
			if (decrypted[i] == 0x80) {
				padOffset = i;
				break;
			}
		}

		for (size_t i = 0; i < padOffset; i++)
			result_.push_back(decrypted[i]);
	}

	return result_;
}

CAPDU ePACard::applySM(const CAPDU &capdu)
{
	std::vector<unsigned char> do87_, do8E_, do97_, Le, sm_data;
	CAPDU sm_apdu = CAPDU(capdu.getCLA() | CAPDU::CLA_SM,
						  capdu.getINS(), capdu.getP1(), capdu.getP2());

	m_ssc++;

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

	sm_rdata = sm_rapdu.getData();

	m_ssc++;

	if (!verifyResponse_AES(m_kMac, sm_rdata, m_ssc))
		throw WrongSM();

	response = decryptResponse_AES(m_kEnc, sm_rdata, m_ssc);
	/* TODO compare DO99 with SW */
	return RAPDU(response, sm_rapdu.getSW());
}

RAPDU ePACard::sendAPDU(const CAPDU &cmd)
{
	if (!m_kEnc.empty() && !m_kMac.empty() && !cmd.isSecure()) {
		CAPDU sm_apdu = applySM(cmd);
		RAPDU sm_rapdu = ICard::sendAPDU(sm_apdu);
		return removeSM(sm_rapdu);
	}

	return ICard::sendAPDU(cmd);
}

vector<RAPDU> ePACard::sendAPDUs(const vector<CAPDU> &cmds)
{
	vector<RAPDU> resps;

	if (!m_kEnc.empty() && !m_kMac.empty()) {
		unsigned long long start_ssc = m_ssc;
		size_t i;
		vector<CAPDU> sm_cmds;
		for (i = 0; i < cmds.size(); i++) {
			if (!cmds[i].isSecure()) {
				sm_cmds.push_back(applySM(cmds[i]));
				/* increment SSC, to simulate decryption of the APDU */
				m_ssc++;
			} else
				sm_cmds.push_back(cmds[i]);
		}

		vector<RAPDU> sm_resps = ICard::sendAPDUs(sm_cmds);

		m_ssc = start_ssc;
		for (i = 0; i < sm_resps.size() && i < cmds.size(); i++) {
			if (!cmds[i].isSecure()) {
				/* increment SSC, to simulate encryption of the APDU */
				m_ssc++;
				resps.push_back(removeSM(sm_resps[i]));
			} else
				resps.push_back(sm_resps[i]);
		}
	} else {
		resps = ICard::sendAPDUs(cmds);
	}

	return resps;
}

void ePACard::setKeys(vector<unsigned char>& kEnc, vector<unsigned char>& kMac)
{
	m_kEnc = kEnc;
	m_kMac = kMac;
	m_ssc = 0;
}

void ePACard::setSSC(unsigned long long ssc)
{
	m_ssc = ssc;
}

ICard *ePACardDetector::getCard(IReader *reader)
{
	try {
		return new ePACard(reader);

	} catch (...) {
	}

	return 0x00;
}

