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

ePACard::ePACard(IReader *hSubSystem) : ICard(hSubSystem)
{
	if (!selectMF()
		|| !readFile(SFID_EF_CARDACCESS, CAPDU::DATA_EXTENDED_MAX, m_ef_cardaccess))
		throw WrongHandle();
}

ePACard::ePACard(IReader *hSubSystem,
	   	const vector<unsigned char> ef_cardaccess) : ICard(hSubSystem)
{
    m_ef_cardaccess = ef_cardaccess;
}

string ePACard::getCardDescription(void)
{
	return "German nPA";
}

const vector<unsigned char> ePACard::get_ef_cardaccess(void) const
{
	return m_ef_cardaccess;
}

const vector<unsigned char> ePACard::get_ef_cardsecurity(void)
{
	if (m_ef_cardsecurity.empty()
			/* read EF.CardSecurity in chunks that fit into short length APDU */
			&& !readFile(SFID_EF_CARDSECURITY, 0xDF, m_ef_cardsecurity))
		throw WrongHandle();

	return m_ef_cardsecurity;
}


#define BIT_PADDING 0x01
static std::vector<unsigned char> buildDO87_AES(
	const std::vector<unsigned char>& kEnc,
	const std::vector<unsigned char>& data,
	unsigned long long ssc)
{
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
   
	// Append padding content indicator
	encryptedData_.insert(encryptedData_.begin(), BIT_PADDING);

	return TLV_encode(0x87, encryptedData_);
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

	return TLV_encode(0x8E, result_);
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

	debug_CAPDU("Unencrypted", capdu);

	CAPDU sm_apdu = CAPDU(capdu.getCLA() | CAPDU::CLA_SM,
						  capdu.getINS(), capdu.getP1(), capdu.getP2());

	m_ssc++;

	if (!capdu.getData().empty()) {
		do87_ = buildDO87_AES(m_kEnc, capdu.getData(), m_ssc);
	}

	Le = capdu.encodedLe();

	if (!Le.empty()) {
		if (Le.size() > 2) {
			Le.erase(Le.begin());
		}
		do97_ = TLV_encode(0x97, Le);
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
	RAPDU rapdu(response, sm_rapdu.getSW());

	debug_RAPDU("Decrypted", rapdu);

	return rapdu;
}

vector<RAPDU> ePACard::transceive(const vector<CAPDU> &cmds)
{
	vector<RAPDU> resps;

	if (!m_kEnc.empty() && !m_kMac.empty()) {
		unsigned long long start_ssc = m_ssc;
		size_t i;
		bool sm = true;
		vector<CAPDU> sm_cmds;
		for (i = 0; i < cmds.size(); i++) {
			if (cmds[i].isSecure())
				sm = false;

			if (sm) {
				sm_cmds.push_back(applySM(cmds[i]));
				/* increment SSC, to simulate decryption of the APDU */
				m_ssc++;
			} else
				sm_cmds.push_back(cmds[i]);
		}

		vector<RAPDU> sm_resps = ICard::transceive(sm_cmds);
		if (cmds.size() > sm_resps.size()) {
			eCardCore_warn(DEBUG_LEVEL_APDU, "Received too few APDUs");
		}

		m_ssc = start_ssc;
		sm = true;
		for (i = 0; i < sm_resps.size() && i < cmds.size(); i++) {
			if (cmds[i].isSecure())
				sm = false;
			if (sm) {
				/* increment SSC, to simulate encryption of the APDU */
				m_ssc++;
				resps.push_back(removeSM(sm_resps[i]));
			} else
				resps.push_back(sm_resps[i]);
		}

		for (i = 0; i < (cmds.size() - sm_resps.size()); i++) {
			resps.push_back(RAPDU(vector<unsigned char> (), 0x6d00));
		}

		if (!sm) {
			m_kEnc.clear();
			m_kMac.clear();
			m_ssc = 0;
		}
	} else {
		resps = ICard::transceive(cmds);
	}

	return resps;
}

RAPDU ePACard::transceive(const CAPDU &cmd)
{
	return BatchTransceiver<CAPDU, RAPDU>::transceive(cmd);
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

