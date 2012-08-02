// ---------------------------------------------------------------------------
// Copyright (c) 2009 Bundesdruckerei GmbH
// All rights reserved.
//
// $Id: ePACommon.cpp 1291 2011-09-07 10:25:24Z dietrfra $
// ---------------------------------------------------------------------------

#define STRSAFE_NO_DEPRECATE

#include <eCardCore.h>
#include <eCardTypes.h>
#include <eCardStatus.h>
#include <ICard.h>
#include <ePACommon.h>

#include <PACEDomainParameterInfo.h>
#include <ECParameters.h>
#include <CertificateBody.h>
#include <CVCertificate.h>
#include <CertificateDescription.h>

#include <debug.h>

#include <vector>
#if defined(WIN32) && !defined(_WIN32_WCE)
#include <windows.h>
#endif


/*
 * Build up the DO87 Part of an Secure Messaging APDU according to 
 * PKI for Machine Readable Travel Documents offering ICC read-only access
 * Release : 1.1
 * Date : October 01, 2004
 */
std::vector<unsigned char> buildDO87_AES(
										 IN const std::vector<unsigned char>& kEnc,
										 IN const std::vector<unsigned char>& data,
										 IN unsigned long long ssc)
{
	std::vector<unsigned char> do87;
	std::vector<unsigned char> data_ = static_cast<std::vector<unsigned char> >(data);
	
	data_.push_back(0x80);
	while (data_.size() % kEnc.size())
		data_.push_back(0x00);
	
	unsigned char iv_[] = { 
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	
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
	
	if (encryptedSize <= 0x80)
	{ 
		do87.push_back(encryptedSize); 
	} else if (encryptedSize > 0x80 && encryptedSize <= 0xFF)
	{
		do87.push_back(0x81);
		do87.push_back(encryptedSize);
	} else if (encryptedSize > 0xFF && encryptedSize <= 0xFFFF)
	{
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
std::vector<unsigned char> buildDO8E_AES(
										 IN const std::vector<unsigned char>& kMac,
										 IN const std::vector<unsigned char>& data,
										 IN const std::vector<unsigned char>& do87,
										 IN const std::vector<unsigned char>& do97,
										 IN OUT unsigned long long &ssc)
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
	do8E.push_back(0x8E); do8E.push_back(0x08);
	
	for (size_t o = 0; o < result_.size(); o++)
		do8E.push_back(result_[o]);
	
	return do8E;
}

/*
 * Verify the response of an Secure Messaging APDU according to 
 * PKI for Machine Readable Travel Documents offering ICC read-only access
 * Release : 1.1
 * Date : October 01, 2004
 */
bool verifyResponse_AES( 
						IN const std::vector<unsigned char>& kMac, 
						IN const std::vector<unsigned char>& dataPart,
						IN unsigned long long &ssc)
{
	if (0x00 == dataPart.size())
		return false;
	
	// Store the SSC as vector.
	std::vector<unsigned char> ssc_;
	
	for (size_t i = 0; i < kMac.size() - 8; i++)
		ssc_.push_back(0x00);
	
	ssc_.push_back((ssc << 56) & 0xFF);
	ssc_.push_back((ssc << 48) & 0xFF);
	ssc_.push_back((ssc << 40) & 0xFF);
	ssc_.push_back((ssc << 32) & 0xFF);
	ssc_.push_back((ssc << 24) & 0xFF);
	ssc_.push_back((ssc << 16) & 0xFF);
	ssc_.push_back((ssc << 8) & 0xFF);
	ssc_.push_back(ssc & 0xFF);
	
	// Increment the SSC
	Integer issc(&ssc_[0], kMac.size());
	issc += 1;
	
	// The data buffer for the computations. 
	std::vector<unsigned char> vssc;
	vssc.resize(kMac.size());
	issc.Encode(&vssc[0], kMac.size());
	
	// Set the SSC to the new value.
	// {
	issc.Encode(&ssc_[0], kMac.size()); // Encode the incremented value to ssc_
	ssc = 0;                  // Clear the old value.
	// Shift the new value to ssc.
	ssc += (unsigned long long) ssc_[8] << 56;
	ssc += (unsigned long long) ssc_[9] << 48;
	ssc += (unsigned long long) ssc_[10] << 40;
	ssc += (unsigned long long) ssc_[11] << 32;
	ssc += (unsigned long long) ssc_[12] << 24;
	ssc += (unsigned long long) ssc_[13] << 16;
	ssc += (unsigned long long) ssc_[14] << 8;
	ssc += (unsigned long long) ssc_[15];
	// }
	
	// Check for the right types of data
	if (dataPart[0] != 0x99 && dataPart[0] != 0x87)
	{
#if defined(WIN32) && !defined(_WIN32_WCE)
		OutputDebugStringA("Verify MAC failed! Invalid data format!");
#endif
		return false;
	}
	
	// ?? Should we check here for the ISO padding byte if dataPart[0] == 0x87 ??
	
	// Copy all excluding the MAC value
	for (size_t i = 0; i < dataPart.size() - 10; i++)
		vssc.push_back(dataPart[i]);
	
	// Append padding
	vssc.push_back(0x80);
	while (vssc.size() % kMac.size())
		vssc.push_back(0x00);
	
	std::vector<unsigned char> kMac_;
	for (size_t i = 0; i < kMac.size(); i++)
		kMac_.push_back(kMac[i]);
	
	std::vector<unsigned char> calculatedMAC_ = calculateMAC(vssc, kMac_);
	
	// Compare the calculated MAC against the returned MAC. If equal all is fine ;)
	if (memcmp(&dataPart[dataPart.size() - 8], &calculatedMAC_[0], 8))
	{		
		return false; // Hmmm ... That should not happen 
	}
	
	return true;
}


/**
 * @brief Decrypt the response.
 */
std::vector<unsigned char> decryptResponse_AES(
											   IN std::vector<unsigned char>& kEnc,
											   IN const std::vector<unsigned char>& returnedData,
											   IN unsigned long long ssc)
{
	std::vector<unsigned char> result_;
	
	if (returnedData[0] == 0x87)
	{
		int len = 0;
		int offset = 0;
		if (0x81 == returnedData[1])
		{ 
			len = returnedData[2]; 
			offset = 4;
		}  
		else if (0x82 == returnedData[1])
		{
			len = returnedData[2] << 8;
			len += returnedData[3];
			offset = 5;
		} else 
		{ 
			len = returnedData[1]; 
			offset = 3;
		}
		
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
		
		std::vector<unsigned char> calculatedIV_;
		
		CBC_Mode<AES>::Encryption AESCBC_encryption;
		if (false == AESCBC_encryption.IsValidKeyLength(kEnc.size()))
			return calculatedIV_; // Wen can return here because the resulting vector is empty. 
		// This will be checked by the caller.
		
		unsigned char iv_[] = { 
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		
		calculatedIV_.resize(kEnc.size());
		AESCBC_encryption.SetKeyWithIV(&kEnc[0], kEnc.size(), iv_);
		AESCBC_encryption.ProcessData(&calculatedIV_[0], &ssc_[0], ssc_.size());
		
		CBC_Mode<AES>::Decryption AESCBC_decryption;
		
		std::vector<unsigned char> decrypted;
		decrypted.resize(len - 1);
		AESCBC_decryption.SetKeyWithIV(&kEnc[0], kEnc.size(), &calculatedIV_[0]);
		AESCBC_decryption.ProcessData(&decrypted[0], &returnedData[offset], len - 1);
		
		int padOffset = -1;
		for (int i = decrypted.size() - 1; i > 0; i--)
		{
			if (decrypted[i] == 0x80)
			{
				padOffset = i;
				break;
			}
		}
		
		// We have to check if padding was found!? If not we have an error while decryption???
		
		for (int i = 0; i < padOffset; i++)
			result_.push_back(decrypted[i]);
	}
	
	return result_;
}

std::vector<unsigned char> generate_PrK_IFD_DHx(
												IN const AlgorithmIdentifier* PACEDomainParameterInfo_)
{
	std::vector<unsigned char> result;
	result.resize(32);
	
	AutoSeededRandomPool rng;  
	rng.GenerateBlock(
					  &result[0], result.size()); 
	
	return result;
}

ECP::Point calculate_PuK_IFD_DHx(
								 IN const std::vector<unsigned char>& PrK_IFD_DHx,
								 IN const AlgorithmIdentifier* PACEDomainParameterInfo)
{
		hexdump(DEBUG_LEVEL_CRYPTO, "###-> PrK.IFD.DHx in calculate_PuK_IFD_DHx", (void*) &PrK_IFD_DHx[0], PrK_IFD_DHx.size());
		
		Integer k(&PrK_IFD_DHx[0], PrK_IFD_DHx.size());
		
		Integer a("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9h");
		Integer b("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6h");
		
		Integer Mod("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377h");
		ECP ecp(Mod, a, b);
		
		Integer X("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262h");
		Integer Y("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997h");
		ECP::Point G(X, Y);  
		
		ECP::Point result = ecp.Multiply(k, G);
		
		std::vector<unsigned char> x_;
		std::vector<unsigned char> y_;
		
		x_.resize(result.x.ByteCount());
		y_.resize(result.y.ByteCount());
		result.x.Encode(&x_[0], result.x.ByteCount());
		result.y.Encode(&y_[0], result.y.ByteCount());
		
		if (x_.size() != 0x20)
			x_.insert(x_.begin(), 0x00);
		
		if (y_.size() != 0x20)
			y_.insert(y_.begin(), 0x00);
		
		hexdump(DEBUG_LEVEL_CRYPTO, "###-> PuK.IFD.DHx.x", (void*) &x_[0], x_.size());
		hexdump(DEBUG_LEVEL_CRYPTO, "###-> PuK.IFD.DHx.y", (void*) &y_[0], y_.size());
		
		return result;
}

/**
 */
std::vector<unsigned char> calculateMAC(
										const std::vector<unsigned char>& toBeMaced,
										const std::vector<unsigned char>& kMac)
{
	std::vector<unsigned char> result_;
	result_.resize(toBeMaced.size());
	
	CMAC<AES> cmac;
	cmac.SetKey(&kMac[0], kMac.size()); 
	cmac.Update(&toBeMaced[0], toBeMaced.size()); 
	cmac.Final(&result_[0]);
	
	result_.resize(8);
	
	return result_;
}

/*
 *
 */
std::string getCAR(
				   const std::vector<unsigned char>& certificate)
{
	std::string car_;
	
	CVCertificate_t	*CVCertificate = 0x00;
	if (ber_decode(0, &asn_DEF_CVCertificate, (void **)&CVCertificate,
				   &certificate[0], certificate.size()).code != RC_OK)
	{
#if defined(WIN32)		
		OutputDebugStringA("getCAR failed ...\n");
#endif		
		
		asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
		return car_;
	}
	
	for (int i = 0; i < CVCertificate->certBody.certAuthRef.size; i++)
		car_.push_back(CVCertificate->certBody.certAuthRef.buf[i]);
	
	asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
	
	return car_;
}

/*
 *
 */
std::string getCHR(
				   const std::vector<unsigned char>& certificate)
{
	std::string chr_;
	
	CVCertificate_t	*CVCertificate = 0x00;
	if (ber_decode(0, &asn_DEF_CVCertificate, (void **)&CVCertificate,
				   &certificate[0], certificate.size()).code != RC_OK)
	{
#if defined(WIN32)		
		OutputDebugStringA("getCHR failed ...\n");
#endif
		asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
		return chr_;
	}
	
	for (int i = 0; i < CVCertificate->certBody.certHolderRef.size; i++)
		chr_.push_back(CVCertificate->certBody.certHolderRef.buf[i]);
	
	asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
	
	return chr_;
}
