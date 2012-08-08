#define STRSAFE_NO_DEPRECATE

#include "eCardCore/eCardTypes.h"
#include "eCardCore/eCardStatus.h"
#include "eCardCore/ICard.h"
#include "nPACommon.h"

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
 * Verify the response of an Secure Messaging APDU according to 
 * PKI for Machine Readable Travel Documents offering ICC read-only access
 * Release : 1.1
 * Date : October 01, 2004
 */
bool verifyResponse_AES( 
						const std::vector<unsigned char>& kMac, 
						const std::vector<unsigned char>& dataPart,
						unsigned long long &ssc)
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
											   std::vector<unsigned char>& kEnc,
											   const std::vector<unsigned char>& returnedData,
											   unsigned long long ssc)
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