/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#include "eCardCore/eCardTypes.h"
#include "eCardCore/eCardStatus.h"
#include "eCardCore/ICard.h"
#include "nPACommon.h"
#include "nPAAPI.h"

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




std::vector<unsigned char> calculateMAC(
	const std::vector<unsigned char>& toBeMaced,
	const std::vector<unsigned char>& kMac)
{
	std::vector<unsigned char> result_;
	result_.resize(toBeMaced.size());
	CMAC<AES> cmac;
	cmac.SetKey(kMac.data(), kMac.size());
	cmac.Update(toBeMaced.data(), toBeMaced.size());
	cmac.Final(result_.data());
	result_.resize(8);
	return result_;
}

std::string getCAR(
	const std::vector<unsigned char>& certificate)
{
	std::string car_;
	CVCertificate_t *CVCertificate = 0x00;

	if (ber_decode(0, &asn_DEF_CVCertificate, (void **)&CVCertificate,
				   certificate.data(), certificate.size()).code != RC_OK) {
#if defined(WIN32)
		OutputDebugStringA("getCAR failed ...\n");
#endif
		asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
		return car_;
	}

	for (size_t i = 0; i < CVCertificate->certBody.certAuthRef.size; i++)
		car_.push_back((char) CVCertificate->certBody.certAuthRef.buf[i]);

	asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
	return car_;
}

std::string getCHR(
	const std::vector<unsigned char>& certificate)
{
	std::string chr_;
	CVCertificate_t *CVCertificate = 0x00;

	if (ber_decode(0, &asn_DEF_CVCertificate, (void **)&CVCertificate,
				   certificate.data(), certificate.size()).code != RC_OK) {
#if defined(WIN32)
		OutputDebugStringA("getCHR failed ...\n");
#endif
		asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
		return chr_;
	}

	for (int i = 0; i < CVCertificate->certBody.certHolderRef.size; i++)
		chr_.push_back((char) CVCertificate->certBody.certHolderRef.buf[i]);

	asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
	return chr_;
}

ECARD_STATUS __STDCALL__ ePAGetRandom(
	size_t size, vector<unsigned char>& random_bytes)
{
	/* TODO only initialize rng once, then use the pseudo random bits */
	AutoSeededRandomPool rng;
	random_bytes.resize(size);
	rng.GenerateBlock(random_bytes.data(), random_bytes.size());
	return ECARD_SUCCESS;
}

std::vector<unsigned char> generate_PrK_IFD_DHx(void)
{
	std::vector<unsigned char> result;
	result.resize(32);
	AutoSeededRandomPool rng;
	rng.GenerateBlock(result.data(), result.size());
	return result;
}

ECP::Point calculate_PuK_IFD_DH1(
	const std::vector<unsigned char>& PrK_IFD_DH1)
{
	hexdump(DEBUG_LEVEL_CRYPTO, "###-> PrK.IFD.DHx in calculate_PuK_IFD_DHx", (void *) PrK_IFD_DH1.data(), PrK_IFD_DH1.size());
	Integer k(PrK_IFD_DH1.data(), PrK_IFD_DH1.size());
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
	result.x.Encode(x_.data(), result.x.ByteCount());
	result.y.Encode(y_.data(), result.y.ByteCount());

	if (x_.size() != 0x20)
		x_.insert(x_.begin(), 0x00);

	if (y_.size() != 0x20)
		y_.insert(y_.begin(), 0x00);

	hexdump(DEBUG_LEVEL_CRYPTO, "###-> PuK.IFD.DHx.x", (void *) x_.data(), x_.size());
	hexdump(DEBUG_LEVEL_CRYPTO, "###-> PuK.IFD.DHx.y", (void *) y_.data(), y_.size());
	return result;
}

std::vector<unsigned char> calculate_SMKeys( std::vector<unsigned char> input, bool generateMac)
{
  std::vector<unsigned char> result;

  unsigned char kenc[] = { 0x00, 0x00, 0x00, 0x01 };
  unsigned char kmac[] = { 0x00, 0x00, 0x00, 0x02 };

  SHA1 H;

  H.Update(input.data(), input.size());

  if (true == generateMac)
    H.Update(kmac, 4);
  else
    H.Update(kenc, 4);

  // Get the first 16 bytes from result
  result.resize(20);
  H.Final(result.data());
  result.resize(16);  

  return result;
}

std::vector<unsigned char> generate_compressed_PuK(
	const ECP::Point &PuK_IFD_DH2)
{
	std::vector<unsigned char> result_;
	std::vector<unsigned char> xDH2_;
	xDH2_.resize(PuK_IFD_DH2.x.ByteCount());
	std::vector<unsigned char> yDH2_;
	yDH2_.resize(PuK_IFD_DH2.y.ByteCount());
	PuK_IFD_DH2.x.Encode(xDH2_.data(), PuK_IFD_DH2.x.ByteCount());
	PuK_IFD_DH2.y.Encode(yDH2_.data(), PuK_IFD_DH2.y.ByteCount());
	size_t fillerX_ = 0;

	if (32 >= xDH2_.size())
		fillerX_ = 32 - xDH2_.size();

	size_t fillerY_ = 0;

	if (32 >= yDH2_.size())
		fillerY_ = 32 - yDH2_.size();

	std::vector<unsigned char> tempResult_;
	// Build 86||L||04||x(G')||y(G') (G' == temporary base point)
	tempResult_.push_back(0x86);
	tempResult_.push_back((unsigned char)(xDH2_.size() + fillerX_ + yDH2_.size() + fillerY_ + 1));
	tempResult_.push_back(0x04);

	for (size_t i = 0; i < fillerX_; i++)
		tempResult_.push_back(0x00);

	for (size_t i = 0; i < xDH2_.size(); i++)
		tempResult_.push_back(xDH2_[i]);

	for (size_t i = 0; i < fillerY_; i++)
		tempResult_.push_back(0x00);

	for (size_t i = 0; i < yDH2_.size(); i++)
		tempResult_.push_back(yDH2_[i]);

	result_.push_back(0x7f);
	result_.push_back(0x49);

	if (tempResult_.size() <= 0x80) {
		result_.push_back((unsigned char)(tempResult_.size() + 12));

	} else if (tempResult_.size() > 0x80 && tempResult_.size() <= 0xFF) {
		result_.push_back(0x81);
		result_.push_back((unsigned char)(tempResult_.size() + 12));

	} else if (tempResult_.size() > 0xFF && tempResult_.size() <= 0xFFFF) {
		result_.push_back(0x82);
		result_.push_back((tempResult_.size() + 12 & 0xFF00) >> 8);
		result_.push_back(tempResult_.size() + 12 & 0xFF);
	}

	// FIXME make the OID an input parameter to be usable for CA
	result_.push_back(0x06);
	result_.push_back(0x0a);
	result_.push_back(0x04);
	result_.push_back(0x00);
	result_.push_back(0x7f);
	result_.push_back(0x00);
	result_.push_back(0x07);
	result_.push_back(0x02);
	result_.push_back(0x02);
	result_.push_back(0x04);
	result_.push_back(0x02);
	result_.push_back(0x02);

	for (size_t i = 0; i < tempResult_.size(); i++)
		result_.push_back(tempResult_[i]);

	return result_;
}
