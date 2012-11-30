/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#include "eCardCore/eCardTypes.h"
#include "eCardCore/eCardStatus.h"
#include "eCardCore/ICard.h"
#include "nPACommon.h"
#include "nPAAPI.h"
#include "eidasn1/eIDHelper.h"
#include "eidasn1/eIDOID.h"

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

std::vector<unsigned char> get_x(const std::vector<unsigned char> &v)
{
	std::vector<unsigned char> xValue_;

	if (v.size() < 1 || v[0] != 0x04)
		return xValue_;

	for (size_t i = 1; i < 1 + (v.size()-1)/2; i++)
		xValue_.push_back(v[i]);

	return xValue_;
}

std::vector<unsigned char> get_y(const std::vector<unsigned char> &v)
{
	std::vector<unsigned char> yValue_;

	if (v.size() < 1 || v[0] != 0x04)
		return yValue_;

	for (size_t i = 1 + (v.size()-1)/2; i < v.size(); i++)
		yValue_.push_back(v[i]);

	return yValue_;
}

ECP::Point vector2point(const std::vector<unsigned char> &v)
{
	ECP::Point p;

	if (v.size() < 1 || v[0] != 0x04)
		return p;

	std::vector<unsigned char> xValue_ = get_x(v);
	std::vector<unsigned char> yValue_ = get_y(v);

	// Encode the point
	p.x.Decode(xValue_.data(), xValue_.size());
	p.y.Decode(yValue_.data(), yValue_.size());
	p.identity = false;

	return p;
}

std::vector<unsigned char> point2vector(const ECP::Point &p)
{
	std::vector<unsigned char> v;

	std::vector<unsigned char> x_;
	x_.resize(p.x.ByteCount());
	p.x.Encode(x_.data(), p.x.ByteCount());
	while (x_.size() < 0x20)
		x_.insert(x_.begin(), 0x00);

	std::vector<unsigned char> y_;
	y_.resize(p.y.ByteCount());
	p.y.Encode(y_.data(), p.y.ByteCount());
	while (y_.size() < 0x20)
		y_.insert(y_.begin(), 0x00);

	v.push_back(0x04);
	v.insert(v.end(), x_.begin(), x_.end());
	v.insert(v.end(), y_.begin(), y_.end());

	return v;
}

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

std::vector<unsigned char> generate_PrK_IFD_DHx(
	const OBJECT_IDENTIFIER_t &OID_)
{
	OBJECT_IDENTIFIER_t PACE_ECDH_3DES_CBC_CBC	 = makeOID(id_PACE_ECDH_3DES_CBC_CBC);
	OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_128 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_128);
	OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_192 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_192);
	OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_256 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_256);

	std::vector<unsigned char> result;
	AutoSeededRandomPool rng;

	if (OID_ == PACE_ECDH_3DES_CBC_CBC ||
		OID_ == PACE_ECDH_AES_CBC_CMAC_128 ||
		OID_ == PACE_ECDH_AES_CBC_CMAC_192 ||
		OID_ ==  PACE_ECDH_AES_CBC_CMAC_256) {
		result.resize(32);
		rng.GenerateBlock(result.data(), result.size());
	}

	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_3DES_CBC_CBC, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_128, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_192, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_256, 1);

	return result;
}

std::vector<unsigned char> calculate_PuK_IFD_DH1(
	const OBJECT_IDENTIFIER_t &OID_,
	const std::vector<unsigned char>& PrK_IFD_DH1)
{
	hexdump(DEBUG_LEVEL_CRYPTO, "###-> PrK.IFD.DHx in calculate_PuK_IFD_DHx", (void *) PrK_IFD_DH1.data(), PrK_IFD_DH1.size());

	OBJECT_IDENTIFIER_t PACE_ECDH_3DES_CBC_CBC	 = makeOID(id_PACE_ECDH_3DES_CBC_CBC);
	OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_128 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_128);
	OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_192 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_192);
	OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_256 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_256);

	std::vector<unsigned char> result_buffer;

	if (OID_ == PACE_ECDH_3DES_CBC_CBC ||
		OID_ == PACE_ECDH_AES_CBC_CMAC_128 ||
		OID_ == PACE_ECDH_AES_CBC_CMAC_192 ||
		OID_ ==  PACE_ECDH_AES_CBC_CMAC_256) {
		Integer k(PrK_IFD_DH1.data(), PrK_IFD_DH1.size());
		Integer a("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9h");
		Integer b("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6h");
		Integer Mod("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377h");
		ECP ecp(Mod, a, b);
		Integer X("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262h");
		Integer Y("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997h");
		ECP::Point G(X, Y);
		ECP::Point result = ecp.Multiply(k, G);

		result_buffer = point2vector(result);
	}

	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_3DES_CBC_CBC, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_128, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_192, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_256, 1);

	return result_buffer;
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
	const OBJECT_IDENTIFIER_t &OID_,
	const std::vector<unsigned char> &PuK_IFD_DH2)
{
	std::vector<unsigned char> do06, do86;

	do06 = TLV_encode(0x06, vector<unsigned char> (OID_.buf, OID_.buf + OID_.size));
	do86 = TLV_encode(0x86, PuK_IFD_DH2);

	do06.insert(do06.end(), do86.begin(), do86.end());

	return TLV_encode(0x7F49, do06);
}

std::vector<unsigned char> TLV_encode(unsigned int tag, const std::vector<unsigned char> &data)
{
	/* XXX use asn1c instead of doing TLV by hand */
	vector<unsigned char> encoded, t, l;

	if (tag == 0x00 || tag == 0xFF)
		eCardCore_warn(DEBUG_LEVEL_CRYPTO, "Invalid tag.");

	while (tag > 0) {
		t.insert(t.begin(), (unsigned char) (tag & 0xff));
		tag >>= 8;
	}

	if (data.size() < 0x7F) {
		l.push_back((unsigned char) data.size());
	} else {
		size_t length = data.size();
		while (length > 0) {
			l.insert(l.begin(), (unsigned char) (length & 0xff));
			length >>= 8;
		}
		if (l.size() >= 0x7F)
			eCardCore_warn(DEBUG_LEVEL_CRYPTO, "Input data too long.");
		l.insert(l.begin(), (unsigned char) (0x80|l.size()));
	}

	encoded.insert(encoded.end(), t.begin(), t.end());
	encoded.insert(encoded.end(), l.begin(), l.end());
	encoded.insert(encoded.end(), data.begin(), data.end());

	return encoded;
}

std::vector<unsigned char> TLV_decode(const std::vector<unsigned char> &tlv,
	   	unsigned int *tag, std::vector<unsigned char> &data)
{
	/* XXX use asn1c instead of doing TLV by hand */
	size_t l;
	unsigned int t;
	vector<unsigned char> rest;
	vector<unsigned char>::const_iterator i;

	if (tlv.empty() || !tag)
		goto err;

	i = tlv.begin();

	t = i[0];
	i++;
	if ((t & 0x1F) == 0x1F) {
		t <<= 8 | i[0];
		while (i[0] & 0x80 == 0x80) {
			i++;
			t <<= 8 | i[0];
		}
		i++;
	}

	l = i[0];
	i++;
	if (l >= 0x80) {
		unsigned int l_ = 0;
		l &= 0x7F;
		while (l > 0) {
			l_ = l_*256 + i[0];
			i++;
			l--;
		}
		l = l_;
	}

	if (i+l > tlv.end())
		goto err;

	*tag = t;

	data.resize(l);
	copy(i, i+l, data.begin());

	i += l;
	rest.resize(tlv.end() - i);
	copy(i, i+rest.size(), rest.begin());

	return rest;

err:
	if (tag)
		tag = 0x00;

	return rest;
}
