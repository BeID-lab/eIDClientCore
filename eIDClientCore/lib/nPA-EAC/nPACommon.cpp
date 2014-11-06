/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#include "eCardCore/ICard.h"
#include "nPACommon.h"
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
	p.x.Decode(DATA(xValue_), xValue_.size());
	p.y.Decode(DATA(yValue_), yValue_.size());
	p.identity = false;

	return p;
}

std::vector<unsigned char> point2vector(const ECP::Point &p, int curveLength)
{
	std::vector<unsigned char> v;

	std::vector<unsigned char> x_;
	x_.resize(p.x.ByteCount());
	p.x.Encode(DATA(x_), p.x.ByteCount());
	while (x_.size() < curveLength)
		x_.insert(x_.begin(), 0x00);

	std::vector<unsigned char> y_;
	y_.resize(p.y.ByteCount());
	p.y.Encode(DATA(y_), p.y.ByteCount());
	while (y_.size() < curveLength)
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
	cmac.SetKey(DATA(kMac), kMac.size());
	cmac.Update(DATA(toBeMaced), toBeMaced.size());
	cmac.Final(DATA(result_));
	result_.resize(8);
	return result_;
}

std::string getCAR(
	const std::vector<unsigned char>& certificate)
{
	std::string car_;
	CVCertificate_t *CVCertificate = 0x00;

	if (ber_decode(0, &asn_DEF_CVCertificate, (void **)&CVCertificate,
				   DATA(certificate), certificate.size()).code != RC_OK) {
		eCardCore_warn(DEBUG_LEVEL_CRYPTO, "getCAR failed ...");
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
				   DATA(certificate), certificate.size()).code != RC_OK) {
		eCardCore_warn(DEBUG_LEVEL_CRYPTO, "getCHR failed ...");
		asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
		return chr_;
	}

	for (int i = 0; i < CVCertificate->certBody.certHolderRef.size; i++)
		chr_.push_back((char) CVCertificate->certBody.certHolderRef.buf[i]);

	asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
	return chr_;
}

DH get_std_dp_0(void)
{
	Integer p("0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
			"9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
			"13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
			"98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
			"A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
			"DF1FB2BC2E4A4371");

	Integer g("0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
			"D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
			"160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
			"909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
			"D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
			"855E6EEB22B3B2E5");

	Integer q("0xF518AA8781A8DF278ABA4E7D64B7CB9D49462353");

	DH dh;
	dh.AccessGroupParameters().Initialize(p, q, g);

	return dh;
}

std::vector<unsigned char> generate_PrK_IFD_DHx (uint8_t standardizedDP){

	AutoSeededRandomPool rng;
	std::vector<unsigned char> result;
	
	switch(standardizedDP){

	case 0x08:
	case 0x09:
		result.resize(24);
		break;
	case 0x0A:
	case 0x0B:
		result.resize(28);
		break;
	case 0x0C:
	case 0x0D:
		result.resize(32);
		break;
	case 0x0E:
		result.resize(40);
		break;
	case 0x0F:
	case 0x10:
		result.resize(48);
		break;
	case 0x11:
	case 0x12:
		result.resize(64);
		break;
	default:
		eCardCore_warn(DEBUG_LEVEL_CRYPTO, "Domainparameters invalid");
		break;
	}

	rng.GenerateBlock(DATA(result), result.size());

	return result;
}

std::vector<unsigned char> calculate_PuK_IFD_DH1(uint8_t standardizedDP, const std::vector<unsigned char>& PrK_IFD_DH1){

	int curveLength;
	Integer a;
	Integer b;
	Integer Mod;
	Integer G_X;
	Integer G_Y;
	std::vector<unsigned char> result_buffer;
	
	switch(standardizedDP){

	case 0x09:
		curveLength = 0x18;
		a = Integer("6A91174076B1E0E19C39C031FE8685C1CAE040E5C69A28EFh");
		b = Integer("469A28EF7C28CCA3DC721D044F4496BCCA7EF4146FBF25C9h");
		Mod = Integer("C302F41D932A36CDA7A3463093D18DB78FCE476DE1A86297h");
		G_X = Integer("C0A0647EAAB6A48753B033C56CB0F0900A2F5C4853375FD6h");
		G_Y = Integer("14B690866ABD5BB88B5F4828C1490002E6773FA2FA299B8Fh");
		break;
	case 0x0D:
		curveLength = 0x20;
		a = Integer("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9h");
		b = Integer("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6h");
		Mod = Integer("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377h");
		G_X = Integer("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262h");
		G_Y = Integer("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997h");
		break;
	default:
		eCardCore_warn(DEBUG_LEVEL_CRYPTO, "Domainparameters not supported");
		break;
	}

	ECP ecp(Mod, a, b);
	ECP::Point G(G_X, G_Y);
	Integer k(DATA(PrK_IFD_DH1), PrK_IFD_DH1.size());
	ECP::Point result = ecp.Multiply(k, G);

	result_buffer = point2vector(result, curveLength);
	return result_buffer;
}

std::vector<unsigned char> calculate_SMKeys( std::vector<unsigned char> input, bool generateMac)
{
  std::vector<unsigned char> result;

  unsigned char kenc[] = { 0x00, 0x00, 0x00, 0x01 };
  unsigned char kmac[] = { 0x00, 0x00, 0x00, 0x02 };

  SHA1 H;

  H.Update(DATA(input), input.size());

  if (true == generateMac)
    H.Update(kmac, 4);
  else
    H.Update(kenc, 4);

  // Get the first 16 bytes from result
  result.resize(20);
  H.Final(DATA(result));
  result.resize(16);  

  return result;
}

std::vector<unsigned char> generate_compressed_PuK(
	const OBJECT_IDENTIFIER_t &OID_,
	const std::vector<unsigned char> &PuK_IFD_DH2)
{
	std::vector<unsigned char> do06, do86;
	unsigned int tag_pubkey = 0;

	OBJECT_IDENTIFIER_t pace_ecdh = makeOID(id_PACE_ECDH);
	OBJECT_IDENTIFIER_t pace_dh   = makeOID(id_PACE_DH);
	OBJECT_IDENTIFIER_t ca_ecdh = makeOID(id_CA_ECDH);
	OBJECT_IDENTIFIER_t ca_dh   = makeOID(id_CA_DH);
	if (pace_ecdh < OID_ || ca_ecdh < OID_) {
		tag_pubkey = 0x86;
	} else if (pace_dh < OID_ || ca_dh < OID_) {
		tag_pubkey = 0x84;
	}
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &pace_ecdh, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &pace_dh, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &ca_ecdh, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &ca_dh, 1);
	if (!tag_pubkey) {
		eCardCore_warn(DEBUG_LEVEL_CRYPTO, "Invalid pace OID.");
	}

	do06 = TLV_encode(0x06, std::vector<unsigned char> (OID_.buf, OID_.buf + OID_.size));
	do86 = TLV_encode(tag_pubkey, PuK_IFD_DH2);

	do06.insert(do06.end(), do86.begin(), do86.end());

	return TLV_encode(0x7F49, do06);
}

std::vector<unsigned char> TLV_encode(unsigned int tag, const std::vector<unsigned char> &data)
{
	/* XXX use asn1c instead of doing TLV by hand */
	std::vector<unsigned char> encoded, t, l;

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
	std::vector<unsigned char> rest;
	std::vector<unsigned char>::const_iterator i;

	if (tlv.empty() || !tag)
		goto err;

	i = tlv.begin();

	t = i[0];
	i++;
	if ((t & 0x1F) == 0x1F) {
		t <<= 8 | i[0];
		while ((i[0] & 0x80) == 0x80) {
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
	std::copy(i, i+l, data.begin());

	i += l;
	rest.resize(tlv.end() - i);
	std::copy(i, i+rest.size(), rest.begin());

	return rest;

err:
	if (tag)
		tag = 0x00;

	return rest;
}

std::vector<unsigned char> calculate_KIFD_ICC(
	const OBJECT_IDENTIFIER_t &OID_,
	const std::vector<unsigned char>& PrK_IFD_DH2,
	const std::vector<unsigned char>& PuK_ICC_DH2)
{
	OBJECT_IDENTIFIER_t PACE_ECDH_3DES_CBC_CBC	   = makeOID(id_PACE_ECDH_3DES_CBC_CBC);
	OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_128 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_128);
	OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_192 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_192);
	OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_256 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_256);

	OBJECT_IDENTIFIER_t PACE_DH_3DES_CBC_CBC	 = makeOID(id_PACE_DH_3DES_CBC_CBC);
	OBJECT_IDENTIFIER_t PACE_DH_AES_CBC_CMAC_128 = makeOID(id_PACE_DH_AES_CBC_CMAC_128);
	OBJECT_IDENTIFIER_t PACE_DH_AES_CBC_CMAC_192 = makeOID(id_PACE_DH_AES_CBC_CMAC_192);
	OBJECT_IDENTIFIER_t PACE_DH_AES_CBC_CMAC_256 = makeOID(id_PACE_DH_AES_CBC_CMAC_256);

	OBJECT_IDENTIFIER_t CA_ECDH_3DES_CBC_CBC	 = makeOID(id_CA_ECDH_3DES_CBC_CBC);
	OBJECT_IDENTIFIER_t CA_ECDH_AES_CBC_CMAC_128 = makeOID(id_CA_ECDH_AES_CBC_CMAC_128);
	OBJECT_IDENTIFIER_t CA_ECDH_AES_CBC_CMAC_192 = makeOID(id_CA_ECDH_AES_CBC_CMAC_192);
	OBJECT_IDENTIFIER_t CA_ECDH_AES_CBC_CMAC_256 = makeOID(id_CA_ECDH_AES_CBC_CMAC_256);

	OBJECT_IDENTIFIER_t CA_DH_3DES_CBC_CBC	   = makeOID(id_CA_DH_3DES_CBC_CBC);
	OBJECT_IDENTIFIER_t CA_DH_AES_CBC_CMAC_128 = makeOID(id_CA_DH_AES_CBC_CMAC_128);
	OBJECT_IDENTIFIER_t CA_DH_AES_CBC_CMAC_192 = makeOID(id_CA_DH_AES_CBC_CMAC_192);
	OBJECT_IDENTIFIER_t CA_DH_AES_CBC_CMAC_256 = makeOID(id_CA_DH_AES_CBC_CMAC_256);

	std::vector<unsigned char> result_buffer;

	if (       OID_ == PACE_ECDH_3DES_CBC_CBC
			|| OID_ == PACE_ECDH_AES_CBC_CMAC_128
			|| OID_ == PACE_ECDH_AES_CBC_CMAC_192
			|| OID_ == PACE_ECDH_AES_CBC_CMAC_256
			|| OID_ == CA_ECDH_3DES_CBC_CBC
			|| OID_ == CA_ECDH_AES_CBC_CMAC_128
			|| OID_ == CA_ECDH_AES_CBC_CMAC_192
			|| OID_ == CA_ECDH_AES_CBC_CMAC_256) {
		ECP::Point PuK_ICC_DH2_ = vector2point(PuK_ICC_DH2);
		Integer k(DATA(PrK_IFD_DH2), PrK_IFD_DH2.size());
		Integer a("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9h");
		Integer b("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6h");
		Integer Mod("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377h");
		ECP ecp(Mod, a, b);
		// Calculate: H = PrK.IFD.DH2 * PuK.ICC.DH2
		ECP::Point kifd_icc_ = ecp.Multiply(k, PuK_ICC_DH2_);

		result_buffer = get_x(point2vector(kifd_icc_, 0x20));
	} else if (OID_ == PACE_DH_3DES_CBC_CBC
			|| OID_ == PACE_DH_AES_CBC_CMAC_128
			|| OID_ == PACE_DH_AES_CBC_CMAC_192
			|| OID_ == PACE_DH_AES_CBC_CMAC_256
			|| OID_ == CA_DH_3DES_CBC_CBC
			|| OID_ == CA_DH_AES_CBC_CMAC_128
			|| OID_ == CA_DH_AES_CBC_CMAC_192
			|| OID_ == CA_DH_AES_CBC_CMAC_256) {
		DH dh = get_std_dp_0();

		if (PrK_IFD_DH2.size() != dh.PrivateKeyLength()
			   	|| PuK_ICC_DH2.size() != dh.PublicKeyLength()) {
			eCardCore_warn(DEBUG_LEVEL_CRYPTO, "No valid public or private key for mapping (%d/%d %d/%d).",
					PrK_IFD_DH2.size(), dh.PrivateKeyLength(), PuK_ICC_DH2.size(), dh.PublicKeyLength());
			return result_buffer;
		}

		result_buffer.resize(dh.AgreedValueLength());
		if (!dh.Agree(DATA(result_buffer), DATA(PrK_IFD_DH2), DATA(PuK_ICC_DH2))) {
			eCardCore_warn(DEBUG_LEVEL_CRYPTO, "Key agreement for shared secret failed.");
			return result_buffer;
		}
	}

	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_3DES_CBC_CBC, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_128, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_192, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_256, 1);

	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_DH_3DES_CBC_CBC, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_DH_AES_CBC_CMAC_128, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_DH_AES_CBC_CMAC_192, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_DH_AES_CBC_CMAC_256, 1);

	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &CA_ECDH_3DES_CBC_CBC, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &CA_ECDH_AES_CBC_CMAC_128, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &CA_ECDH_AES_CBC_CMAC_192, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &CA_ECDH_AES_CBC_CMAC_256, 1);

	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &CA_DH_3DES_CBC_CBC, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &CA_DH_AES_CBC_CMAC_128, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &CA_DH_AES_CBC_CMAC_192, 1);
	asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &CA_DH_AES_CBC_CMAC_256, 1);

	return result_buffer;
}

std::vector<unsigned char> calculate_ID_ICC(const std::vector<unsigned char>& PuK_ICC_DH2){
	
	std::vector<unsigned char> result_buffer;
	result_buffer = get_x(PuK_ICC_DH2);
	return result_buffer;
}

#define INT_LEN (10)
#define HEX_LEN (8)
#define BIN_LEN (32)
#define OCT_LEN (11)

char*  my_itoa ( int value, char * str, int base )
{
    int i,n =2,tmp;
    char buf[BIN_LEN+1];


    switch(base)
    {
        case 16:
            for(i = 0;i<HEX_LEN;++i)
            {
                if(value/base>0)
                {
                    n++;
                }
            }
            snprintf(str, n, "%x" ,value);
            break;
        case 10:
            for(i = 0;i<INT_LEN;++i)
            {
                if(value/base>0)
                {
                    n++;
                }
            }
            snprintf(str, n, "%d" ,value);
            break;
        case 8:
            for(i = 0;i<OCT_LEN;++i)
            {
                if(value/base>0)
                {
                    n++;
                }
            }
            snprintf(str, n, "%o" ,value);
            break;
        case 2:
            for(i = 0,tmp = value;i<BIN_LEN;++i)
            {
                if(tmp/base>0)
                {
                    n++;
                }
                tmp/=base;
            }
            for(i = 1 ,tmp = value; i<n;++i)
            {
                if(tmp%2 != 0)
                {
                    buf[n-i-1] ='1';
                }
                else
                {
                    buf[n-i-1] ='0';
                }
                tmp/=base;
            }
            buf[n-1] = '\0';
            strcpy(str,buf);
            break;
        default:
            return NULL;
    }
    return str;
}
