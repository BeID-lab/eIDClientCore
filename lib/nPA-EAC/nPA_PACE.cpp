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
/**
 */
static std::vector<unsigned char> generate_PrK_IFD_DHx(
  const AlgorithmIdentifier* PACEDomainParameterInfo_);

/*
 * Calculate the SK.PACE.xyz
 */
std::vector<unsigned char> generateSKPACE_FromPassword(
  const std::vector<unsigned char>& password,
  PaceInput::PinID keyReference)
{
  std::vector<unsigned char> result;
  unsigned char c_mrz[] = { 0x00, 0x00, 0x00, 0x03 };	// always 0x03 acc. EAC 2.05 page 54
  unsigned char c_can[] = { 0x00, 0x00, 0x00, 0x03 };
  unsigned char c_pin[] = { 0x00, 0x00, 0x00, 0x03 };
  unsigned char c_puk[] = { 0x00, 0x00, 0x00, 0x03 };

  SHA1 paceH;

  // Hash the full password
  paceH.Update(&password[0], password.size());

  switch (keyReference)
  {
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
  }

  // Get the first 16 bytes from result
  result.resize(20);
  paceH.Final(&result[0]);
  result.resize(16);  

  hexdump(DEBUG_LEVEL_CRYPTO, "###-> INPUT PIN", &password[0], password.size());
  hexdump(DEBUG_LEVEL_CRYPTO, "###-> SKPACE", &result[0], result.size());

  return result;
}

/*
* Decrypt the RND.ICC response according to EAC 2.01 Section 4.2.1 
* using AES algorithm.
*
* @TODO: Think about separation of this function to common code module.
* @TODO: Implement this function.
*/
std::vector<unsigned char> decryptRNDICC_AES(
  const vector<unsigned char>&  encryptedRNDICC,
  const vector<unsigned char>& skPACE)
{
  hexdump(DEBUG_LEVEL_CRYPTO, "###-> SKPACE in decryptRNDICC_AES", (void*) &skPACE[0], skPACE.size());
  hexdump(DEBUG_LEVEL_CRYPTO, "###-> encryptedRNDICC", (void*) &encryptedRNDICC[0], encryptedRNDICC.size());

  unsigned char iv_[] = { 
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

  std::vector<unsigned char> result_;

  CBC_Mode<AES>::Decryption AESCBC_decryption;
  if (false == AESCBC_decryption.IsValidKeyLength(skPACE.size()))
    return result_;

  result_.resize(encryptedRNDICC.size());
  AESCBC_decryption.SetKeyWithIV(&skPACE[0], skPACE.size(), iv_);
  AESCBC_decryption.ProcessData(&result_[0], &encryptedRNDICC[0], encryptedRNDICC.size());

  hexdump(DEBUG_LEVEL_CRYPTO, "###-> RNDICC", &result_[0], result_.size());

  return result_;
}


ECP::Point calculate_PuK_IFD_DH1(
  const std::vector<unsigned char>& PrK_IFD_DH1,
  const AlgorithmIdentifier* const PACEDomainParameterInfo)
{
    hexdump(DEBUG_LEVEL_CRYPTO, "###-> PrK.IFD.DHx in calculate_PuK_IFD_DHx", (void*) &PrK_IFD_DH1[0], PrK_IFD_DH1.size());

    Integer k(&PrK_IFD_DH1[0], PrK_IFD_DH1.size());

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

/*
* 1. H = PrK.IFD.DH1 * PuK.ICC.DH1
*/
ECP::Point calculate_PuK_IFD_DH2(
  const std::vector<unsigned char>& PrK_IFD_DH1,
  const std::vector<unsigned char>& PrK_IFD_DH2,
  const ECP::Point& PuK_ICC_DH1,
  const std::vector<unsigned char>& rndICC_,
  const AlgorithmIdentifier* const PACEDomainParameterInfo)
{
    hexdump(DEBUG_LEVEL_CRYPTO, "###-> PrK.IFD.DH1 in calculate_PuK_IFD_DH2", (void*) &PrK_IFD_DH1[0], PrK_IFD_DH1.size());
    hexdump(DEBUG_LEVEL_CRYPTO, "###-> rndICC in calculate_PuK_IFD_DH2", (void*) &rndICC_[0], rndICC_.size());

    Integer k(&PrK_IFD_DH1[0], PrK_IFD_DH1.size());
    Integer rndICC(&rndICC_[0], rndICC_.size());

    Integer a("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9h");
    Integer b("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6h");
  
    Integer Mod("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377h");
    ECP ecp(Mod, a, b);

    // Calculate: H = PrK.IFD.DH1 * PuK.ICC.DH1
    ECP::Point H_ = ecp.Multiply(k, PuK_ICC_DH1);

    Integer X("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262h");
    Integer Y("547EF835C3DAC4FD97F8461A14611DC9C27745132DED8E545C1D54C72F046997h");
    ECP::Point G(X, Y);  

    ECP::Point G_temp = ecp.ScalarMultiply(G, rndICC);
    ECP::Point G1 = ecp.Add(G_temp, H_);

    hexdump(DEBUG_LEVEL_CRYPTO, "###-> PrK.IFD.DH2 in calculate_PuK_IFD_DH2", (void*) &PrK_IFD_DH2[0], PrK_IFD_DH2.size());
    Integer k1(&PrK_IFD_DH2[0], PrK_IFD_DH2.size());

    ECP::Point result = ecp.Multiply(k1, G1);

    std::vector<unsigned char> x_;
    x_.resize(result.x.ByteCount());
    std::vector<unsigned char> y_;
    y_.resize(result.y.ByteCount());

    result.x.Encode(&x_[0], result.x.ByteCount());
    result.y.Encode(&y_[0], result.y.ByteCount());
 
    hexdump(DEBUG_LEVEL_CRYPTO, "###-> PuK.IFD.DH2.x", (void*) &x_[0], x_.size());
    hexdump(DEBUG_LEVEL_CRYPTO, "###-> PuK.IFD.DH2.y", (void*) &y_[0], y_.size());
  
    return result;
}

/**
 *
 */
ECP::Point calculate_KIFD_ICC( 
  const std::vector<unsigned char>& PrK_IFD_DH2,
  ECP::Point PuK_ICC_DH2,
  const AlgorithmIdentifier* PACEDomainParameterInfo)
{
    Integer k(&PrK_IFD_DH2[0], PrK_IFD_DH2.size());
    Integer a("7D5A0975FC2C3057EEF67530417AFFE7FB8055C126DC5C6CE94A4B44F330B5D9h");
    Integer b("26DC5C6CE94A4B44F330B5D9BBD77CBF958416295CF7E1CE6BCCDC18FF8C07B6h");
  
    Integer Mod("A9FB57DBA1EEA9BC3E660A909D838D726E3BF623D52620282013481D1F6E5377h");
    ECP ecp(Mod, a, b);

    // Calculate: H = PrK.IFD.DH2 * PuK.ICC.DH2
    ECP::Point kifd_icc_ = ecp.Multiply(k, PuK_ICC_DH2);

    std::vector<unsigned char> x_;
    x_.resize(kifd_icc_.x.ByteCount());
    std::vector<unsigned char> y_;
    y_.resize(kifd_icc_.y.ByteCount());

    kifd_icc_.x.Encode(&x_[0], kifd_icc_.x.ByteCount());
    kifd_icc_.y.Encode(&y_[0], kifd_icc_.y.ByteCount());

    hexdump(DEBUG_LEVEL_CRYPTO, "###-> KIFD/ICC.x", (void*) &x_[0], x_.size());
    hexdump(DEBUG_LEVEL_CRYPTO, "###-> KIFD/ICC.y", (void*) &y_[0], y_.size());
  
    return kifd_icc_;
}

/*
 *
 */
std::vector<unsigned char> calculate_SMKeys(
  ECP::Point KIFD_ICC,
  bool generateMac)
{
  std::vector<unsigned char> result;

  std::vector<unsigned char> x_;
  std::vector<unsigned char> tmpx_;

  tmpx_.resize(KIFD_ICC.x.ByteCount());
  KIFD_ICC.x.Encode(&tmpx_[0], KIFD_ICC.x.ByteCount());

  int filler = 32 - tmpx_.size();

  for (int i = 0; i < filler; i++)
    x_.push_back(0x00);
  for (size_t i = 0; i < tmpx_.size(); i++)
    x_.push_back(tmpx_[i]);

  unsigned char kenc[] = { 0x00, 0x00, 0x00, 0x01 };
  unsigned char kmac[] = { 0x00, 0x00, 0x00, 0x02 };

  SHA1 H;

  // Hash the full password
  H.Update(&x_[0], x_.size());

  if (true == generateMac)
    H.Update(kmac, 4);
  else
    H.Update(kenc, 4);

  // Get the first 16 bytes from result
  result.resize(20);
  H.Final(&result[0]);
  result.resize(16);  

  hexdump(DEBUG_LEVEL_CRYPTO, generateMac ? "###-> KMac" : "###-> KEnc", (void*) &result[0], result.size());

  return result;
}

/*
 *
 */
std::vector<unsigned char> generate_PuK_ICC_DH2(
  const ECP::Point& PuK_ICC_DH2,
  const std::vector<unsigned char>& rndICC_,
  const AlgorithmIdentifier* PACEDomainParameterInfo)
{
  std::vector<unsigned char> result_;

    std::vector<unsigned char> xDH2_;
    xDH2_.resize(PuK_ICC_DH2.x.ByteCount());
    std::vector<unsigned char> yDH2_;
    yDH2_.resize(PuK_ICC_DH2.y.ByteCount());

    PuK_ICC_DH2.x.Encode(&xDH2_[0], PuK_ICC_DH2.x.ByteCount());
    PuK_ICC_DH2.y.Encode(&yDH2_[0], PuK_ICC_DH2.y.ByteCount());

    std::vector<unsigned char> tempResult_;

    int fillerX_ = 32 - xDH2_.size();
    int fillerY_ = 32 - yDH2_.size();
    // Build 86||L||04||x(G')||y(G') (G' == temporary base point)
    tempResult_.push_back(0x86); tempResult_.push_back(xDH2_.size() + fillerX_ + yDH2_.size() + fillerY_ + 1);
    tempResult_.push_back(0x04);

    for (int i = 0; i < fillerX_; i++)
      tempResult_.push_back(0x00);
    for(size_t i = 0; i < xDH2_.size(); i++)
	    tempResult_.push_back(xDH2_[i]);

    for (int i = 0; i < fillerY_; i++)
      tempResult_.push_back(0x00);
    for(size_t i = 0; i < yDH2_.size(); i++)
	    tempResult_.push_back(yDH2_[i]);

    result_.push_back(0x7f); result_.push_back(0x49);

    if (tempResult_.size() <= 0x80)
    { 
      result_.push_back(tempResult_.size() + 12); 
    } else if (tempResult_.size() > 0x80 && tempResult_.size() <= 0xFF)
    {
      result_.push_back(0x81);
      result_.push_back(tempResult_.size() + 12);
    } else if (tempResult_.size() > 0xFF && tempResult_.size() <= 0xFFFF)
    {
      result_.push_back(0x82);
      result_.push_back((tempResult_.size() + 12 & 0xFF00) >> 8);
      result_.push_back(tempResult_.size() + 12 & 0xFF);
    }

    result_.push_back(0x06); result_.push_back(0x0a); result_.push_back(0x04); result_.push_back(0x00);
    result_.push_back(0x7f); result_.push_back(0x00); result_.push_back(0x07); result_.push_back(0x02);
    result_.push_back(0x02); result_.push_back(0x04); result_.push_back(0x02); result_.push_back(0x02);

    for (size_t i = 0; i < tempResult_.size(); i++)
	    result_.push_back(tempResult_[i]);

	return result_;
}

/*
 *
 */
std::vector<unsigned char> generate_PuK_IFD_DH2(
  const ECP::Point& PuK_IFD_DH2,
  const std::vector<unsigned char>& rndICC_,
  const AlgorithmIdentifier* PACEDomainParameterInfo)
{
  std::vector<unsigned char> result_;

    std::vector<unsigned char> xDH2_;
    xDH2_.resize(PuK_IFD_DH2.x.ByteCount());
    std::vector<unsigned char> yDH2_;
    yDH2_.resize(PuK_IFD_DH2.y.ByteCount());

    PuK_IFD_DH2.x.Encode(&xDH2_[0], PuK_IFD_DH2.x.ByteCount());
    PuK_IFD_DH2.y.Encode(&yDH2_[0], PuK_IFD_DH2.y.ByteCount());

    int fillerX_ = 32 - xDH2_.size();
    int fillerY_ = 32 - yDH2_.size();

    std::vector<unsigned char> tempResult_;

    // Build 86||L||04||x(G')||y(G') (G' == temporary base point)
    tempResult_.push_back(0x86); tempResult_.push_back(xDH2_.size() + fillerX_ + yDH2_.size() + fillerY_ + 1);
    tempResult_.push_back(0x04);

    for (int i = 0; i < fillerX_; i++)
      tempResult_.push_back(0x00);

    for(size_t i = 0; i < xDH2_.size(); i++)
	    tempResult_.push_back(xDH2_[i]);

    for (int i = 0; i < fillerY_; i++)
      tempResult_.push_back(0x00);

    for(size_t i = 0; i < yDH2_.size(); i++)
	    tempResult_.push_back(yDH2_[i]);

    result_.push_back(0x7f); result_.push_back(0x49);

    if (tempResult_.size() <= 0x80)
    { 
      result_.push_back(tempResult_.size() + 12); 
    } else if (tempResult_.size() > 0x80 && tempResult_.size() <= 0xFF)
    {
      result_.push_back(0x81);
      result_.push_back(tempResult_.size() + 12);
    } else if (tempResult_.size() > 0xFF && tempResult_.size() <= 0xFFFF)
    {
      result_.push_back(0x82);
      result_.push_back((tempResult_.size() + 12 & 0xFF00) >> 8);
      result_.push_back(tempResult_.size() + 12 & 0xFF);
    }

    result_.push_back(0x06); result_.push_back(0x0a); result_.push_back(0x04); result_.push_back(0x00);
    result_.push_back(0x7f); result_.push_back(0x00); result_.push_back(0x07); result_.push_back(0x02);
    result_.push_back(0x02); result_.push_back(0x04); result_.push_back(0x02); result_.push_back(0x02);

    for (size_t i = 0; i < tempResult_.size(); i++)
	    result_.push_back(tempResult_[i]);

  return result_;
}

/* 
 * This function performs step B of the PACE protocol
 */
ECARD_STATUS __STDCALL__ perform_PACE_Step_B(
  const OBJECT_IDENTIFIER_t& PACE_OID_, 
  PaceInput::PinID keyReference, 
  const std::vector<unsigned char>& chat, 
  ICard& card_)
{
	vector<unsigned char> data;
	MSE mse = MSE(MSE::P1_SET|MSE::P1_COMPUTE|MSE::P1_VERIFY, MSE::P2_AT);

	hexdump(DEBUG_LEVEL_CRYPTO, "###-> PACE OID", PACE_OID_.buf, PACE_OID_.size);
	hexdump(DEBUG_LEVEL_CRYPTO, "###-> CHAT", &chat[0], chat.size());
	hexdump(DEBUG_LEVEL_CRYPTO, "###-> KEY REF", &keyReference, 1);

	// Append OID
	data.push_back(0x80);
	data.push_back(PACE_OID_.size);
	data.insert(data.end(), PACE_OID_.buf, PACE_OID_.buf + PACE_OID_.size);

	// Append Key reference
	data.push_back(0x83);
	data.push_back(0x01);
	if (PaceInput::can == keyReference) data.push_back(0x02);
	if (PaceInput::pin == keyReference) data.push_back(0x03);
	if (PaceInput::puk == keyReference) data.push_back(0x04);
	// @TODO: MRZ not handled!! Different preparation function if needed.

	// Append CHAT
	data.insert(data.end(), &chat[0], &chat[0] + chat.size());

	mse.setData(data);

	// Do the dirty work.
	RAPDU rapdu = card_.sendAPDU(mse);

	if (rapdu.getSW() != RAPDU::ISO_SW_NORMAL)
	{
		if ((rapdu.getSW() >> 4) == 0x63C) {
			eCardCore_warn(DEBUG_LEVEL_CRYPTO, "%u tries left.", rapdu.getSW() & 0xf);

			return ECARD_SUCCESS;
		}

		return ECARD_PACE_STEP_B_FAILED;
	}

	return ECARD_SUCCESS;
}

ECARD_STATUS __STDCALL__ perform_PACE_Step_C( 
  const OBJECT_IDENTIFIER_t& PACE_OID_,
  const std::vector<unsigned char>& password,
  PaceInput::PinID keyReference,
  ICard& card_,
  std::vector<unsigned char>& rndICC)
{
	GeneralAuthenticate authenticate(0x00, 0x00);
	authenticate.setCLA(CAPDU::CLA_CHAINING);
	authenticate.setNe(CAPDU::DATA_SHORT_MAX);

	vector<unsigned char> data;
	data.push_back(0x7C);
	data.push_back(0x00);

	authenticate.setData(data);

	eCardCore_info(DEBUG_LEVEL_CRYPTO, "Send GENERAL AUTHENTICATE to get RND.ICC");
	RAPDU rapdu = card_.sendAPDU(authenticate);
	if (!rapdu.isOK())
		return ECARD_PACE_STEP_C_FAILED;

	// Now compute the SK.PACE.xyz key from the given password.
	// SK.PACE is used to decrypt the RND.ICC value from the 
	std::vector<unsigned char> skPACE_ = generateSKPACE_FromPassword(password, keyReference);
 
	OBJECT_IDENTIFIER_t PACE_ECDH_3DES_CBC_CBC     = makeOID(id_PACE_ECDH_3DES_CBC_CBC);
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
  ECP::Point PuK_IFD_DH1_,
  ICard& card_,
  ECP::Point& Puk_ICC_DH1_)
{
  GeneralAuthenticate authenticate(0x00, 0x00);
  authenticate.setCLA(CAPDU::CLA_CHAINING);
  authenticate.setNe(CAPDU::DATA_SHORT_MAX);

  std::vector<unsigned char> x_;
  x_.resize(PuK_IFD_DH1_.x.ByteCount());
  std::vector<unsigned char> y_;
  y_.resize(PuK_IFD_DH1_.y.ByteCount());

  // assert(0x20 == PuK_IFD_DH1_.x.ByteCount());
  // assert(0x20 == PuK_IFD_DH1_.y.ByteCount());

  PuK_IFD_DH1_.x.Encode(&x_[0], PuK_IFD_DH1_.x.ByteCount());
  PuK_IFD_DH1_.y.Encode(&y_[0], PuK_IFD_DH1_.y.ByteCount());

  int fillerX_ = 32 - x_.size();
  int fillerY_ = 32 - y_.size();

  // Build up command data field
  std::vector<unsigned char> dataPart_;
  dataPart_.push_back(0x7C);
  // Set the size
  dataPart_.push_back(0x03 + x_.size() + fillerX_ + y_.size() + fillerY_);
  dataPart_.push_back(0x81);
  // Set the size
  dataPart_.push_back(0x01 + x_.size() + fillerX_ + y_.size() + fillerY_);
  dataPart_.push_back(0x04);
  // Append X
  for (int i = 0; i < fillerX_; i++)
    dataPart_.push_back(0x00);
  for (size_t i = 0; i < x_.size(); i++)
    dataPart_.push_back(x_[i]);
  // Append Y 
  for (int i = 0; i < fillerY_; i++)
    dataPart_.push_back(0x00);
  for (size_t i = 0; i < y_.size(); i++)
    dataPart_.push_back(y_[i]);

  authenticate.setData(dataPart_);

  eCardCore_info(DEBUG_LEVEL_CRYPTO, "Send GENERAL AUTHENTICATE to Map Nonce");
  RAPDU rapdu = card_.sendAPDU(authenticate);
  if (!rapdu.isOK())
    return ECARD_PACE_STEP_D_FAILED;

  std::vector<unsigned char> point_;
#define DATA_INDEX_RAW_POINT 5
  for (size_t i = DATA_INDEX_RAW_POINT; i < rapdu.getData().size(); i++)
    point_.push_back(rapdu.getData()[i]);

  std::vector<unsigned char> xValue_;
  for (size_t i = 0; i <= point_.size() / 2 - 1; i++)
    xValue_.push_back(point_[i]); 

  std::vector<unsigned char> yValue_;
  for (size_t i = point_.size() / 2; i <= point_.size() - 1; i++)
    yValue_.push_back(point_[i]); 

  // Encode the point
  Puk_ICC_DH1_.x.Decode(&xValue_[0], xValue_.size());
  Puk_ICC_DH1_.y.Decode(&yValue_[0], yValue_.size());
  Puk_ICC_DH1_.identity = false;

  hexdump(DEBUG_LEVEL_CRYPTO, "PuK.ICC.DH1.x", (void*) &xValue_[0], xValue_.size());
  hexdump(DEBUG_LEVEL_CRYPTO, "PuK.ICC.DH1.y", (void*) &yValue_[0], yValue_.size());

  return ECARD_SUCCESS;
}

/* 
* This function performs step E of the PACE protocol 
*/
ECARD_STATUS __STDCALL__ perform_PACE_Step_E( 
  ECP::Point PuK_IFD_DH2_,
  ICard& card_,
  ECP::Point& Puk_ICC_DH2_)
{
  GeneralAuthenticate authenticate(0x00, 0x00);
  authenticate.setCLA(CAPDU::CLA_CHAINING);
  authenticate.setNe(CAPDU::DATA_SHORT_MAX);

  std::vector<unsigned char> x_;
  x_.resize(PuK_IFD_DH2_.x.ByteCount());
  std::vector<unsigned char> y_;
  y_.resize(PuK_IFD_DH2_.y.ByteCount());

  PuK_IFD_DH2_.x.Encode(&x_[0], PuK_IFD_DH2_.x.ByteCount());
  PuK_IFD_DH2_.y.Encode(&y_[0], PuK_IFD_DH2_.y.ByteCount());

  int fillerX_ = 32 - x_.size();
  int fillerY_ = 32 - y_.size();

  // Build up command data field
  std::vector<unsigned char> dataPart_;
  dataPart_.push_back(0x7C);
  // Set the size
  dataPart_.push_back(0x03 + x_.size() + fillerX_ + y_.size() + fillerY_);
  dataPart_.push_back(0x83);
  // Set the size
  dataPart_.push_back(0x01 + x_.size() + fillerX_ + y_.size() + fillerY_);
  dataPart_.push_back(0x04);
  // Append X
  for (int i = 0; i < fillerX_; i++)
    dataPart_.push_back(0x00);
  for (size_t i = 0; i < x_.size(); i++)
    dataPart_.push_back(x_[i]);
  // Append Y 
  for (int i = 0; i < fillerY_; i++)
    dataPart_.push_back(0x00);
  for (size_t i = 0; i < y_.size(); i++)
    dataPart_.push_back(y_[i]);

  // Append command data field
  authenticate.setData(dataPart_);

  eCardCore_info(DEBUG_LEVEL_CRYPTO, "Send GENERAL AUTHENTICATE to Perform Key Agreement");

  RAPDU rapdu = card_.sendAPDU(authenticate);
  if (!rapdu.isOK())
    return ECARD_PACE_STEP_E_FAILED;

  std::vector<unsigned char> data_ = rapdu.getData();

  std::vector<unsigned char> point_;
  for (size_t i = 5; i < data_.size(); i++)
    point_.push_back(data_[i]);

  std::vector<unsigned char> xValue_;
  for (size_t i = 0; i <= point_.size() / 2 - 1; i++)
    xValue_.push_back(point_[i]); 

  std::vector<unsigned char> yValue_;
  for (size_t i = point_.size() / 2; i <= point_.size() - 1; i++)
    yValue_.push_back(point_[i]); 

  // Encode the point
  Puk_ICC_DH2_.x.Decode(&xValue_[0], xValue_.size());
  Puk_ICC_DH2_.y.Decode(&yValue_[0], yValue_.size());
  Puk_ICC_DH2_.identity = false;

  hexdump(DEBUG_LEVEL_CRYPTO, "PuK.ICC.DH2.x", (void*) &xValue_[0], xValue_.size());
  hexdump(DEBUG_LEVEL_CRYPTO, "PuK.ICC.DH2.y", (void*) &yValue_[0], yValue_.size());

  return ECARD_SUCCESS;
}

ECARD_STATUS __STDCALL__ perform_PACE_Step_F( 
  const std::vector<unsigned char>& macedPuk_ICC_DH2,
  const std::vector<unsigned char>& macedPuk_IFD_DH2,
  ICard& card_,
  std::string& car_cvca)
{
  GeneralAuthenticate authenticate(0x00, 0x00);
  authenticate.setNe(CAPDU::DATA_SHORT_MAX);

  // Build up command data field
  std::vector<unsigned char> dataPart_;
  dataPart_.push_back(0x7C);
  // Set the size
  dataPart_.push_back(0x02 + macedPuk_ICC_DH2.size());
  dataPart_.push_back(0x85);
  // Set the size
  dataPart_.push_back(macedPuk_ICC_DH2.size());
  // Append maced Data
  for (size_t i = 0; i < macedPuk_ICC_DH2.size(); i++)
    dataPart_.push_back(macedPuk_ICC_DH2[i]);

  authenticate.setData(dataPart_);

  eCardCore_info(DEBUG_LEVEL_CRYPTO, "Send GENERAL AUTHENTICATE to perform explicit authentication");

  RAPDU rapdu = card_.sendAPDU(authenticate);
  if (!rapdu.isOK())
    return ECARD_PACE_STEP_F_FAILED;

  std::vector<unsigned char> data_ = rapdu.getData();

  hexdump(DEBUG_LEVEL_CRYPTO, "###-> Last PACE result", &data_[0], data_.size());

  for (int i = 4; i < 12; i++)
  {
    if (macedPuk_IFD_DH2[i-4] != data_[i])
      return ECARD_PACE_STEP_F_VERIFICATION_FAILED;
  }

  // relevant for changing PIN
  if ( 12 == data_.size() )
	  return ECARD_SUCCESS;

  if (0x87 == data_[12])
  {
    for (int i = 14; i < 14 + data_[13]; i++)
      car_cvca.push_back(data_[i]);
  }

  return ECARD_SUCCESS;
}

std::vector<unsigned char> generate_PrK_IFD_DHx(
												const AlgorithmIdentifier* PACEDomainParameterInfo_)
{
	std::vector<unsigned char> result;
	result.resize(32);
	
	AutoSeededRandomPool rng;  
	rng.GenerateBlock(
					  &result[0], result.size()); 
	
	return result;
}

ECARD_STATUS __STDCALL__ ePAPerformPACE(
  ePACard& ePA_,
  const PaceInput& pace_input,
  std::vector<unsigned char>& car_cvca,
  std::vector<unsigned char>& x_Puk_ICC_DH2,
  unsigned char* PINCount)
{
  if (ePA_.getSubSystem()->supportsPACE()) {
      eCardCore_info(DEBUG_LEVEL_CRYPTO, "Reader supports PACE");

      std::vector<unsigned char> no_password;
      PaceInput pace_input_ = pace_input;
      pace_input_.set_pin(no_password);
      PaceOutput output = ePA_.getSubSystem()->establishPACEChannel(pace_input_);

      car_cvca = output.get_car_curr();
      x_Puk_ICC_DH2 = output.get_id_icc();
  } else {
      eCardCore_info(DEBUG_LEVEL_CRYPTO, "Reader does not support PACE. Will establish PACE channel.");

      // Parse the EF.CardAccess file to get needed information.
      SecurityInfos	*secInfos_ = 0x00;
      if (ber_decode(0, &asn_DEF_SecurityInfos, (void **)&secInfos_, ePA_.get_ef_cardaccess().data(), ePA_.get_ef_cardaccess().size()).code != RC_OK)
      {
          asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
          return ECARD_EFCARDACCESS_PARSER_ERROR;
      }

      OBJECT_IDENTIFIER_t PACE_OID_;
      AlgorithmIdentifier* PACEDomainParameterInfo_ = 0x00;

      for (int i = 0; i < secInfos_->list.count; i++)
      {
          OBJECT_IDENTIFIER_t oid = secInfos_->list.array[i]->protocol;

          {
              // Find the algorithm for PACE ...
              OBJECT_IDENTIFIER_t PACE_ECDH_3DES_CBC_CBC     = makeOID(id_PACE_ECDH_3DES_CBC_CBC);
              OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_128 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_128);
              OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_192 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_192);
              OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_256 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_256);

              if (PACE_ECDH_3DES_CBC_CBC == oid || PACE_ECDH_AES_CBC_CMAC_128 == oid ||
                      PACE_ECDH_AES_CBC_CMAC_192 == oid || PACE_ECDH_AES_CBC_CMAC_256 == oid)
                  PACE_OID_ = oid;

              asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_3DES_CBC_CBC, 1);
              asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_128, 1);
              asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_192, 1);
              asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &PACE_ECDH_AES_CBC_CMAC_256, 1);
          }

          { OBJECT_IDENTIFIER_t oidCheck = makeOID(id_PACE_ECDH);
              // Find the PACEDomainParameter
              if (oidCheck == oid)
              {
                  if (ber_decode(0, &asn_DEF_AlgorithmIdentifier, (void **)&PACEDomainParameterInfo_, 
                              secInfos_->list.array[i]->requiredData.buf, secInfos_->list.array[i]->requiredData.size).code != RC_OK)
                  {
                      asn_DEF_AlgorithmIdentifier.free_struct(&asn_DEF_AlgorithmIdentifier, PACEDomainParameterInfo_, 0);
                      asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
                      return ECARD_EFCARDACCESS_PARSER_ERROR;    
                  }
              }

              asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &oidCheck, 1);

          }
      }


      ECARD_STATUS status = ECARD_SUCCESS;  
      if (ECARD_SUCCESS != (status = perform_PACE_Step_B(PACE_OID_, pace_input.get_pin_id(), pace_input.get_chat(), ePA_)))
      {
          asn_DEF_AlgorithmIdentifier.free_struct(&asn_DEF_AlgorithmIdentifier, PACEDomainParameterInfo_, 0);
          asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
          return status;
      }

      std::vector<unsigned char> rndICC_;
      if (ECARD_SUCCESS != (status = perform_PACE_Step_C(PACE_OID_, pace_input.get_pin(), pace_input.get_pin_id(), ePA_, rndICC_)))
      {
          asn_DEF_AlgorithmIdentifier.free_struct(&asn_DEF_AlgorithmIdentifier, PACEDomainParameterInfo_, 0);
          asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
          return status;
      }

      std::vector<unsigned char> PrK_IFD_DH1_ = generate_PrK_IFD_DHx(PACEDomainParameterInfo_);

      ECP::Point PuK_IFD_DH1_ = calculate_PuK_IFD_DH1(PrK_IFD_DH1_, PACEDomainParameterInfo_);

      ECP::Point PuK_ICC_DH1_;
      if (ECARD_SUCCESS != (status = perform_PACE_Step_D(PuK_IFD_DH1_, ePA_, PuK_ICC_DH1_)))
      {
          asn_DEF_AlgorithmIdentifier.free_struct(&asn_DEF_AlgorithmIdentifier, PACEDomainParameterInfo_, 0);
          asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
          return status;
      }

      std::vector<unsigned char> PrK_IFD_DH2_ = generate_PrK_IFD_DHx(PACEDomainParameterInfo_);

      ECP::Point PuK_IFD_DH2_ = calculate_PuK_IFD_DH2(PrK_IFD_DH1_, PrK_IFD_DH2_, PuK_ICC_DH1_, 
              rndICC_, PACEDomainParameterInfo_);

      ECP::Point PuK_ICC_DH2_;
      if (ECARD_SUCCESS != (status = perform_PACE_Step_E(PuK_IFD_DH2_, ePA_, PuK_ICC_DH2_)))
      {
          asn_DEF_AlgorithmIdentifier.free_struct(&asn_DEF_AlgorithmIdentifier, PACEDomainParameterInfo_, 0);
          asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
          return status;
      }

      ECP::Point KIFD_ICC_ = calculate_KIFD_ICC(PrK_IFD_DH2_, PuK_ICC_DH2_, PACEDomainParameterInfo_);

      std::vector<unsigned char> kMac_ = calculate_SMKeys(KIFD_ICC_, true);
      std::vector<unsigned char> kEnc_ = calculate_SMKeys(KIFD_ICC_, false);

      std::vector<unsigned char> x_Puk_ICC_DH2_;
      x_Puk_ICC_DH2_.resize(PuK_ICC_DH2_.x.ByteCount());
      std::vector<unsigned char> y_Puk_ICC_DH2_;
      y_Puk_ICC_DH2_.resize(PuK_ICC_DH2_.y.ByteCount());

      // assert(0x20 == PuK_ICC_DH2_.x.ByteCount());
      // assert(0x20 == PuK_ICC_DH2_.y.ByteCount());

      PuK_ICC_DH2_.x.Encode(&x_Puk_ICC_DH2_[0], PuK_ICC_DH2_.x.ByteCount());
      PuK_ICC_DH2_.y.Encode(&y_Puk_ICC_DH2_[0], PuK_ICC_DH2_.y.ByteCount());

      if (x_Puk_ICC_DH2_.size() != 0x20)
          x_Puk_ICC_DH2_.insert(x_Puk_ICC_DH2_.begin(), 0x00);

      if (y_Puk_ICC_DH2_.size() != 0x20)
          y_Puk_ICC_DH2_.insert(y_Puk_ICC_DH2_.begin(), 0x00);

      std::vector<unsigned char> toBeMaced_PuK_ICC_DH2_ = generate_PuK_ICC_DH2(
              PuK_ICC_DH2_, rndICC_, PACEDomainParameterInfo_);

      std::vector<unsigned char> toBeMaced_PuK_IFD_DH2_ = generate_PuK_IFD_DH2(
              PuK_IFD_DH2_, rndICC_, PACEDomainParameterInfo_);

      std::string car_cvca_;
      if (ECARD_SUCCESS != (status = perform_PACE_Step_F(calculateMAC(toBeMaced_PuK_ICC_DH2_, kMac_),
                      calculateMAC(toBeMaced_PuK_IFD_DH2_, kMac_), ePA_, car_cvca_)))
      {
          asn_DEF_AlgorithmIdentifier.free_struct(&asn_DEF_AlgorithmIdentifier, PACEDomainParameterInfo_, 0);
          asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
          return status;
      }

      ePA_.setKeys(kEnc_, kMac_);

      car_cvca = std::vector<unsigned char> ( car_cvca_.begin(), car_cvca_.end() );

      x_Puk_ICC_DH2 = x_Puk_ICC_DH2_;

      asn_DEF_AlgorithmIdentifier.free_struct(&asn_DEF_AlgorithmIdentifier, PACEDomainParameterInfo_, 0);
      asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
  }
  
  return ECARD_SUCCESS;
}

