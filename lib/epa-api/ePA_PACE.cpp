#include "ePAAPI.h"
#include "ePAStatus.h"
#include "ePACard.h"

using namespace Bundesdruckerei::nPA;

#include <ICard.h>
#include <SecurityInfos.h>
#include <PACEDomainParameterInfo.h>
#include <eIDHelper.h>
#include <eIDOID.h>
#include <ECParameters.h>

#include <ePACommon.h>

#include <cstdio>

/*
 * Calculate the SK.PACE.xyz
 */
std::vector<unsigned char> generateSKPACE_FromPassword(
  IN BYTE_INPUT_DATA password,
  IN KEY_REFERENCE keyReference)
{
  std::vector<unsigned char> result;
  unsigned char c_mrz[] = { 0x00, 0x00, 0x00, 0x03 };	// always 0x03 acc. EAC 2.05 page 54
  unsigned char c_can[] = { 0x00, 0x00, 0x00, 0x03 };
  unsigned char c_pin[] = { 0x00, 0x00, 0x00, 0x03 };
  unsigned char c_puk[] = { 0x00, 0x00, 0x00, 0x03 };

  SHA1 paceH;

  // Hash the full password
  paceH.Update(password.pData, password.dataSize);

  switch (keyReference)
  {
  case MRZ:
	  paceH.Update(c_mrz, 4);
	  break;

  case CAN:
	  paceH.Update(c_can, 4);
	  break;

  case PIN:
	  paceH.Update(c_pin, 4);
	  break;

  case PUK:
	  paceH.Update(c_puk, 4);
	  break;
  }

  // Get the first 16 bytes from result
  result.resize(20);
  paceH.Final(&result[0]);
  result.resize(16);  

  hexdump("###-> INPUT PIN", password.pData, password.dataSize);
  hexdump("###-> SKPACE", &result[0], result.size());

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
  hexdump("###-> SKPACE in decryptRNDICC_AES", (void*) &skPACE[0], skPACE.size());
  hexdump("###-> encryptedRNDICC", (void*) &encryptedRNDICC[0], encryptedRNDICC.size());

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

  hexdump("###-> RNDICC", &result_[0], result_.size());

  return result_;
}


ECP::Point calculate_PuK_IFD_DH1(
  const std::vector<unsigned char>& PrK_IFD_DH1,
  const AlgorithmIdentifier* PACEDomainParameterInfo)
{
  return calculate_PuK_IFD_DHx(PrK_IFD_DH1, PACEDomainParameterInfo);
}

/*
* 1. H = PrK.IFD.DH1 * PuK.ICC.DH1
*/
ECP::Point calculate_PuK_IFD_DH2(
  const std::vector<unsigned char>& PrK_IFD_DH1,
  const std::vector<unsigned char>& PrK_IFD_DH2,
  const ECP::Point& PuK_ICC_DH1,
  const std::vector<unsigned char>& rndICC_,
  const AlgorithmIdentifier* PACEDomainParameterInfo)
{
    hexdump("###-> PrK.IFD.DH1 in calculate_PuK_IFD_DH2", (void*) &PrK_IFD_DH1[0], PrK_IFD_DH1.size());
    hexdump("###-> rndICC in calculate_PuK_IFD_DH2", (void*) &rndICC_[0], rndICC_.size());

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

    hexdump("###-> PrK.IFD.DH2 in calculate_PuK_IFD_DH2", (void*) &PrK_IFD_DH2[0], PrK_IFD_DH2.size());
    Integer k1(&PrK_IFD_DH2[0], PrK_IFD_DH2.size());

    ECP::Point result = ecp.Multiply(k1, G1);

    std::vector<unsigned char> x_;
    x_.resize(result.x.ByteCount());
    std::vector<unsigned char> y_;
    y_.resize(result.y.ByteCount());

    result.x.Encode(&x_[0], result.x.ByteCount());
    result.y.Encode(&y_[0], result.y.ByteCount());
 
    hexdump("###-> PuK.IFD.DH2.x", (void*) &x_[0], x_.size());
    hexdump("###-> PuK.IFD.DH2.y", (void*) &y_[0], y_.size());
  
    return result;
}

/**
 *
 */
ECP::Point calculate_KIFD_ICC( 
  std::vector<unsigned char> PrK_IFD_DH2, 
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

    hexdump("###-> KIFD/ICC.x", (void*) &x_[0], x_.size());
    hexdump("###-> KIFD/ICC.y", (void*) &y_[0], y_.size());
  
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
  for (int i = 0; i < tmpx_.size(); i++)
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

  hexdump(generateMac ? "###-> KMac" : "###-> KEnc", (void*) &result[0], result.size());

  return result;
}

/*
 *
 */
std::vector<unsigned char> generate_PuK_ICC_DH2(
  std::vector<unsigned char> PrK_IFD_DH1,
  const ECP::Point& PuK_ICC_DH1,
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
  std::vector<unsigned char> PrK_IFD_DH1,
  const ECP::Point& PuK_ICC_DH1,
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
  KEY_REFERENCE keyReference, 
  const BYTE_INPUT_DATA& chat, 
  ICard* card_)
{
  hexdump("###-> PACE OID", PACE_OID_.buf, PACE_OID_.size);
  hexdump("###-> CAHT", chat.pData, chat.dataSize);
  hexdump("##-> KEY REF", &keyReference, 1);


  CardCommand MSE_Set_AT_;
  MSE_Set_AT_ << 0x00 << 0x22 << 0xC1 << 0xA4 << 0xFF; // Append 0xFF as LC, will be set later

  // Append OID
  MSE_Set_AT_ << 0x80 << PACE_OID_.size;
  for (int i = 0; i < PACE_OID_.size; i++)
    MSE_Set_AT_ << PACE_OID_.buf[i];

  // Append Key reference
  MSE_Set_AT_ << 0x83 << 0x01;
  // @TODO: MRZ not handled!! Different preparation function if needed.
  if (CAN == keyReference) MSE_Set_AT_ << 0x02;
  if (PIN == keyReference) MSE_Set_AT_ << 0x03;
  if (PUK == keyReference) MSE_Set_AT_ << 0x04;

  // Append CHAT
  for (size_t i = 0; i < chat.dataSize; i++)
    MSE_Set_AT_.push_back(chat.pData[i]);

  // Set LC
  MSE_Set_AT_[4] = MSE_Set_AT_.size() - 5;

  // Do the dirty work.
  CardResult MSE_Set_AT_Result_ = card_->sendAPDU(MSE_Set_AT_, "Send MSE:SET AT");
  if (MSE_Set_AT_Result_.getSW() != 0x9000)
  {
    if (MSE_Set_AT_Result_.getSW() == 0x63C2)
	  return ECARD_SUCCESS;

    return ECARD_PACE_STEP_B_FAILED;
  }
  return ECARD_SUCCESS;
}

ECARD_STATUS __STDCALL__ perform_PACE_Step_C( 
  const OBJECT_IDENTIFIER_t& PACE_OID_,
  const BYTE_INPUT_DATA& password,
  KEY_REFERENCE keyReference,
  ICard* card_,
  std::vector<unsigned char>& rndICC)
{
  CardCommand GeneralAuthenticate_;
  GeneralAuthenticate_ << 0x10 << 0x86 << 0x00 << 0x00 << 0x02 << 0x7C << 0x00 << 0x00; 

  CardResult GeneralAuthenticate_Result_ = card_->sendAPDU(GeneralAuthenticate_, "Send GENERAL AUTHENTICATE to get RND.ICC");
  if (GeneralAuthenticate_Result_.getSW() != 0x9000)
    return ECARD_PACE_STEP_C_FAILED;

  // Here we have the encrypted RND.ICC value
  std::vector<unsigned char> responseData_ = GeneralAuthenticate_Result_.getData();

  std::vector<unsigned char> encryptedRNDICC_;

  // Save the RND.ICC value for further usage
  for (size_t i = 4; i < responseData_.size(); i++)
    encryptedRNDICC_.push_back(responseData_[i]);

  // Now compute the SK.PACE.xyz key from the given password.
  // SK.PACE is used to decrypt the RND.ICC value from the 
  std::vector<unsigned char> skPACE_ = generateSKPACE_FromPassword(password, keyReference);
 
  OBJECT_IDENTIFIER_t PACE_ECDH_3DES_CBC_CBC     = makeOID(id_PACE_ECDH_3DES_CBC_CBC);
  OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_128 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_128);
  OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_192 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_192);
  OBJECT_IDENTIFIER_t PACE_ECDH_AES_CBC_CMAC_256 = makeOID(id_PACE_ECDH_AES_CBC_CMAC_256);
  
  if (PACE_OID_ == PACE_ECDH_AES_CBC_CMAC_128 || 
	  PACE_OID_ == PACE_ECDH_AES_CBC_CMAC_192 ||
	  PACE_OID_ ==  PACE_ECDH_AES_CBC_CMAC_256)
    rndICC = decryptRNDICC_AES(encryptedRNDICC_, skPACE_);

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
  ICard* card_,
  ECP::Point& Puk_ICC_DH1_)
{
  CardCommand GeneralAuthenticate_;
  GeneralAuthenticate_ << 0x10 << 0x86 << 0x00 << 0x00 << 0xFF; // Append 0xFF as LE, will be set later

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

  // Set LC
  GeneralAuthenticate_[4] = dataPart_.size();

  // Append command data field
  for (size_t i = 0; i < dataPart_.size(); i++)
    GeneralAuthenticate_.push_back(dataPart_[i]);

  // Append LE
  GeneralAuthenticate_ << 0x00; 

  CardResult GeneralAuthenticate_Result_ = card_->sendAPDU(GeneralAuthenticate_, "Send GENERAL AUTHENTICATE to Map Nonce");
  if (GeneralAuthenticate_Result_.getSW() != 0x9000)
    return ECARD_PACE_STEP_D_FAILED;

  std::vector<unsigned char> data_ = GeneralAuthenticate_Result_.getData();

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
  Puk_ICC_DH1_.x.Decode(&xValue_[0], xValue_.size());
  Puk_ICC_DH1_.y.Decode(&yValue_[0], yValue_.size());
  Puk_ICC_DH1_.identity = false;

  hexdump("PuK.ICC.DH1.x", (void*) &xValue_[0], xValue_.size());
  hexdump("PuK.ICC.DH1.y", (void*) &yValue_[0], yValue_.size());

  return ECARD_SUCCESS;
}

/* 
* This function performs step E of the PACE protocol 
*/
ECARD_STATUS __STDCALL__ perform_PACE_Step_E( 
  ECP::Point PuK_IFD_DH2_,
  ICard* card_,
  ECP::Point& Puk_ICC_DH2_)
{
  CardCommand GeneralAuthenticate_;
  GeneralAuthenticate_ << 0x10 << 0x86 << 0x00 << 0x00 << 0xFF; // Append 0xFF as LE, will be set later

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

  // Set LC
  GeneralAuthenticate_[4] = dataPart_.size();

  // Append command data field
  for (size_t i = 0; i < dataPart_.size(); i++)
    GeneralAuthenticate_.push_back(dataPart_[i]);

  // Append LE
  GeneralAuthenticate_ << 0x00; 

  CardResult GeneralAuthenticate_Result_ = card_->sendAPDU(GeneralAuthenticate_, "Send GENERAL AUTHENTICATE to Perform Key Agreement");
  if (GeneralAuthenticate_Result_.getSW() != 0x9000)
    return ECARD_PACE_STEP_E_FAILED;

  std::vector<unsigned char> data_ = GeneralAuthenticate_Result_.getData();

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

  hexdump("PuK.ICC.DH2.x", (void*) &xValue_[0], xValue_.size());
  hexdump("PuK.ICC.DH2.y", (void*) &yValue_[0], yValue_.size());

  return ECARD_SUCCESS;
}

ECARD_STATUS __STDCALL__ perform_PACE_Step_F( 
  const std::vector<unsigned char>& macedPuk_ICC_DH2,
  const std::vector<unsigned char>& macedPuk_IFD_DH2,
  ICard* card_,
  std::string& car_cvca)
{
  CardCommand GeneralAuthenticate_;
  GeneralAuthenticate_ << 0x00 << 0x86 << 0x00 << 0x00 << 0xFF; // Append 0xFF as LE, will be set later

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

  // Set LC
  GeneralAuthenticate_[4] = dataPart_.size();

  // Append command data field
  for (size_t i = 0; i < dataPart_.size(); i++)
    GeneralAuthenticate_.push_back(dataPart_[i]);

  // Append LE
  GeneralAuthenticate_ << 0x00; 

  CardResult GeneralAuthenticate_Result_ = card_->sendAPDU(GeneralAuthenticate_, "Send GENERAL AUTHENTICATE to perform explicit authentication");
  if (GeneralAuthenticate_Result_.getSW() != 0x9000)
    return ECARD_PACE_STEP_F_FAILED;

  std::vector<unsigned char> data_ = GeneralAuthenticate_Result_.getData();

  hexdump("###-> Last PACE result", &data_[0], data_.size());

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
    for (size_t i = 14; i < 14 + data_[13]; i++)
      car_cvca.push_back(data_[i]);
  }

  return ECARD_SUCCESS;
}

ECARD_STATUS __STDCALL__ ePAPerformPACE(
  IN ECARD_HANDLE hCard,
  IN KEY_REFERENCE keyReference,
  IN BYTE_INPUT_DATA chat,
  IN BYTE_INPUT_DATA certificate_description,
  IN BYTE_INPUT_DATA password,
  IN BYTE_INPUT_DATA efCardAccess,
  IN OUT BYTE_OUTPUT_DATA& kMac,
  IN OUT BYTE_OUTPUT_DATA& kEnc,
  IN OUT BYTE_OUTPUT_DATA& car_cvca,
  IN OUT BYTE_OUTPUT_DATA& x_Puk_ICC_DH2,
  OUT unsigned char* PINCount)
{
  // Check handle ...
  if (0x00 == hCard || ECARD_INVALID_HANDLE_VALUE == hCard)
    return ECARD_INVALID_PARAMETER_1;

  // Try to get ePA card
  ICard* card_ = (ICard*) hCard;
  ePACard* ePA_ = dynamic_cast<ePACard*>(card_);

  // No ePA -> Leave
  if (0x00 == ePA_)
    return ECARD_INVALID_EPA;

  if (ePA_->subSystemSupportsPACE()) {
      enum PaceInput::PinID pin_id;
      switch (keyReference) {
          case MRZ:
              pin_id = PaceInput::mrz;
              break;
          case CAN:
              pin_id = PaceInput::can;
              break;
          case PIN:
              pin_id = PaceInput::pin;
              break;
          case PUK:
              pin_id = PaceInput::puk;
              break;
          default:
              pin_id = PaceInput::undef;
      }
      vector<BYTE> v_password, v_chat, v_certificate_description;

      v_password.reserve(password.dataSize);
      v_password.resize(password.dataSize);
      memcpy(&v_password[0], password.pData, password.dataSize);

      v_chat.reserve(chat.dataSize);
      v_chat.resize(chat.dataSize);
      memcpy(&v_chat[0], chat.pData, chat.dataSize);

      //v_certificate_description.reserve(certificate_description.dataSize);
      //v_certificate_description.resize(certificate_description.dataSize);
      //memcpy(&v_certificate_description[0], certificate_description.pData, certificate_description.dataSize);

      PaceOutput output = ePA_->subSystemEstablishPACEChannel(PaceInput(pin_id, v_password, v_chat, v_certificate_description));

      car_cvca.m_dataSize = output.get_car_curr().size();
      car_cvca.m_pDataBuffer = kMac.m_allocator(output.get_car_curr().size());
      memcpy(car_cvca.m_pDataBuffer, &output.get_car_curr()[0], output.get_car_curr().size());

      x_Puk_ICC_DH2.m_dataSize = output.get_id_icc().size();
      x_Puk_ICC_DH2.m_pDataBuffer = x_Puk_ICC_DH2.m_allocator(output.get_id_icc().size());
      memcpy(x_Puk_ICC_DH2.m_pDataBuffer, &output.get_id_icc()[0], output.get_id_icc().size());
  } else {
  // Parse the EF.CardAccess file to get needed information.
  SecurityInfos	*secInfos_ = 0x00;
  if (ber_decode(0, &asn_DEF_SecurityInfos, (void **)&secInfos_, efCardAccess.pData, efCardAccess.dataSize).code != RC_OK)
  {
    asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
    return ECARD_EFCARDACCESS_PARSER_ERROR;
  }

  OBJECT_IDENTIFIER_t PACE_OID_;
  AlgorithmIdentifier* PACEDomainParameterInfo_ = 0x00;
  //AlgorithmIdentifier* CADomainParameterInfo_ = 0x00;

  for (int i = 0; i < secInfos_->list.count; i++)
  {
    OBJECT_IDENTIFIER_t oid = secInfos_->list.array[i]->protocol;

    { // Find the algorithm for PACE ...
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
    } // Find the algorithm for PACE ...

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
      } // if (OID(id_PACE_ECDH) == oid)
      
      asn_DEF_OBJECT_IDENTIFIER.free_struct(&asn_DEF_OBJECT_IDENTIFIER, &oidCheck, 1);
      
    } // Find the PACEDomainParameter ...
  } // for (int i = 0; i < secInfos_->list.count; i++)
  
  ECARD_STATUS status = ECARD_SUCCESS;  
  if (ECARD_SUCCESS != (status = perform_PACE_Step_B(PACE_OID_, keyReference, chat, card_)))
  {
    asn_DEF_AlgorithmIdentifier.free_struct(&asn_DEF_AlgorithmIdentifier, PACEDomainParameterInfo_, 0);
    asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
    return status;
  }

  std::vector<unsigned char> rndICC_;
  if (ECARD_SUCCESS != (status = perform_PACE_Step_C(PACE_OID_, password, keyReference, card_, rndICC_)))
  {
    asn_DEF_AlgorithmIdentifier.free_struct(&asn_DEF_AlgorithmIdentifier, PACEDomainParameterInfo_, 0);
    asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
    return status;
  }

  std::vector<unsigned char> PrK_IFD_DH1_ = generate_PrK_IFD_DHx(PACEDomainParameterInfo_);

  ECP::Point PuK_IFD_DH1_ = calculate_PuK_IFD_DH1(PrK_IFD_DH1_, PACEDomainParameterInfo_);

  ECP::Point PuK_ICC_DH1_;
  if (ECARD_SUCCESS != (status = perform_PACE_Step_D(PuK_IFD_DH1_, card_, PuK_ICC_DH1_)))
  {
    asn_DEF_AlgorithmIdentifier.free_struct(&asn_DEF_AlgorithmIdentifier, PACEDomainParameterInfo_, 0);
    asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
    return status;
  }

  std::vector<unsigned char> PrK_IFD_DH2_ = generate_PrK_IFD_DHx(PACEDomainParameterInfo_);

  ECP::Point PuK_IFD_DH2_ = calculate_PuK_IFD_DH2(PrK_IFD_DH1_, PrK_IFD_DH2_, PuK_ICC_DH1_, 
	  rndICC_, PACEDomainParameterInfo_);

  ECP::Point PuK_ICC_DH2_;
  if (ECARD_SUCCESS != (status = perform_PACE_Step_E(PuK_IFD_DH2_, card_, PuK_ICC_DH2_)))
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
	  PrK_IFD_DH1_, PuK_ICC_DH1_, PuK_ICC_DH2_, rndICC_, PACEDomainParameterInfo_);

  std::vector<unsigned char> toBeMaced_PuK_IFD_DH2_ = generate_PuK_IFD_DH2(
	  PrK_IFD_DH1_, PuK_ICC_DH1_, PuK_IFD_DH2_, rndICC_, PACEDomainParameterInfo_);

  std::string car_cvca_;
  if (ECARD_SUCCESS != (status = perform_PACE_Step_F(calculateMAC(toBeMaced_PuK_ICC_DH2_, kMac_),
	  calculateMAC(toBeMaced_PuK_IFD_DH2_, kMac_), card_, car_cvca_)))
  {
    asn_DEF_AlgorithmIdentifier.free_struct(&asn_DEF_AlgorithmIdentifier, PACEDomainParameterInfo_, 0);
    asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
    return status;
  }

  kMac.m_dataSize = kMac_.size();
  kMac.m_pDataBuffer = kMac.m_allocator(kMac_.size());
  memcpy(kMac.m_pDataBuffer, &kMac_[0], kMac_.size());

  kEnc.m_dataSize = kEnc_.size();
  kEnc.m_pDataBuffer = kEnc.m_allocator(kEnc_.size());
  memcpy(kEnc.m_pDataBuffer, &kEnc_[0], kEnc_.size());

  car_cvca.m_dataSize = car_cvca_.length();
  car_cvca.m_pDataBuffer = car_cvca.m_allocator(car_cvca_.length());
  memcpy(car_cvca.m_pDataBuffer, &car_cvca_[0], car_cvca_.length());

  x_Puk_ICC_DH2.m_dataSize = x_Puk_ICC_DH2_.size();
  x_Puk_ICC_DH2.m_pDataBuffer = x_Puk_ICC_DH2.m_allocator(x_Puk_ICC_DH2_.size());
  memcpy(x_Puk_ICC_DH2.m_pDataBuffer, &x_Puk_ICC_DH2_[0], x_Puk_ICC_DH2_.size());

  asn_DEF_AlgorithmIdentifier.free_struct(&asn_DEF_AlgorithmIdentifier, PACEDomainParameterInfo_, 0);
  asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
  }
  
  return ECARD_SUCCESS;
}

