// ---------------------------------------------------------------------------
// Copyright (c) 2009 Bundesdruckerei GmbH
// All rights reserved.
//
// $Id: ePA_TA.cpp 1427 2012-01-17 15:04:42Z x_schrom $
// ---------------------------------------------------------------------------

#include "ePAAPI.h"
#include "ePAStatus.h"
#include "ePACard.h"
//#include "CHAT.h"
using namespace Bundesdruckerei::nPA;

#include <ICard.h>
#include <SecurityInfos.h>
#include <PACEDomainParameterInfo.h>
#include <eIDHelper.h>
#include <eIDOID.h>
#include <ePACommon.h>

USING_NAMESPACE(CryptoPP)

#include <cstdio>
#include <fstream>

// ---------------------------------------------------------------------------
// Start implementation
// ---------------------------------------------------------------------------

/*
 *
 */
ECARD_STATUS __STDCALL__ perform_TA_Step_A( 
  BYTE_INPUT_DATA &carCVCA, 
  unsigned long long &ssc, 
  BYTE_INPUT_DATA kEnc, 
  BYTE_INPUT_DATA kMac, 
  ICard* card_ )
{
  CardCommand MseSetDST;
  MseSetDST << 0x0C << 0x22 << 0x81 << 0xB6;

  // Build up command data field
  std::vector<unsigned char> dataPart_;
  dataPart_.push_back(0x83);
  // Set the size
  dataPart_.push_back(carCVCA.dataSize);

  // Append the CAR
  for (size_t i = 0; i < carCVCA.dataSize ; i++)
    dataPart_.push_back(carCVCA.pData[i]);

  // Build the SM related structures.
  std::vector<unsigned char> do87_ = buildDO87_AES(kEnc, dataPart_, ssc);
  std::vector<unsigned char> do8E_ = buildDO8E_AES(kMac, MseSetDST, do87_, ssc);

  // Append LC
  MseSetDST.push_back(do87_.size() + do8E_.size());
  
  // Append DO87 to APDU
  for (size_t i = 0; i < do87_.size(); i++)
    MseSetDST.push_back(do87_[i]);

  // Append DO8E to APDU
  for (size_t i = 0; i < do8E_.size(); i++)
    MseSetDST.push_back(do8E_[i]);

  // Append LE
  MseSetDST.push_back(0x00);

  // Do the dirty work.
  CardResult MseSetDST_Result_ = card_->sendAPDU(MseSetDST, "Send MANAGE SECURITY ENVIRONMENT to set CAR for PuK.CVCA.xy.n");
  if (MseSetDST_Result_.getSW() != 0x9000)
    return ECARD_TA_STEP_A_FAILED;

  // Get returned data.
  std::vector<unsigned char> returnedData = MseSetDST_Result_.getData();

  // Verify the SM response from the card.
  if (!verifyResponse_AES(kMac, returnedData, ssc))
    return ECARD_TA_STEP_A_VERIFY_FAILED;

  return ECARD_SUCCESS; // We are happy :)
}

/*
 *
 */
ECARD_STATUS __STDCALL__ perform_TA_Step_B( 
  unsigned long long &ssc, 
  BYTE_INPUT_DATA kEnc, 
  BYTE_INPUT_DATA kMac, 
  BYTE_INPUT_DATA dvcaCertificate,
  ICard* card_ )
{
  int copyOffset = 0;

  // Check for certificate header and cut off is needed
  if (dvcaCertificate.pData[0] == 0x7F && dvcaCertificate.pData[1] == 0x21)
  {
    // One length byte
    if (dvcaCertificate.pData[2] == 0x81)
      copyOffset = 4;

    // Two length bytes
    if (dvcaCertificate.pData[2] == 0x82)
      copyOffset = 5;
  } else if (dvcaCertificate.pData[0] == 0x7F && dvcaCertificate.pData[1] == 0x4E)
  {
    // Copy all
    copyOffset = 0;
  } else
  {
    // Invalid certificate format
    return ECARD_TA_STEP_B_INVALID_CERTIFCATE_FORMAT;
  }

  std::vector<unsigned char> dvcaCertificate_;
  // Copy the terminal certificate for further usage.
  for (size_t i = copyOffset; i < dvcaCertificate.dataSize; i++)
    dvcaCertificate_.push_back(dvcaCertificate.pData[i]);

  CardCommand VerifyCertificate;
  VerifyCertificate << 0x0C << 0x2A << 0x00 << 0xBE;

  // Build the SM related structures.
  std::vector<unsigned char> do87_ = buildDO87_AES(kEnc, dvcaCertificate_, ssc);
  std::vector<unsigned char> do8E_ = buildDO8E_AES(kMac, VerifyCertificate, do87_, ssc);

  // Append the size of the SM structures to the APDU.
  if (do87_.size() + do8E_.size() <= 0xFF)
  {    
    // Normal APDU
    VerifyCertificate.push_back(do87_.size() + do8E_.size());
  } else
  {
    // Extended length APDU
    VerifyCertificate.push_back(0x00);
    VerifyCertificate.push_back(((do87_.size() + do8E_.size()) & 0xFF00) >> 8);
    VerifyCertificate.push_back((do87_.size() + do8E_.size()) & 0xFF);
  }

  // Append DO87 to APDU
  for (size_t i = 0; i < do87_.size(); i++)
    VerifyCertificate.push_back(do87_[i]);

  // Append DO8E to APDU
  for (size_t i = 0; i < do8E_.size(); i++)
    VerifyCertificate.push_back(do8E_[i]);

  // Append the LE byte to the APDU
  if (do87_.size() + do8E_.size() <= 0xFF)
  {
    // Normal APDU
    VerifyCertificate.push_back(0x00);
  }
  else 
  {
    // Extended length APDU
    VerifyCertificate.push_back(0x00);
    VerifyCertificate.push_back(0x00);
  }

  // Do the dirty work.
  CardResult VerifyCertificate_Result_ = card_->sendAPDU(VerifyCertificate, "Send VERIFY CERTIFICATE for CVCA.");
  if (VerifyCertificate_Result_.getSW() != 0x9000)
    return ECARD_TA_STEP_B_FAILED;

  // Get returned data.
  std::vector<unsigned char> returnedData = VerifyCertificate_Result_.getData();

  // Verify the SM response from the card.
  if (!verifyResponse_AES(kMac, returnedData, ssc))
    return ECARD_TA_STEP_B_VERIFY_FAILED;

  return ECARD_SUCCESS; // We are happy :)
}

/*
 *
 */
ECARD_STATUS __STDCALL__ perform_TA_Step_C( 
  BYTE_INPUT_DATA &carDVCA, 
  unsigned long long &ssc, 
  BYTE_INPUT_DATA kEnc, 
  BYTE_INPUT_DATA kMac, 
  ICard* card_ )
{
  CardCommand MseSetDST;
  MseSetDST << 0x0C << 0x22 << 0x81 << 0xB6;

  // Build up command data field
  std::vector<unsigned char> dataPart_;
  dataPart_.push_back(0x83);
  // Set the size
  dataPart_.push_back(carDVCA.dataSize);

  // Append the CAR
  for (size_t i = 0; i < carDVCA.dataSize ; i++)
    dataPart_.push_back(carDVCA.pData[i]);

  // Build the SM related structures.
  std::vector<unsigned char> do87_ = buildDO87_AES(kEnc, dataPart_, ssc);
  std::vector<unsigned char> do8E_ = buildDO8E_AES(kMac, MseSetDST, do87_, ssc);

  // Append LC
  MseSetDST.push_back(do87_.size() + do8E_.size());

  // Append DO87 to APDU
  for (size_t i = 0; i < do87_.size(); i++)
    MseSetDST.push_back(do87_[i]);

  // Append DO8E to APDU
  for (size_t i = 0; i < do8E_.size(); i++)
    MseSetDST.push_back(do8E_[i]);

  // Append LE
  MseSetDST.push_back(0x00);

  // Do the dirty work.
  CardResult MseSetDST_Result_ = card_->sendAPDU(MseSetDST, "Send MANAGE SECURITY ENVIRONMENT to set CAR for PuK.DV");
  if (MseSetDST_Result_.getSW() != 0x9000)
    return ECARD_TA_STEP_C_FAILED;

  // Get returned data.
  std::vector<unsigned char> returnedData = MseSetDST_Result_.getData();

  // Verify the SM response from the card.
  if (!verifyResponse_AES(kMac, returnedData, ssc))
    return ECARD_TA_STEP_C_VERIFY_FAILED;

  return ECARD_SUCCESS; // We are happy :)
}

/*
 *
 */
ECARD_STATUS __STDCALL__ perform_TA_Step_D( 
  unsigned long long &ssc, 
  BYTE_INPUT_DATA kEnc, 
  BYTE_INPUT_DATA kMac, 
  BYTE_INPUT_DATA terminalCertificateData,
  ICard* card_ )
{
  int copyOffset = 0;

  // Check for certificate header and cut off is needed
  if (terminalCertificateData.pData[0] == 0x7F && terminalCertificateData.pData[1] == 0x21)
  {
    // One length byte
    if (terminalCertificateData.pData[2] == 0x81)
      copyOffset = 4;

    // Two length bytes
    if (terminalCertificateData.pData[2] == 0x82)
      copyOffset = 5;
  } else if (terminalCertificateData.pData[0] == 0x7F && terminalCertificateData.pData[1] == 0x4E)
  {
    // Copy all
    copyOffset = 0;
  } else
  {
    // Invalid certificate format
    return ECARD_TA_STEP_D_INVALID_CERTIFCATE_FORMAT;
  }

  std::vector<unsigned char> terminalCertificateData_;
  // Copy the terminal certificate for further usage.
  for (size_t i = copyOffset; i < terminalCertificateData.dataSize; i++)
    terminalCertificateData_.push_back(terminalCertificateData.pData[i]);

  CardCommand VerifyCertificate;
  VerifyCertificate << 0x0C << 0x2A << 0x00 << 0xBE;

  // Build the SM related structures.
  std::vector<unsigned char> do87_ = buildDO87_AES(kEnc, terminalCertificateData_, ssc);
  std::vector<unsigned char> do8E_ = buildDO8E_AES(kMac, VerifyCertificate, do87_, ssc);

  // Append the size of the SM structures to the APDU.
  if (do87_.size() + do8E_.size() <= 0xFF)
  {    
    // Normal APDU
    VerifyCertificate.push_back(do87_.size() + do8E_.size());
  } else
  {
    // Extended length APDU
    VerifyCertificate.push_back(0x00);
    VerifyCertificate.push_back(((do87_.size() + do8E_.size()) & 0xFF00) >> 8);
    VerifyCertificate.push_back((do87_.size() + do8E_.size()) & 0xFF);
  }

  // Append DO87 to APDU
  for (size_t i = 0; i < do87_.size(); i++)
    VerifyCertificate.push_back(do87_[i]);

  // Append DO8E to APDU
  for (size_t i = 0; i < do8E_.size(); i++)
    VerifyCertificate.push_back(do8E_[i]);

  // Append the LE byte to the APDU
  if (do87_.size() + do8E_.size() <= 0xFF)
  {
    // Normal APDU
    VerifyCertificate.push_back(0x00);
  }
  else 
  {
    // Extended length APDU
    VerifyCertificate.push_back(0x00);
    VerifyCertificate.push_back(0x00);
  }

  // Do the dirty work.
  CardResult VerifyCertificate_Result_ = card_->sendAPDU(VerifyCertificate, "Send VERIFY CERTIFICATE for Terminal Certificate.");
  if (VerifyCertificate_Result_.getSW() != 0x9000)
    return ECARD_TA_STEP_D_FAILED;

  // Get returned data.
  std::vector<unsigned char> returnedData = VerifyCertificate_Result_.getData();

  // Verify the SM response from the card.
  if (!verifyResponse_AES(kMac, returnedData, ssc))
    return ECARD_TA_STEP_D_VERIFY_FAILED;

  return ECARD_SUCCESS; // We are happy :)
}

/*
 *
 */
ECARD_STATUS __STDCALL__ perform_TA_Step_E( 
  unsigned long long &ssc, 
  BYTE_INPUT_DATA kEnc, 
  BYTE_INPUT_DATA kMac,
  BYTE_INPUT_DATA keyID,
  BYTE_INPUT_DATA x_Puk_IFD_DH,
  BYTE_INPUT_DATA authenticatedAuxiliaryData,
  ICard* card_ )
{
  CardCommand MseSetAT;
  MseSetAT << 0x0C << 0x22 << 0x81 << 0xA4;

  // @todo Get the right oid for TA from ???. At the moment we use only id_TA_ECDSA_SHA_1!!

  std::vector<unsigned char> dataField;
  dataField.push_back(0x80); // OID for algorithm id_TA_ECDSA_SHA_1 
  dataField.push_back(0x0A); dataField.push_back(0x04); dataField.push_back(0x00);
  dataField.push_back(0x7F); dataField.push_back(0x00); dataField.push_back(0x07); 
  dataField.push_back(0x02); dataField.push_back(0x02); dataField.push_back(0x02); 
  dataField.push_back(0x02); dataField.push_back(0x03);  
  
  dataField.push_back(0x83); // keyId
  dataField.push_back(keyID.dataSize);
  for (size_t i = 0; i < keyID.dataSize; i++)
    dataField.push_back(keyID.pData[i]);

  dataField.push_back(0x91); // x(Puk.IFD.CA) -> see chip authentication
  dataField.push_back(x_Puk_IFD_DH.dataSize);
  for (size_t i = 0; i < x_Puk_IFD_DH.dataSize; i++)
    dataField.push_back(x_Puk_IFD_DH.pData[i]);

  for (size_t i = 0; i < authenticatedAuxiliaryData.dataSize; i++)
    dataField.push_back(authenticatedAuxiliaryData.pData[i]);
  
  // Build the SM related structures.
  std::vector<unsigned char> do87_ = buildDO87_AES(kEnc, dataField, ssc);
  std::vector<unsigned char> do8E_ = buildDO8E_AES(kMac, MseSetAT, do87_, ssc);

  // Append LC
  MseSetAT.push_back(do87_.size() + do8E_.size());

  // Append DO87 to APDU
  for (size_t i = 0; i < do87_.size(); i++)
    MseSetAT.push_back(do87_[i]);

  // Append DO8E to APDU
  for (size_t i = 0; i < do8E_.size(); i++)
    MseSetAT.push_back(do8E_[i]);

  // Append LE
  MseSetAT.push_back(0x00);

  // Do the dirty work.
  CardResult MseSetAT_Result_ = card_->sendAPDU(MseSetAT, "Send SET MSE AT for authentication.");
  if (MseSetAT_Result_.getSW() != 0x9000)
    return ECARD_TA_STEP_E_FAILED;

  // Get returned data.
  std::vector<unsigned char> returnedData = MseSetAT_Result_.getData();

  // Verify the SM response from the card.
  if (!verifyResponse_AES(kMac, returnedData, ssc))
    return ECARD_TA_STEP_E_VERIFY_FAILED;

  return ECARD_SUCCESS;
}

/*
 *
 */
ECARD_STATUS __STDCALL__ perform_TA_Step_F( 
  unsigned long long &ssc, 
  BYTE_INPUT_DATA kEnc, 
  BYTE_INPUT_DATA kMac,
  std::vector<unsigned char>& RND_ICC,
  ICard* card_ )
{
  CardCommand GetChallenge_;
  GetChallenge_ << 0x0C << 0x84 << 0x00 << 0x00;

  // We need 8 bytes of random data. So we encode the DO97 by hand here.
  std::vector<unsigned char> do97_;
  do97_.push_back(0x97); do97_.push_back(0x01); do97_.push_back(0x08);
  std::vector<unsigned char> do8E_ = buildDO8E_AES(kMac, GetChallenge_, do97_, ssc);
 
  GetChallenge_.push_back(do97_.size() + do8E_.size());

  // Append DO97 to APDU
  for (size_t i = 0; i < do97_.size(); i++)
    GetChallenge_.push_back(do97_[i]);

  // Append DO8E to APDU
  for (size_t i = 0; i < do8E_.size(); i++)
    GetChallenge_.push_back(do8E_[i]);

  GetChallenge_.push_back(0x00);

  // Do the dirty work.
  CardResult GetChallenge_Result_ = card_->sendAPDU(GetChallenge_, "Send GET CHALLENGE to get encrypted nonce.");
  if (GetChallenge_Result_.getSW() != 0x9000)
    return ECARD_TA_STEP_F_FAILED;

  // Get returned data.
  std::vector<unsigned char> returnedData = GetChallenge_Result_.getData();

  // Verify the SM response from the card.
  if (!verifyResponse_AES(kMac, returnedData, ssc))
    return ECARD_TA_STEP_F_VERIFY_FAILED;

  RND_ICC = decryptResponse_AES(kEnc, returnedData, ssc);

  return ECARD_SUCCESS;
}

/*
 *
 */
ECARD_STATUS __STDCALL__ perform_TA_Step_G( 
  unsigned long long &ssc, 
  BYTE_INPUT_DATA kEnc, 
  BYTE_INPUT_DATA kMac,
  BYTE_INPUT_DATA signature,
  ICard* card_ )
{
  CardCommand ExternalAuthenticate_;
  ExternalAuthenticate_ << 0x0C << 0x82 << 0x00 << 0x00;

  // Copy the input.
  std::vector<unsigned char> signature_;
  for (size_t i = 0; i < signature.dataSize; i++)
    signature_.push_back(signature.pData[i]);

  // Build the SM related structures.
  std::vector<unsigned char> do87_ = buildDO87_AES(kEnc, signature_, ssc);
  std::vector<unsigned char> do8E_ = buildDO8E_AES(kMac, ExternalAuthenticate_, do87_, ssc);
 
  // Append LC
  ExternalAuthenticate_.push_back(do87_.size() + do8E_.size());

  // Append DO87 to APDU
  for (size_t i = 0; i < do87_.size(); i++)
    ExternalAuthenticate_.push_back(do87_[i]);

  // Append DO8E to APDU
  for (size_t i = 0; i < do8E_.size(); i++)
    ExternalAuthenticate_.push_back(do8E_[i]);

  // Append the LE byte to the APDU
  if (do87_.size() + do8E_.size() <= 0xFF)
  {
    // Normal APDU
    ExternalAuthenticate_.push_back(0x00);
  }
  else 
  {
    // Extended length APDU
    ExternalAuthenticate_.push_back(0x00);
    ExternalAuthenticate_.push_back(0x00);
  }

  // Do the dirty work.
  CardResult ExternalAuthenticate__Result_ = card_->sendAPDU(ExternalAuthenticate_, "EXTERNAL AUTHENTICATE for signature verification.");
  // Caution! getSW() only checks the last 2 Bytes -> We only check the correctnes of Secure Messaging and not of the Command
  if (ExternalAuthenticate__Result_.getSW() != 0x9000)
    return ECARD_TA_STEP_G_FAILED;

  // Get returned data.
  std::vector<unsigned char> returnedData = ExternalAuthenticate__Result_.getData();

  // Verify the SM response from the card.
  if (!verifyResponse_AES(kMac, returnedData, ssc))
    return ECARD_TA_STEP_G_VERIFY_FAILED;

  return ECARD_SUCCESS;
}

// ---------------------------------------------------------------------------
// Exported functions
// ---------------------------------------------------------------------------

/**
 *
 */
ECARD_STATUS __STDCALL__ ePAPerformTA(
  IN ECARD_HANDLE hCard,
  IN BYTE_INPUT_DATA kEnc,
  IN BYTE_INPUT_DATA kMac,
  IN OUT unsigned long long &ssc,
  IN BYTE_INPUT_DATA efCardAccess,
  IN BYTE_INPUT_DATA carCVCA,
  IN BYTE_INPUT_DATA dvcaCertificate,
  IN BYTE_INPUT_DATA terminalCertificate,
  IN BYTE_INPUT_DATA x_Puk_ICC_DH2,
  IN BYTE_INPUT_DATA x_Puk_IFD_DH_CA,
  IN BYTE_INPUT_DATA authenticatedAuxiliaryData,
  IN OUT BYTE_OUTPUT_DATA& toBeSigned)
{
  ECARD_STATUS status = ECARD_SUCCESS;

  // Check handle ...
  if (0x00 == hCard || ECARD_INVALID_HANDLE_VALUE == hCard)
    return ECARD_INVALID_PARAMETER_1;

  // Try to get ePA card
  ICard* card_ = (ICard*) hCard;
  ePACard* ePA_ = dynamic_cast<ePACard*>(card_);

  // No ePA -> Leave
  if (0x00 == ePA_)
    return ECARD_INVALID_EPA;

  // Parse the EF.CardAccess file to get needed information.
  SecurityInfos	*secInfos_ = 0x00;
  if (ber_decode(0, &asn_DEF_SecurityInfos, (void **)&secInfos_, efCardAccess.pData, efCardAccess.dataSize).code != RC_OK)
  {
    asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
    return ECARD_EFCARDACCESS_PARSER_ERROR;
  }

  OBJECT_IDENTIFIER_t PACE_OID_;
  AlgorithmIdentifier* PACEDomainParameterInfo_ = 0x00;

  for (int i = 0; i < secInfos_->list.count; i++)
  {
    OBJECT_IDENTIFIER_t oid = secInfos_->list.array[i]->protocol;

    { // Find the algorithm for PACE ...
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

    { 
      OBJECT_IDENTIFIER_t oidCheck = makeOID(id_PACE_ECDH);
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

  //assert(0x20 == x_Puk_IFD_DH_CA.dataSize);

  int filler_ = 32 - x_Puk_IFD_DH_CA.dataSize;
  // Copy the x part of the public key for chip authentication. This key was created on the server.
  std::vector<unsigned char> x_Puk_IFD_DH_;
  for (int i = 0; i < filler_; i++)
    x_Puk_IFD_DH_.push_back(0x00);
  for (size_t i = 0; i < x_Puk_IFD_DH_CA.dataSize; i++)
    x_Puk_IFD_DH_.push_back(x_Puk_IFD_DH_CA.pData[i]);

  if (ECARD_SUCCESS != (status = perform_TA_Step_A(carCVCA, ssc, kEnc, kMac, card_)))
  {
    asn_DEF_AlgorithmIdentifier.free_struct(&asn_DEF_AlgorithmIdentifier, PACEDomainParameterInfo_, 0);
    asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
    return status;
  }

  if (ECARD_SUCCESS != (status = perform_TA_Step_B(ssc, kEnc, kMac, dvcaCertificate, card_)))
  {
    asn_DEF_AlgorithmIdentifier.free_struct(&asn_DEF_AlgorithmIdentifier, PACEDomainParameterInfo_, 0);
    asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
    return status;
  }

  std::string carDVCA_ = getCAR(terminalCertificate);
  hexdump("TERM CAR: ", &carDVCA_[0], carDVCA_.size());

  BYTE_INPUT_DATA carDVCA;
  carDVCA.dataSize = carDVCA_.size();
  carDVCA.pData    = (PBYTE) &carDVCA_[0];

  if (ECARD_SUCCESS != (status = perform_TA_Step_C(carDVCA, ssc, kEnc, kMac, card_)))
  {
    asn_DEF_AlgorithmIdentifier.free_struct(&asn_DEF_AlgorithmIdentifier, PACEDomainParameterInfo_, 0);
    asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
    return status;
  }

  if (ECARD_SUCCESS != (status = perform_TA_Step_D(ssc, kEnc, kMac, terminalCertificate, card_)))
  {
    asn_DEF_AlgorithmIdentifier.free_struct(&asn_DEF_AlgorithmIdentifier, PACEDomainParameterInfo_, 0);
    asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
    return status;
  }
  
  std::string chrTerm_ = getCHR(terminalCertificate);
  hexdump("TERM CHR: ", &chrTerm_[0], chrTerm_.size());

  BYTE_INPUT_DATA keyID_;
  keyID_.dataSize = chrTerm_.size();
  keyID_.pData = (PBYTE) &chrTerm_[0];

  //assert(0x20 == x_Puk_IFD_DH_.size());

  BYTE_INPUT_DATA x_Puk_IFD_DH;
  x_Puk_IFD_DH.dataSize = x_Puk_IFD_DH_.size();
  x_Puk_IFD_DH.pData = &x_Puk_IFD_DH_[0];

  if (ECARD_SUCCESS != (status = perform_TA_Step_E(ssc, kEnc, kMac, keyID_, x_Puk_IFD_DH, authenticatedAuxiliaryData, card_)))
  {
    asn_DEF_AlgorithmIdentifier.free_struct(&asn_DEF_AlgorithmIdentifier, PACEDomainParameterInfo_, 0);
    asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
    return status;
  }

  std::vector<unsigned char> RND_ICC_;

  if (ECARD_SUCCESS != (status = perform_TA_Step_F(ssc, kEnc, kMac, RND_ICC_, card_)))
  {
    asn_DEF_AlgorithmIdentifier.free_struct(&asn_DEF_AlgorithmIdentifier, PACEDomainParameterInfo_, 0);
    asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
    return status;
  }
 
  int fillerX1_ = 32 - x_Puk_ICC_DH2.dataSize;
  int fillerX2_ = 32 - x_Puk_IFD_DH_.size();

  // Build up x(PuK.ICC.DH2) || RND.ICC || x(PuK.IFD.DH)
  std::vector<unsigned char> toBeSigned_;
  
  //for (size_t i = 0; i < fillerX1_; i++)
  //  toBeSigned_.push_back(0x00);
  //for (size_t i = 0; i < x_Puk_ICC_DH2.dataSize; i++)
  //  toBeSigned_.push_back(x_Puk_ICC_DH2.pData[i]);

  for (size_t i = 0; i < RND_ICC_.size(); i++)
    toBeSigned_.push_back(RND_ICC_[i]);

  //for (size_t i = 0; i < fillerX2_; i++)
  //  toBeSigned_.push_back(0x00);
  //for (size_t i = 0; i < x_Puk_IFD_DH_.size(); i++)
  //  toBeSigned_.push_back(x_Puk_IFD_DH_[i]);

  assert(0x20 == x_Puk_ICC_DH2.dataSize);
  assert(0x20 == x_Puk_IFD_DH_.size());
  // assert(0x48 == toBeSigned_.size());

  // Copy the data to the output buffer.
  toBeSigned.m_dataSize = toBeSigned_.size();
  toBeSigned.m_pDataBuffer = toBeSigned.m_allocator(toBeSigned_.size());
  memcpy(toBeSigned.m_pDataBuffer, &toBeSigned_[0], toBeSigned_.size());

  asn_DEF_AlgorithmIdentifier.free_struct(&asn_DEF_AlgorithmIdentifier, PACEDomainParameterInfo_, 0);
  asn_DEF_SecurityInfos.free_struct(&asn_DEF_SecurityInfos, secInfos_, 0);
  
  return ECARD_SUCCESS;
}

/*!
 *
 */
ECARD_STATUS __STDCALL__ ePASendSignature(
  IN ECARD_HANDLE hCard,
  IN BYTE_INPUT_DATA kEnc,
  IN BYTE_INPUT_DATA kMac,
  IN OUT unsigned long long &ssc,
  IN BYTE_INPUT_DATA signature)
{
  ECARD_STATUS status = ECARD_SUCCESS;

  // Check handle ...
  if (0x00 == hCard || ECARD_INVALID_HANDLE_VALUE == hCard)
    return ECARD_INVALID_PARAMETER_1;

  // Try to get ePA card
  ICard* card_ = (ICard*) hCard;
  ePACard* ePA_ = dynamic_cast<ePACard*>(card_);

  // No ePA -> Leave
  if (0x00 == ePA_)
    return ECARD_INVALID_EPA;

  if (ECARD_SUCCESS != (status = perform_TA_Step_G(ssc, kEnc, kMac, signature, card_)))
    return status;

  return ECARD_SUCCESS;
}