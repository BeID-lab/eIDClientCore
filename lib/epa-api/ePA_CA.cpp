#include "ePAAPI.h"
#include "ePAStatus.h"
#include "ePACard.h"
using namespace Bundesdruckerei::nPA;                                           

#include <ePACommon.h>

/**
 */ 
ECARD_STATUS __STDCALL__ perform_CA_Step_B( 
  BYTE_INPUT_DATA kEnc,
  BYTE_INPUT_DATA kMac, 
  unsigned long long& ssc, 
  ePACard* ePA_ ) 
{
  CardCommand MseSetAT_;
  MseSetAT_ << 0x0C << 0x22 << 0x41 << 0xA4;

  // Build up command data field
  std::vector<unsigned char> dataPart_;
  dataPart_.push_back(0x80); dataPart_.push_back(0x0A);
  dataPart_.push_back(0x04); dataPart_.push_back(0x00);
  dataPart_.push_back(0x7F); dataPart_.push_back(0x00);
  dataPart_.push_back(0x07); dataPart_.push_back(0x02);
  dataPart_.push_back(0x02); dataPart_.push_back(0x03);
  dataPart_.push_back(0x02); dataPart_.push_back(0x02); // This is id_CA_ECDH_AES_CBC_CMAC_128

  // Build the SM related structures.
  std::vector<unsigned char> do87_ = buildDO87_AES(kEnc, dataPart_, ssc);
  std::vector<unsigned char> do8E_ = buildDO8E_AES(kMac, MseSetAT_, do87_, ssc);

  // Append LC
  MseSetAT_.push_back(do87_.size() + do8E_.size());

  // Append DO87 to APDU
  for (size_t i = 0; i < do87_.size(); i++)
    MseSetAT_.push_back(do87_[i]);

  // Append DO8E to APDU
  for (size_t i = 0; i < do8E_.size(); i++)
    MseSetAT_.push_back(do8E_[i]); 

  MseSetAT_.push_back(0x00);

  // Do the dirty work.
  CardResult MseSetAT_Result_ = ePA_->sendAPDU(MseSetAT_, "Send MANAGE SECURITY ENVIRONMENT to set cryptographic algorithm for CA.");
  if (MseSetAT_Result_.getSW() != 0x9000)
    return ECARD_CA_STEP_B_FAILED;

  // Get returned data.
  std::vector<unsigned char> returnedData = MseSetAT_Result_.getData();

  // Verify the SM response from the card.
  if (!verifyResponse_AES(kMac, returnedData, ssc))
    return ECARD_CA_STEP_B_VERIFY_FAILED;

  return ECARD_SUCCESS;
}

/**
 */
ECARD_STATUS __STDCALL__ perform_CA_Step_C( 
  IN BYTE_INPUT_DATA kEnc,
  IN BYTE_INPUT_DATA kMac, 
  IN OUT unsigned long long& ssc, 
  IN ePACard* ePA_,
  IN BYTE_INPUT_DATA x_Puk_IFD_DH,
  IN BYTE_INPUT_DATA y_Puk_IFD_DH,
  IN OUT BYTE_OUTPUT_DATA& GeneralAuthenticationResult) 
{
  CardCommand GenralAuthenticate_;
  GenralAuthenticate_ << 0x0C << 0x86 << 0x00 << 0x00;

  int fillerX_ = 32 - x_Puk_IFD_DH.dataSize;
  int fillerY_ = 32 - y_Puk_IFD_DH.dataSize;

  std::vector<unsigned char> dataPart_;
  // '7C' || L7C || '80' || L80 || ('04' || x(PuK.IFD.DH) || y(PuK.IFD.DH))
  dataPart_.push_back(0x7C);
  dataPart_.push_back((x_Puk_IFD_DH.dataSize + fillerX_ + y_Puk_IFD_DH.dataSize + fillerY_) + 3);
  dataPart_.push_back(0x80);
  dataPart_.push_back((x_Puk_IFD_DH.dataSize + fillerX_ + y_Puk_IFD_DH.dataSize + fillerY_) + 1);
  dataPart_.push_back(0x04);

  for (size_t i = 0; i < fillerX_; i++)
    dataPart_.push_back(0x00);

  for (size_t i = 0; i < x_Puk_IFD_DH.dataSize; i++)
    dataPart_.push_back(x_Puk_IFD_DH.pData[i]);

  for (size_t i = 0; i < fillerY_; i++)
    dataPart_.push_back(0x00);

  for (size_t i = 0; i < y_Puk_IFD_DH.dataSize; i++)
    dataPart_.push_back(y_Puk_IFD_DH.pData[i]);


  // Build the SM related structures.
  std::vector<unsigned char> do97_;
  do97_.push_back(0x97); do97_.push_back(0x01); do97_.push_back(0x00);
  std::vector<unsigned char> do87_ = buildDO87_AES(kEnc, dataPart_, ssc);
  std::vector<unsigned char> do8E_ = buildDO8E_AES(kMac, GenralAuthenticate_, do87_, do97_, ssc);
  
  // Append LC
  GenralAuthenticate_.push_back(do87_.size() + do8E_.size() + do97_.size());

  // Append DO87 to APDU
  for (size_t i = 0; i < do87_.size(); i++)
    GenralAuthenticate_.push_back(do87_[i]);

  // Append DO97 to APDU
  for (size_t i = 0; i < do97_.size(); i++)
    GenralAuthenticate_.push_back(do97_[i]);

  // Append DO8E to APDU
  for (size_t i = 0; i < do8E_.size(); i++)
    GenralAuthenticate_.push_back(do8E_[i]); 

  GenralAuthenticate_.push_back(0x00);

  // Do the dirty work.
  CardResult GenralAuthenticate_Result_ = ePA_->sendAPDU(GenralAuthenticate_, "Send GENERAL AUTHENTICATE for key agreement.");
  if (GenralAuthenticate_Result_.getSW() != 0x9000)
    return ECARD_CA_STEP_B_FAILED;

  // Get returned data.
  std::vector<unsigned char> returnedData = GenralAuthenticate_Result_.getData();

  // Verify the SM response from the card.
  if (!verifyResponse_AES(kMac, returnedData, ssc))
    return ECARD_CA_STEP_B_VERIFY_FAILED;

  std::vector<unsigned char> decryptedDataPart = decryptResponse_AES(kEnc, returnedData, ssc);
  hexdump("###-> Decrypted response (GENERAL AUTHENTICATE): ", &decryptedDataPart[0], decryptedDataPart.size());

  GeneralAuthenticationResult.m_dataSize = decryptedDataPart.size();
  GeneralAuthenticationResult.m_pDataBuffer = GeneralAuthenticationResult.m_allocator(decryptedDataPart.size());
  memcpy(GeneralAuthenticationResult.m_pDataBuffer, &decryptedDataPart[0], decryptedDataPart.size());

  return ECARD_SUCCESS;
}

/**
 */
ECARD_STATUS __STDCALL__ ePAPerformCA(
  IN ECARD_HANDLE hCard,
  IN BYTE_INPUT_DATA kEnc,
  IN BYTE_INPUT_DATA kMac,
  IN OUT unsigned long long &ssc,
  IN BYTE_INPUT_DATA x_Puk_IFD_DH,
  IN BYTE_INPUT_DATA y_Puk_IFD_DH,
  IN OUT BYTE_OUTPUT_DATA& GeneralAuthenticationResult)
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

  ECARD_STATUS status_ = ECARD_SUCCESS; 
  
  if (ECARD_SUCCESS !=  (status_ = perform_CA_Step_B(kEnc, kMac, ssc, ePA_)))
    return status_;

  if (ECARD_SUCCESS !=  (status_ = perform_CA_Step_C(kEnc, kMac, ssc, ePA_, x_Puk_IFD_DH, y_Puk_IFD_DH, GeneralAuthenticationResult)))
    return status_;

  return ECARD_SUCCESS;
}
