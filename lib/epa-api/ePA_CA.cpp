#include "ePAAPI.h"
#include "ePAStatus.h"
#include "ePACard.h"
#include <debug.h>
using namespace Bundesdruckerei::nPA;                                           

#include <ePACommon.h>

/**
 */ 
ECARD_STATUS __STDCALL__ perform_CA_Step_B( 
  ePACard* ePA_ ) 
{
  MSE mse = MSE(MSE::P1_SET|MSE::P1_COMPUTE, MSE::P2_AT);

  // Build up command data field
  std::vector<unsigned char> dataPart_;
  dataPart_.push_back(0x80); dataPart_.push_back(0x0A);
  dataPart_.push_back(0x04); dataPart_.push_back(0x00);
  dataPart_.push_back(0x7F); dataPart_.push_back(0x00);
  dataPart_.push_back(0x07); dataPart_.push_back(0x02);
  dataPart_.push_back(0x02); dataPart_.push_back(0x03);
  dataPart_.push_back(0x02); dataPart_.push_back(0x02); // This is id_CA_ECDH_AES_CBC_CMAC_128

  mse.setData(dataPart_);

  eCardCore_info(DEBUG_LEVEL_CRYPTO, "Send MANAGE SECURITY ENVIRONMENT to set cryptographic algorithm for CA.");

  // Do the dirty work.
  RAPDU MseSetAT_Result_ = ePA_->sendAPDU(mse);
  if (MseSetAT_Result_.getSW() != 0x9000)
      return ECARD_CA_STEP_B_FAILED;

  return ECARD_SUCCESS;
}

/**
 */
ECARD_STATUS __STDCALL__ perform_CA_Step_C( 
  IN ePACard* ePA_,
  IN const std::vector<unsigned char>& x_Puk_IFD_DH,
  IN const std::vector<unsigned char>& y_Puk_IFD_DH,
  IN OUT std::vector<unsigned char>& GeneralAuthenticationResult) 
{
  GeneralAuthenticate authenticate = GeneralAuthenticate(
          GeneralAuthenticate::P1_NO_INFO, GeneralAuthenticate::P2_NO_INFO);
  authenticate.setNe(CAPDU::DATA_SHORT_MAX);

  int fillerX_ = 32 - x_Puk_IFD_DH.size();
  int fillerY_ = 32 - y_Puk_IFD_DH.size();

  std::vector<unsigned char> dataPart_;
  // '7C' || L7C || '80' || L80 || ('04' || x(PuK.IFD.DH) || y(PuK.IFD.DH))
  dataPart_.push_back(0x7C);
  dataPart_.push_back((x_Puk_IFD_DH.size() + fillerX_ + y_Puk_IFD_DH.size() + fillerY_) + 3);
  dataPart_.push_back(0x80);
  dataPart_.push_back((x_Puk_IFD_DH.size() + fillerX_ + y_Puk_IFD_DH.size() + fillerY_) + 1);
  dataPart_.push_back(0x04);

  for (int i = 0; i < fillerX_; i++)
    dataPart_.push_back(0x00);

  for (size_t i = 0; i < x_Puk_IFD_DH.size(); i++)
    dataPart_.push_back(x_Puk_IFD_DH[i]);

  for (int i = 0; i < fillerY_; i++)
    dataPart_.push_back(0x00);

  for (size_t i = 0; i < y_Puk_IFD_DH.size(); i++)
    dataPart_.push_back(y_Puk_IFD_DH[i]);

  authenticate.setData(dataPart_);

  eCardCore_info(DEBUG_LEVEL_CRYPTO, "Send GENERAL AUTHENTICATE for key agreement.");

  // Do the dirty work.
  RAPDU GenralAuthenticate_Result_ = ePA_->sendAPDU(authenticate);
  if (GenralAuthenticate_Result_.getSW() != 0x9000)
    return ECARD_CA_STEP_B_FAILED;

  // Get returned data.
  std::vector<unsigned char> result = GenralAuthenticate_Result_.getData();

  GeneralAuthenticationResult = result;

  return ECARD_SUCCESS;
}

/**
 */
ECARD_STATUS __STDCALL__ ePAPerformCA(
  IN ECARD_HANDLE hCard,
  IN const std::vector<unsigned char>& x_Puk_IFD_DH,
  IN const std::vector<unsigned char>& y_Puk_IFD_DH,
  IN OUT std::vector<unsigned char>& GeneralAuthenticationResult)
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
  
  if (ECARD_SUCCESS !=  (status_ = perform_CA_Step_B(ePA_)))
    return status_;

  if (ECARD_SUCCESS !=  (status_ = perform_CA_Step_C(ePA_, x_Puk_IFD_DH, y_Puk_IFD_DH, GeneralAuthenticationResult)))
    return status_;

  return ECARD_SUCCESS;
}
