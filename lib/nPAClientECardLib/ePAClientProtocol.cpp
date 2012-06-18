#include "ePAClientProtocol.h"

#include <eCardStatus.h>
#include <ePAAPI.h>

#include <SignedData.h>
#include <ContentInfo.h>
#include <ePAStatus.h>

#include <SecurityInfos.h>
#include <PACEDomainParameterInfo.h>
#include <eIDHelper.h>
#include <eIDOID.h>
#include <ECParameters.h>

ECARD_STATUS __STDCALL__ ePASelectFile(
  IN ECARD_HANDLE hCard,
  IN USHORT fid);

ECARD_STATUS __STDCALL__ ePAGetFileSize(
  IN ECARD_HANDLE hCard,
  IN USHORT fid,
  IN OUT PDWORD dwSize);

ECARD_STATUS __STDCALL__ ePAGetFileSize(
  IN ECARD_HANDLE hCard,
  IN USHORT fid,
  IN BYTE_INPUT_DATA& kEnc,
  IN BYTE_INPUT_DATA& kMac,
  IN unsigned long long& ssc,
  IN OUT PDWORD dwSize);

ECARD_STATUS __STDCALL__ ePAReadFile(
  IN ECARD_HANDLE hCard,
  IN size_t bytesToRead,
  IN OUT BYTE_OUTPUT_DATA& fileContent);

ECARD_STATUS __STDCALL__ ePAReadFile(
  IN ECARD_HANDLE hCard,
  IN BYTE_INPUT_DATA& kEnc,
  IN BYTE_INPUT_DATA& kMac,
  IN unsigned long long& ssc,
  IN size_t bytesToRead,
  IN OUT BYTE_OUTPUT_DATA& fileContent);

/**
 */
extern "C" unsigned char* ePAClientProtocol_allocator(
  size_t size)
{
  return new unsigned char[size];
}

/**
 */
extern "C" void ePAClientProtocol_deallocator(
  unsigned char* data)
{
  delete [] data;
}

/**
 */
ePAClientProtocol::ePAClientProtocol(
  ECARD_HANDLE hCard) : m_hCard(hCard), m_SendSequenceCounter(0)
{
}

ePAClientProtocol::~ePAClientProtocol(
  void)
{
}

/**
 */
ECARD_STATUS ePAClientProtocol::PACE(
  IN const BYTE_INPUT_DATA& chat,
  IN const BYTE_INPUT_DATA& certificate_description,
  IN const BYTE_INPUT_DATA& password,
  IN KEY_REFERENCE keyReference,
  OUT unsigned char& PINCount)
{
  ECARD_STATUS status_ = ECARD_SUCCESS;

  // Read EF.CardAccess from the chip.
  if (ECARD_SUCCESS != (status_ = read_EF_CardAccess()))
    return status_;

  // Setup input variables
  BYTE_INPUT_DATA efCardAccess_;
  efCardAccess_.dataSize = m_efCardAccess.size();
  efCardAccess_.pData = &m_efCardAccess[0];

  // Setup output variables
  BYTE_OUTPUT_DATA kMac_(&ePAClientProtocol_allocator, &ePAClientProtocol_deallocator);
  BYTE_OUTPUT_DATA kEnc_(&ePAClientProtocol_allocator, &ePAClientProtocol_deallocator);
  BYTE_OUTPUT_DATA car_cvca_(&ePAClientProtocol_allocator, &ePAClientProtocol_deallocator);
  BYTE_OUTPUT_DATA x_Puk_ICC_DH2_(&ePAClientProtocol_allocator, &ePAClientProtocol_deallocator);
   
  // Run the PACE protocol.
  if (ECARD_SUCCESS != (status_ = ePAPerformPACE(m_hCard, keyReference, chat, certificate_description, password,
	  efCardAccess_, kMac_, kEnc_, car_cvca_, x_Puk_ICC_DH2_, &PINCount)))
    return status_;

  // Copy the PACE results for further usage.
  for (size_t i = 0; i < kMac_.m_dataSize; i++)
    m_kMac.push_back(kMac_.m_pDataBuffer[i]);

  for (size_t i = 0; i < kEnc_.m_dataSize; i++)
    m_kEnc.push_back(kEnc_.m_pDataBuffer[i]);

  for (size_t i = 0; i < car_cvca_.m_dataSize; i++)
    m_carCVCA.push_back(car_cvca_.m_pDataBuffer[i]);

  // try to pad this to 20 bytes TODO remove
  if (x_Puk_ICC_DH2_.m_dataSize < 0x20) 
  {
	for (size_t i = 0; i < 20 - x_Puk_ICC_DH2_.m_dataSize; i++)
	  m_x_Puk_ICC_DH2.push_back(0x00);
  }

  for (size_t i = 0; i < x_Puk_ICC_DH2_.m_dataSize; i++)
    m_x_Puk_ICC_DH2.push_back(x_Puk_ICC_DH2_.m_pDataBuffer[i]);

  return ECARD_SUCCESS;
}

/**
 */
ECARD_STATUS ePAClientProtocol::TerminalAuthentication(
  IN const BYTE_INPUT_DATA& dvCertificate,
  IN const BYTE_INPUT_DATA& terminalCertificate,
  IN const BYTE_INPUT_DATA& x_PuK_IFD_DH_CA,
  IN const BYTE_INPUT_DATA& authenticatedAuxiliaryData,
  IN OUT BYTE_OUTPUT_DATA& toBeSigned)
{
  // Setup input variables
  BYTE_INPUT_DATA kEnc_;
  kEnc_.dataSize = m_kEnc.size();
  kEnc_.pData = &m_kEnc[0];

  BYTE_INPUT_DATA kMac_;
  kMac_.dataSize = m_kMac.size();
  kMac_.pData = &m_kMac[0];

  BYTE_INPUT_DATA carCVCA_;
  carCVCA_.dataSize = m_carCVCA.size();
  carCVCA_.pData = (BYTE*) &m_carCVCA[0];

  BYTE_INPUT_DATA efCardAccess_;
  efCardAccess_.dataSize = m_efCardAccess.size();
  efCardAccess_.pData = &m_efCardAccess[0];

  BYTE_INPUT_DATA x_PuK_ICC_DH2_;
  x_PuK_ICC_DH2_.dataSize = m_x_Puk_ICC_DH2.size();
  x_PuK_ICC_DH2_.pData = &m_x_Puk_ICC_DH2[0];
 
  //assert(0x20 == x_PuK_ICC_DH2_.dataSize);

  // Do work
  ECARD_STATUS status_ = ECARD_SUCCESS;
  if (ECARD_SUCCESS != (status_ = ePAPerformTA(m_hCard, kEnc_, kMac_, m_SendSequenceCounter, efCardAccess_, 
    carCVCA_, dvCertificate, terminalCertificate, x_PuK_ICC_DH2_, x_PuK_IFD_DH_CA, authenticatedAuxiliaryData, toBeSigned)))
    return status_;

  return ECARD_SUCCESS;
}

/**
 */
ECARD_STATUS ePAClientProtocol::read_EF_CardAccess(
  void)
{
  ECARD_STATUS status_ = ECARD_SUCCESS;

  // Select the MF
  if (ECARD_SUCCESS != (status_ = ePASelectFile(m_hCard, 0x3F00)))
    return status_;

  // Select the EF.CardAccess
  if (ECARD_SUCCESS != (status_ = ePASelectFile(m_hCard, 0x011C)))
    return status_;

  // Query the size of EF.CardAccess. The selction of the file is implicid here. So we
  // have no SELCT on EF.CardAccess before.
  DWORD fileSize = 0;
  //if (ECARD_SUCCESS != (status_ = ePAGetFileSize(m_hCard, 0x011C, &fileSize)))
  //  return status_;
 
  // Read the content of EF.CardAccess.
  BYTE_OUTPUT_DATA fileDataSmall(&ePAClientProtocol_allocator, &ePAClientProtocol_deallocator);
  if (ECARD_SUCCESS != (status_ = ePAReadFile(m_hCard, 4, fileDataSmall)))
    return status_;

  if (fileDataSmall.m_pDataBuffer[1] == 0x81)
  {
    fileSize = fileDataSmall.m_pDataBuffer[2];
    fileSize += 3;
  }

  if (fileDataSmall.m_pDataBuffer[1] == 0x82)
  {
    fileSize = fileDataSmall.m_pDataBuffer[2] << 8;
    fileSize += fileDataSmall.m_pDataBuffer[3];
    fileSize += 4; 
  }

  // Read the content of EF.CardAccess.
  BYTE_OUTPUT_DATA fileData(&ePAClientProtocol_allocator, &ePAClientProtocol_deallocator);
  if (ECARD_SUCCESS != (status_ = ePAReadFile(m_hCard, fileSize, fileData)))
    return status_;

  // May check the data size and resize the buffer!!!

  // Copy the content for further usage.
  for (size_t i = 0 ; i < fileData.m_dataSize; i++)
    m_efCardAccess.push_back(fileData.m_pDataBuffer[i]); 

  return ECARD_SUCCESS;
}

/**
 */
ECARD_STATUS ePAClientProtocol::read_EF_ChipSecurity(
  void)
{
  ECARD_STATUS status_ = ECARD_SUCCESS;

  // Select the MF
  if (ECARD_SUCCESS != (status_ = ePASelectFile(m_hCard, 0x3F00)))
    return status_;

  // Query the size of EF.CardAccess. The selction of the file is implicid here. So we
  // have no SELCT on EF.CardAccess before.
  DWORD fileSize = 0;
  if (ECARD_SUCCESS != (status_ = ePAGetFileSize(m_hCard, 0x011B, &fileSize)))
    return status_;

  // Read the content of EF.CardAccess.
  BYTE_OUTPUT_DATA fileData(&ePAClientProtocol_allocator, &ePAClientProtocol_deallocator);
  if (ECARD_SUCCESS != (status_ = ePAReadFile(m_hCard, fileSize, fileData)))
    return status_;

  // Copy the content for further usage.
  for (size_t i = 0 ; i < fileData.m_dataSize; i++)
    m_efCardAccess.push_back(fileData.m_pDataBuffer[i]); 

  return ECARD_SUCCESS;
}

/**
 */
ECARD_STATUS ePAClientProtocol::read_EF_CardSecurity(
  void)
{
  ECARD_STATUS status_ = ECARD_SUCCESS;

  BYTE_INPUT_DATA kEnc_;
  kEnc_.dataSize = m_kEnc.size();
  kEnc_.pData = &m_kEnc[0];

  BYTE_INPUT_DATA kMac_;
  kMac_.dataSize = m_kMac.size();
  kMac_.pData = &m_kMac[0];

  // Query the size of EF.CardSecurity. The selction of the file is implicid here. So we
  // have no SELCT on EF.CardSecurity before.
  DWORD fileSize = 0;
  if (ECARD_SUCCESS != (status_ = ePAGetFileSize(m_hCard, 0x011D, kEnc_, kMac_, m_SendSequenceCounter, &fileSize)))
    return status_;

  // Read the content of EF.CardSecurity.
  BYTE_OUTPUT_DATA fileData(&ePAClientProtocol_allocator, &ePAClientProtocol_deallocator);
  if (ECARD_SUCCESS != (status_ = ePAReadFile(m_hCard, kEnc_, kMac_, m_SendSequenceCounter, fileSize, fileData)))
    return status_;

  // Copy the content for further usage.
  for (size_t i = 0 ; i < fileData.m_dataSize; i++)
    m_efCardSecurity.push_back(fileData.m_pDataBuffer[i]); 

  return ECARD_SUCCESS;
}

/**
 */
ECARD_STATUS ePAClientProtocol::SendSignature(
  IN const BYTE_INPUT_DATA& signature)
{
  // Setup input variables
  BYTE_INPUT_DATA kEnc_;
  kEnc_.dataSize = m_kEnc.size();
  kEnc_.pData = &m_kEnc[0];

  BYTE_INPUT_DATA kMac_;
  kMac_.dataSize = m_kMac.size();
  kMac_.pData = &m_kMac[0];

  return ePASendSignature(m_hCard, kEnc_, kMac_, m_SendSequenceCounter, signature);
}

/**
 */
ECARD_STATUS ePAClientProtocol::ChipAuthentication(
  IN const BYTE_INPUT_DATA& x_Puk_IFD_DH,
  IN const BYTE_INPUT_DATA& y_Puk_IFD_DH,
  IN OUT BYTE_OUTPUT_DATA& GeneralAuthenticationResult)
{
  ECARD_STATUS status_ = ECARD_SUCCESS;

  //assert(0x20 == x_Puk_IFD_DH.dataSize);
  //assert(0x20 == y_Puk_IFD_DH.dataSize);

  // Read EF.CardAccess from the chip.
  if (ECARD_SUCCESS != (status_ = read_EF_CardSecurity()))
    return status_;

  // Setup input variables
  BYTE_INPUT_DATA kEnc_;
  kEnc_.dataSize = m_kEnc.size();
  kEnc_.pData = &m_kEnc[0];

  BYTE_INPUT_DATA kMac_;
  kMac_.dataSize = m_kMac.size();
  kMac_.pData = &m_kMac[0];

  if (ECARD_SUCCESS != (status_ = ePAPerformCA(m_hCard, kEnc_, kMac_, m_SendSequenceCounter, x_Puk_IFD_DH, y_Puk_IFD_DH, GeneralAuthenticationResult)))
    return status_;

  return ECARD_SUCCESS;
}

/**
 */
ECARD_STATUS ePAClientProtocol::GetEFCardAccess(
  IN OUT BYTE_OUTPUT_DATA& efCardAccess)
{
  efCardAccess.m_dataSize = m_efCardAccess.size();
  efCardAccess.m_pDataBuffer = efCardAccess.m_allocator(m_efCardAccess.size());
  memcpy(efCardAccess.m_pDataBuffer, &m_efCardAccess[0], m_efCardAccess.size());        
  
  return ECARD_SUCCESS;
}

/**
 */
ECARD_STATUS ePAClientProtocol::GetEFCardSecurity(
  IN OUT BYTE_OUTPUT_DATA& efCardSecurity)
{
  efCardSecurity.m_dataSize = m_efCardSecurity.size();
  efCardSecurity.m_pDataBuffer = efCardSecurity.m_allocator(m_efCardSecurity.size());
  memcpy(efCardSecurity.m_pDataBuffer, &m_efCardSecurity[0], m_efCardSecurity.size());        
  
  return ECARD_SUCCESS;
}

/**
 */
ECARD_STATUS ePAClientProtocol::GetIDPICC(
  IN OUT BYTE_OUTPUT_DATA& idPICC)
{
  idPICC.m_dataSize = m_x_Puk_ICC_DH2.size();
  idPICC.m_pDataBuffer = idPICC.m_allocator(m_x_Puk_ICC_DH2.size());
  memcpy(idPICC.m_pDataBuffer, &m_x_Puk_ICC_DH2[0], m_x_Puk_ICC_DH2.size());        
  
  return ECARD_SUCCESS;
}

/**
 */
/*ECARD_STATUS ePAClientProtocol::ChangePIN(
    IN const BYTE_INPUT_DATA& pin)
{
  // Setup input variables
  BYTE_INPUT_DATA kEnc_;
  kEnc_.dataSize = m_kEnc.size();
  kEnc_.pData = &m_kEnc[0];

  BYTE_INPUT_DATA kMac_;
  kMac_.dataSize = m_kMac.size();
  kMac_.pData = &m_kMac[0];

  ECARD_STATUS status_ = ECARD_SUCCESS;
  if (ECARD_SUCCESS != (status_ = ePAChangePIN(m_hCard, kEnc_, kMac_, m_SendSequenceCounter, pin)))
    return status_;

  return ECARD_SUCCESS;
}

ECARD_STATUS ePAClientProtocol::ResetRetryCounterPIN()
{
  // Setup input variables
  BYTE_INPUT_DATA kEnc_;
  kEnc_.dataSize = m_kEnc.size();
  kEnc_.pData = &m_kEnc[0];

  BYTE_INPUT_DATA kMac_;
  kMac_.dataSize = m_kMac.size();
  kMac_.pData = &m_kMac[0];

  ECARD_STATUS status_ = ECARD_SUCCESS;
  if (ECARD_SUCCESS != (status_ = ePAResetRetryCounterPIN(m_hCard, kEnc_, kMac_, m_SendSequenceCounter)))
    return status_;

  return ECARD_SUCCESS;
}
*/
