#include "ePAClientProtocol.h"

#include <eCardStatus.h>
#include <nPAAPI.h>

#include <SignedData.h>
#include <ContentInfo.h>
#include <nPAStatus.h>

#include <SecurityInfos.h>
#include <PACEDomainParameterInfo.h>
#include <eIDHelper.h>
#include <eIDOID.h>
#include <ECParameters.h>
#include <debug.h>

ECARD_STATUS __STDCALL__ ePASelectFile(
  IN ECARD_HANDLE hCard,
  IN USHORT fid);

ECARD_STATUS __STDCALL__ ePAGetFileSize(
  IN ECARD_HANDLE hCard,
  IN USHORT fid,
  IN OUT PDWORD dwSize);

ECARD_STATUS __STDCALL__ ePAReadFile(
  IN ECARD_HANDLE hCard,
  IN size_t bytesToRead,
  IN OUT std::vector<unsigned char>& fileContent);

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
  ICard *hCard) : m_hCard(hCard)
{
}

ePAClientProtocol::~ePAClientProtocol(
  void)
{
}

/**
 */
ECARD_STATUS ePAClientProtocol::PACE(
  IN const std::vector<unsigned char>& chat,
  IN const std::vector<unsigned char>& certificate_description,
  IN const std::vector<unsigned char>& password,
  IN KEY_REFERENCE keyReference,
  OUT unsigned char& PINCount)
{
  ECARD_STATUS status_ = ECARD_SUCCESS;

  // Read EF.CardAccess from the chip.
  if (ECARD_SUCCESS != (status_ = read_EF_CardAccess()))
    return status_;

  // Setup input variables
  std::vector<unsigned char> efCardAccess_;
  efCardAccess_ = m_efCardAccess;

  // Setup output variables
  std::vector<unsigned char> car_cvca_;
  std::vector<unsigned char> x_Puk_ICC_DH2_;

  // Run the PACE protocol.
  if (ECARD_SUCCESS != (status_ = ePAPerformPACE(m_hCard, keyReference, chat, certificate_description, password,
	  efCardAccess_, car_cvca_, x_Puk_ICC_DH2_, &PINCount)))
    return status_;

  // Copy the PACE results for further usage.
  m_carCVCA = std::string ( car_cvca_.begin(), car_cvca_.end() );

  m_x_Puk_ICC_DH2 = x_Puk_ICC_DH2_;

  return ECARD_SUCCESS;
}

/**
 */
ECARD_STATUS ePAClientProtocol::TerminalAuthentication(
  IN std::vector<std::vector<unsigned char> >& list_certificates,
  IN const std::vector<unsigned char>& terminalCertificate,
  IN const std::vector<unsigned char>& x_PuK_IFD_DH_CA,
  IN const std::vector<unsigned char>& authenticatedAuxiliaryData,
  IN OUT std::vector<unsigned char>& toBeSigned)
{
  std::vector<unsigned char> carCVCA_;
  carCVCA_ = std::vector<unsigned char> ( m_carCVCA.begin(), m_carCVCA.end() );

  std::vector<unsigned char> efCardAccess_;
  efCardAccess_ = m_efCardAccess;

  std::vector<unsigned char> x_PuK_ICC_DH2_;
  x_PuK_ICC_DH2_ = m_x_Puk_ICC_DH2;
 
  //assert(0x20 == x_PuK_ICC_DH2_.size());

  // Do work
  return ePAPerformTA(m_hCard, efCardAccess_, carCVCA_, list_certificates,
          terminalCertificate, x_PuK_IFD_DH_CA, authenticatedAuxiliaryData,
          toBeSigned);
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
  std::vector<unsigned char> fileDataSmall;
  if (ECARD_SUCCESS != (status_ = ePAReadFile(m_hCard, 4, fileDataSmall)))
    return status_;

  if (fileDataSmall[1] == 0x81)
  {
    fileSize = fileDataSmall[2];
    fileSize += 3;
  }

  if (fileDataSmall[1] == 0x82)
  {
    fileSize = fileDataSmall[2] << 8;
    fileSize += fileDataSmall[3];
    fileSize += 4; 
  }

  // Read the content of EF.CardAccess.
  std::vector<unsigned char> fileData;
  if (ECARD_SUCCESS != (status_ = ePAReadFile(m_hCard, fileSize, fileData)))
    return status_;

  // May check the data size and resize the buffer!!!

  // Copy the content for further usage.
  m_efCardAccess = fileData; 

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
  std::vector<unsigned char> fileData;
  if (ECARD_SUCCESS != (status_ = ePAReadFile(m_hCard, fileSize, fileData)))
    return status_;

  // Copy the content for further usage.
  m_efCardAccess = fileData; 

  return ECARD_SUCCESS;
}

/**
 */
ECARD_STATUS ePAClientProtocol::read_EF_CardSecurity(
  void)
{
  ECARD_STATUS status_ = ECARD_SUCCESS;

  // Query the size of EF.CardSecurity. The selction of the file is implicid here. So we
  // have no SELCT on EF.CardSecurity before.
  DWORD fileSize = 0;
  if (ECARD_SUCCESS != (status_ = ePAGetFileSize(m_hCard, 0x011D, &fileSize)))
    return status_;

  // Read the content of EF.CardSecurity.
  std::vector<unsigned char> fileData;
  fileData.reserve(0xffff);
  if (ECARD_SUCCESS != (status_ = ePAReadFile(m_hCard, fileSize, fileData)))
    return status_;

  // Copy the content for further usage.
  m_efCardSecurity = fileData; 

  return ECARD_SUCCESS;
}

/**
 */
ECARD_STATUS ePAClientProtocol::SendSignature(
  IN const std::vector<unsigned char>& signature)
{
  return ePASendSignature(m_hCard, signature);
}

/**
 */
ECARD_STATUS ePAClientProtocol::ChipAuthentication(
  IN const std::vector<unsigned char>& x_Puk_IFD_DH,
  IN const std::vector<unsigned char>& y_Puk_IFD_DH,
  IN OUT std::vector<unsigned char>& GeneralAuthenticationResult)
{
  ECARD_STATUS status_ = ECARD_SUCCESS;

  //assert(0x20 == x_Puk_IFD_DH.size());
  //assert(0x20 == y_Puk_IFD_DH.size());

  // Read EF.CardAccess from the chip.
  if (ECARD_SUCCESS != (status_ = read_EF_CardSecurity()))
    return status_;

  if (ECARD_SUCCESS != (status_ = ePAPerformCA(m_hCard, x_Puk_IFD_DH, y_Puk_IFD_DH, GeneralAuthenticationResult)))
    return status_;

  return ECARD_SUCCESS;
}

/**
 */
ECARD_STATUS ePAClientProtocol::GetEFCardAccess(
  IN OUT std::vector<unsigned char>& efCardAccess)
{
  efCardAccess = m_efCardAccess;
  
  return ECARD_SUCCESS;
}

/**
 */
ECARD_STATUS ePAClientProtocol::GetEFCardSecurity(
  IN OUT std::vector<unsigned char>& efCardSecurity)
{
  efCardSecurity = m_efCardSecurity;
  
  return ECARD_SUCCESS;
}

ECARD_STATUS ePAClientProtocol::GetIDPICC(
  IN OUT std::vector<unsigned char>& idPICC)
{
  idPICC = m_x_Puk_ICC_DH2;
  
  return ECARD_SUCCESS;
}
