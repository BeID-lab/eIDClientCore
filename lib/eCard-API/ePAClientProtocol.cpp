#include "eCardCore/eCardStatus.h"
#include "ePAClientProtocol.h"
#include <debug.h>

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
        const PaceInput& pace_input,
        unsigned char& PINCount)
{
  ECARD_STATUS status_ = ECARD_SUCCESS;

  // Setup output variables
  std::vector<unsigned char> car_cvca_;
  std::vector<unsigned char> x_Puk_ICC_DH2_;

  if (!m_hCard)
    return ECARD_ERROR;

  // Try to get ePA card
  Bundesdruckerei::nPA::ePACard& ePA_ = dynamic_cast<Bundesdruckerei::nPA::ePACard&>(*m_hCard);

  // Run the PACE protocol.
  if (ECARD_SUCCESS != (status_ = ePAPerformPACE(ePA_, pace_input,
	  car_cvca_, x_Puk_ICC_DH2_, &PINCount)))
    return status_;

  // Copy the PACE results for further usage.
  m_carCVCA = std::string ( car_cvca_.begin(), car_cvca_.end() );

  m_x_Puk_ICC_DH2 = x_Puk_ICC_DH2_;

  return ECARD_SUCCESS;
}

/**
 */
ECARD_STATUS ePAClientProtocol::TerminalAuthentication(
  std::vector<std::vector<unsigned char> >& list_certificates,
  const std::vector<unsigned char>& terminalCertificate,
  const std::vector<unsigned char>& x_PuK_IFD_DH_CA,
  const std::vector<unsigned char>& authenticatedAuxiliaryData,
  std::vector<unsigned char>& toBeSigned)
{
  std::vector<unsigned char> carCVCA_;
  carCVCA_ = std::vector<unsigned char> ( m_carCVCA.begin(), m_carCVCA.end() );

  std::vector<unsigned char> x_PuK_ICC_DH2_;
  x_PuK_ICC_DH2_ = m_x_Puk_ICC_DH2;

  if (!m_hCard)
    return ECARD_ERROR;

  // Try to get ePA card
  Bundesdruckerei::nPA::ePACard& ePA_ = dynamic_cast<Bundesdruckerei::nPA::ePACard&>(*m_hCard);

  // Do work
  return ePAPerformTA(ePA_, carCVCA_, list_certificates, terminalCertificate,
          x_PuK_IFD_DH_CA, authenticatedAuxiliaryData, toBeSigned);
}

/**
 */
ECARD_STATUS ePAClientProtocol::SendSignature(
  const std::vector<unsigned char>& signature)
{
  if (!m_hCard)
    return ECARD_ERROR;
  return ePASendSignature(*m_hCard, signature);
}

/**
 */
ECARD_STATUS ePAClientProtocol::ChipAuthentication(
  const std::vector<unsigned char>& x_Puk_IFD_DH,
  const std::vector<unsigned char>& y_Puk_IFD_DH,
  std::vector<unsigned char>& GeneralAuthenticationResult)
{
  ECARD_STATUS status_ = ECARD_SUCCESS;

  if (!m_hCard)
    return ECARD_ERROR;

  if (ECARD_SUCCESS != (status_ = ePAPerformCA(*m_hCard, x_Puk_IFD_DH, y_Puk_IFD_DH, GeneralAuthenticationResult)))
    return status_;

  return ECARD_SUCCESS;
}

ECARD_STATUS ePAClientProtocol::GetIDPICC(
  std::vector<unsigned char>& idPICC)
{
  idPICC = m_x_Puk_ICC_DH2;
  
  return ECARD_SUCCESS;
}
