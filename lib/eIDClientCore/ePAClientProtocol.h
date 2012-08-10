#if !defined(__EPACLIENTPROTOCOL_INCLUDED__)
#define __EPACLIENTPROTOCOL_INCLUDED__

#include <string>
#include <vector>

#include "eCardCore/ICard.h"
#include "eCardCore/eCardStatus.h"
#include "nPA-EAC/nPAAPI.h"

/**
 */
class ePAClientProtocol
{
private:
  /** Handle to a valid ePA card */
  ICard *m_hCard;
  /** X part of Puk_ICC_DH2 after PACE */
  std::vector<unsigned char> m_x_Puk_ICC_DH2;
  /** CAR of the CVCA for TA after PACE */
  std::string m_carCVCA;
  /** Authenticated auxiliary data */
  std::vector<unsigned char> authenticatedAuxiliaryData;

  // No copy
  ePAClientProtocol(
    const ePAClientProtocol&);

  ePAClientProtocol& operator=(
    const ePAClientProtocol&);

public:
  /*!
   * ctor
   *
   * @param hCard Handle to an ePA card
   */
  ePAClientProtocol(
    ICard* hCard);

  ~ePAClientProtocol(
    void);

  /**
   * @brief Perform the PACE protocol.
   */
  ECARD_STATUS PACE(
    const PaceInput& pace_input,
    unsigned char& PINCount);

  /**
   * @brief Perform the terminal authentication.
   *
   * @param dvCertificate The DVCA certificate.
   * @param terminalCertificate The certificate of the terminal.
   * @param toBeSigned The data which will be signed by the eID server.
   */
  ECARD_STATUS TerminalAuthentication(
    std::vector<std::vector<unsigned char> >& list_certificates,
    const std::vector<unsigned char>& terminalCertificate,
    const std::vector<unsigned char>& x_PuK_IFD_DH_CA,
    const std::vector<unsigned char>& authenticatedAuxiliaryData,
    std::vector<unsigned char>& toBeSigned);

  /**
   * @brief Send the signature, created by the eID server, to the chip.
   *
   * @param signature The signature data.
   */
  ECARD_STATUS SendSignature(
    const std::vector<unsigned char>& signature);

  /**
   * @brief Perform the chip authentication.
   */
  ECARD_STATUS ChipAuthentication(
    const std::vector<unsigned char>& x_Puk_IFD_DH,
    const std::vector<unsigned char>& y_Puk_IFD_DH,
    std::vector<unsigned char>& GeneralAuthenticationResult);

  /**
   * @brief Get the IDPICC.
   */
  ECARD_STATUS GetIDPICC(
    std::vector<unsigned char>& idPICC);

  std::string GetCARCVCA() { return m_carCVCA;}
}; // class ePAClientProtocol

#endif
