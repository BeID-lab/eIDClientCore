#if !defined(__EPACLIENTPROTOCOL_INCLUDED__)
#define __EPACLIENTPROTOCOL_INCLUDED__

#include <eCardTypes.h>
#include <eCardStatus.h>
#include <ePAAPI.h>

#include <vector>
#include <string>

/**
 */
class ePAClientProtocol
{
private:
  /** Handle to a valid ePA card */
  ECARD_HANDLE m_hCard;
  /** Encryption key for secure messaging after PACE */
  std::vector<unsigned char> m_kEnc;
  /** Message authentication code (MAC) key for secure messaging after PACE */
  std::vector<unsigned char> m_kMac;
  /** Content of EF.CardAccess */
  std::vector<unsigned char> m_efCardAccess;
  /** Content of EF.CardSecurity */
  std::vector<unsigned char> m_efCardSecurity;
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
    IN ECARD_HANDLE hCard);

  ~ePAClientProtocol(
    void);

  /**
   * @brief Perform the PACE protocol.
   *
   * @param chat The CHAT selected by the user.
   * @param password The password provided by the user.
   * @param keyReference 
   */
  ECARD_STATUS PACE(
    IN const std::vector<unsigned char>& chat,
    IN const std::vector<unsigned char>& certificate_description,
    IN const std::vector<unsigned char>& password,
    IN KEY_REFERENCE keyReference,
    OUT unsigned char& PINCount);

  /**
   * @brief Perform the terminal authentication.
   *
   * @param dvCertificate The DVCA certificate.
   * @param terminalCertificate The certificate of the terminal.
   * @param toBeSigned The data which will be signed by the eID server.
   */
  ECARD_STATUS TerminalAuthentication(
    IN std::vector<std::vector<unsigned char> >& list_certificates,
    IN const std::vector<unsigned char>& terminalCertificate,
    IN const std::vector<unsigned char>& x_PuK_IFD_DH_CA,
    IN const std::vector<unsigned char>& authenticatedAuxiliaryData,
    IN OUT std::vector<unsigned char>& toBeSigned);

  /**
   * @brief Send the signature, created by the eID server, to the chip.
   *
   * @param signature The signature data.
   */
  ECARD_STATUS SendSignature(
    IN const std::vector<unsigned char>& signature);

  /**
   * @brief Perform the chip authentication.
   */
  ECARD_STATUS ChipAuthentication(
    IN const std::vector<unsigned char>& x_Puk_IFD_DH,
    IN const std::vector<unsigned char>& y_Puk_IFD_DH,
    IN OUT std::vector<unsigned char>& GeneralAuthenticationResult);

  /**
   * @brief Get the PACE domain parameter info from EF.CardAccess.
   */
//  ECARD_STATUS GetPACEDomainParamter(
//    IN OUT std::vector<unsigned char>& pacedp);

  /**
   * @brief Get the EF.CardAccess.
   */
  ECARD_STATUS GetEFCardAccess(
    IN OUT std::vector<unsigned char>& efCardAccess);

  /**
   * @brief Get the EF.CardSecurity.
   */
  ECARD_STATUS GetEFCardSecurity(
  IN OUT std::vector<unsigned char>& efCardSecurity);

  /**
   * @brief Get the IDPICC.
   */
  ECARD_STATUS GetIDPICC(
    IN OUT std::vector<unsigned char>& idPICC);

  std::string GetCARCVCA() { return m_carCVCA;}

  /**
   * @brief change PIN
   */
//  ECARD_STATUS ChangePIN(
//    IN const std::vector<unsigned char>& pin);

  /**
   * @brief reset retry counter PIN
   */
//  ECARD_STATUS ResetRetryCounterPIN();

private:
  /**
   * @brief Read the content of EF.CardAccess.
   */
  ECARD_STATUS read_EF_CardAccess(
    void);

  /**
   * @brief Read the content of EF.CardSecurity.
   */
  ECARD_STATUS read_EF_CardSecurity(
    void);

  /**
   * @brief Read the content of EF.ChipSecurity.
   */
  ECARD_STATUS read_EF_ChipSecurity(
    void);
}; // class ePAClientProtocol

/**
 */
extern "C" unsigned char* ePAClientProtocol_allocator(
  size_t size);

/**
 */
extern "C" void ePAClientProtocol_deallocator(
  unsigned char* data);

#endif
