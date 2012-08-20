// ---------------------------------------------------------------------------
// Copyright (c) 2010 Bundesdruckerei GmbH
// All rights reserved.
//
// $Id: nPAClient.cpp 775 2010-06-22 07:37:38Z dietrfra $
// ---------------------------------------------------------------------------

#include "nPAClient.h"
using namespace Bundesdruckerei::nPA;

#include "eIDUtils.h"
using namespace Bundesdruckerei::eIDUtils;

#include <CertificateBody.h>
#include <CVCertificate.h>
#include <CertificateDescription.h>
#include <PlainTermsOfUsage.h>

#include "eCardCore/eCardStatus.h"
#include "nPA-EAC/nPACard.h"

#include <debug.h>
#include "eCardCore/PCSCManager.h"

nPAClient* nPAClient::m_instance = 0x00;

extern "C" unsigned char* nPAClient_allocator(
  size_t size)
{
  return new unsigned char[size];
}

/**
 */
extern "C" void nPAClient_deallocator(
  unsigned char* data)
{
  delete [] data;
}

/*
 *
 */
nPAClient* nPAClient::createInstance(
  IIdP* pIdP)
{
  if (0x00 == m_instance)
    m_instance = new nPAClient(pIdP);

  return m_instance;
}

/*
 *
 */
nPAClient::nPAClient(
  IIdP* pIdP) : m_Idp(pIdP), m_hSystem(0x00), m_hCard(0x00), m_clientProtocol(0x00),
  m_protocolState(Unauthenticated)
{
}

/*
 *
 */
nPAClient::~nPAClient(
  void)
{
  // Delete the IdP connection.
  if (0x00 != m_Idp)
  {
    delete m_Idp;
    m_Idp = 0x00;
  }

  // Delete the protocol stack.
  if (0x00 != m_clientProtocol)
  {
    delete m_clientProtocol;
    m_clientProtocol = 0x00;
  }

  // Close the card.
  if (0x00 != m_hCard)
  {
    delete m_hCard;
    m_hCard = 0x00;
  }

  // Close the card subsystem.
  if (0x00 != m_hSystem)
  {
    delete m_hSystem;
    m_hSystem = 0x00;
  }

  m_instance = 0x00;
}

/*
 *
 */
NPACLIENT_ERROR nPAClient::initialize(
  const CharMap* paraMap,
  ECARD_PROTOCOL usedProtocol)
{
  NPACLIENT_ERROR error = NPACLIENT_ERROR_SUCCESS;

  // Check that we have an valid IdP instance. If not return an error.
  if (0x00 == m_Idp)
    return NPACLIENT_ERROR_IDP_INVALID_CONNECTION;

  // Initialize the IdP connection.
  if ((error = m_Idp->initialize(this)) != NPACLIENT_ERROR_SUCCESS)
    return error;

  // Connect to the underlying smart card system.
  switch (usedProtocol) {
    case PROTOCOL_PCSC:
      {
        m_hSystem = new PCSCManager();
      }
      break;
    default:
      {
        return ECARD_PROTOCOL_UNKNOWN;
      }
  }

  // Add an instance of an detection object to the smart card system.
  m_hSystem->addCardDetector(new ePACardDetector());

  vector<IReader *> readers;
  // Is there a specified CardReader?
  if(paraMap->find((char *) "CardReaderName") == paraMap->end())
      readers = m_hSystem->getReaders();
  else {
      IReader *reader = m_hSystem->getReader(*paraMap->find((char *) "CardReaderName")->second);
      if (reader == 0x00)
          return ECARD_NO_SUCH_READER;
      readers.push_back(reader);
  }

  eCardCore_info(DEBUG_LEVEL_CLIENT, "Found %d reader%s", readers.size(), readers.size() == 1 ? "" : "s");
  if (readers.empty())
      return NPACLIENT_ERROR_NO_USABLE_READER_PRESENT;
  
  size_t ePACounter = 0;
  // Try to find a valid nPA card.
  for (size_t i = 0; i < readers.size(); i++)
  {
      eCardCore_info(DEBUG_LEVEL_CLIENT, "Trying %s.", readers[i]->getReaderName().c_str());

      if (!readers[i]->open())
          continue;

      ICard *hTempCard_ = readers[i]->getCard();
      if (hTempCard_)
      {
          // We have more than one card ... So we have to close the old one.
          if (m_hCard != 0x00) 
              delete m_hCard;

          m_hCard = hTempCard_;
          ePACounter++;

          eCardCore_info(DEBUG_LEVEL_CLIENT, "Found %s", m_hCard->getCardDescription().c_str());
          vector<unsigned char> atr = readers[i]->getATRForPresentCard();
          hexdump(DEBUG_LEVEL_CLIENT, "Answer-to-Reset (ATR):", atr.data(),
                  atr.size());
      } else
          readers[i]->close();
  }

  eCardCore_debug(DEBUG_LEVEL_CLIENT, "Found %d nPA%s", ePACounter, ePACounter == 1 ? "" : "s");
  // We can only handle one nPA.
  if (1 < ePACounter)
   return NPACLIENT_ERROR_TO_MANY_CARDS_FOUND;
  // We need at least one nPA.
  if (1 > ePACounter)
    return NPACLIENT_ERROR_NO_VALID_CARD_FOUND;

  // Create the new protocol.
  m_clientProtocol = new ePAClientProtocol(m_hCard);

  if (0x00 == m_clientProtocol)
    return NPACLIENT_ERROR_PROTCOL_INITIALIZATION_FAILD;

  return NPACLIENT_ERROR_SUCCESS;
}

/*
 *
 */
bool nPAClient::getCHAT2(
  nPADataBuffer_t &chatFromCertificate)
{
  CVCertificate_t	*CVCertificate = 0x00;
  if (ber_decode(0, &asn_DEF_CVCertificate, (void **)&CVCertificate,
    &m_Idp->getTerminalCertificate()[0], m_Idp->getTerminalCertificate().size()).code != RC_OK)
  {
    eCardCore_debug(DEBUG_LEVEL_CLIENT, "nPAClient::getCHAT2 - Could not parse terminal certificate.");

    // @TODO: Do logging ...

    asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
    return false;
  }

  chatFromCertificate.pDataBuffer = new unsigned char[CVCertificate->certBody.certHolderAuthTemplate.chat.size];
  if (0x00 == chatFromCertificate.pDataBuffer)
	  return false;

  chatFromCertificate.bufferSize = CVCertificate->certBody.certHolderAuthTemplate.chat.size;

  memcpy(chatFromCertificate.pDataBuffer, &CVCertificate->certBody.certHolderAuthTemplate.chat.buf[0], 
    chatFromCertificate.bufferSize);

  asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
  
  return true;
}

/*
 *
 */
bool nPAClient::getRequiredCHAT(
  nPADataBuffer_t &requiredChat)
{
  requiredChat.pDataBuffer = new unsigned char[m_Idp->getRequiredChat().size()];
  if (0x00 == requiredChat.pDataBuffer)
	  return false;

  requiredChat.bufferSize = m_Idp->getRequiredChat().size();

  memcpy(requiredChat.pDataBuffer, &m_Idp->getRequiredChat()[0], m_Idp->getRequiredChat().size());
  
  return true;
}

/*
 *
 */
bool nPAClient::getOptionalCHAT(
  nPADataBuffer_t &optionalChat)
{
  if (0x00 == m_Idp->getOptionalChat().size())
    return true;

  optionalChat.pDataBuffer = new unsigned char[m_Idp->getOptionalChat().size()];
  if (0x00 == optionalChat.pDataBuffer)
	  return false;

  optionalChat.bufferSize = m_Idp->getOptionalChat().size();

  memcpy(optionalChat.pDataBuffer, &m_Idp->getOptionalChat()[0], m_Idp->getOptionalChat().size());
  
  return true;
}

/*
 *
 */
bool nPAClient::getValidFromDate(
  time_t &certificateValidFrom)
{
  CVCertificate_t	*CVCertificate = 0x00;
  if (ber_decode(0, &asn_DEF_CVCertificate, (void **)&CVCertificate,
    &m_Idp->getTerminalCertificate()[0], m_Idp->getTerminalCertificate().size()).code != RC_OK)
  {
    eCardCore_debug(DEBUG_LEVEL_CLIENT, "nPAClient::getValidFromDate - Could not parse terminal certificate.");

    asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
    
    // @TODO: Do logging ...
    return false;
  }

  std::vector<unsigned char> validFromBuffer(
          CVCertificate->certBody.certEffectiveDate.buf,
          CVCertificate->certBody.certEffectiveDate.buf + CVCertificate->certBody.certEffectiveDate.size);
  certificateValidFrom = BDRDate::timeFromBCD(validFromBuffer);

  asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
  
  return true;
}

bool nPAClient::getValidToDate(
  time_t &certificateValidTo)
{
  CVCertificate_t	*CVCertificate = 0x00;
  if (ber_decode(0, &asn_DEF_CVCertificate, (void **)&CVCertificate, 
    &m_Idp->getTerminalCertificate()[0], m_Idp->getTerminalCertificate().size()).code != RC_OK)
  {
    eCardCore_debug(DEBUG_LEVEL_CLIENT, "nPAClient::getValidToDate - Could not parse terminal certificate.");

    asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
    
    return false;
  }

  std::vector<unsigned char> validFromBuffer(
          CVCertificate->certBody.certExpirationDate.buf, 
          CVCertificate->certBody.certExpirationDate.buf + CVCertificate->certBody.certExpirationDate.size);
  certificateValidTo = BDRDate::timeFromBCD(validFromBuffer);

  asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
  
  return true;
}

bool nPAClient::getCertificateDescription(
  nPADataBuffer_t &certificateDescription)
{
  CertificateDescription_t* certificateDescription_ = 0x00;
  if (ber_decode(0, &asn_DEF_CertificateDescription, (void **)&certificateDescription_, 
    &m_Idp->getCertificateDescription()[0], m_Idp->getCertificateDescription().size()).code != RC_OK)
  {
    eCardCore_debug(DEBUG_LEVEL_CLIENT, "nPAClient::getCertificateDescription - Could not parse certificate description.");

    asn_DEF_CertificateDescription.free_struct(&asn_DEF_CertificateDescription, certificateDescription_, 0);
    
    return false;
  }

  PlainTermsOfUsage_t* usage = 0x00;
  if (ber_decode(0, &asn_DEF_PlainTermsOfUsage, (void **)&usage, 
    &certificateDescription_->termsOfUsage.buf[0], certificateDescription_->termsOfUsage.size).code != RC_OK)
  {
    eCardCore_debug(DEBUG_LEVEL_CLIENT, "nPAClient::getCertificateDescription - Could not parse certificate description.");

    asn_DEF_PlainTermsOfUsage.free_struct(&asn_DEF_PlainTermsOfUsage, usage, 0);
    
    return false;
  }


  certificateDescription.pDataBuffer = new unsigned char[usage->size];
  if (0x00 == certificateDescription.pDataBuffer)
	  return false;

  certificateDescription.bufferSize = usage->size;

  memcpy(certificateDescription.pDataBuffer, &usage->buf[0], 
    usage->size);

  asn_DEF_CertificateDescription.free_struct(&asn_DEF_CertificateDescription, certificateDescription_, 0);
  asn_DEF_PlainTermsOfUsage.free_struct(&asn_DEF_PlainTermsOfUsage, usage, 0);
  return true;
}

bool nPAClient::getServiceName(
  nPADataBuffer_t &serviceName)
{
  CertificateDescription_t* certificateDescription_ = 0x00;
  if (ber_decode(0, &asn_DEF_CertificateDescription, (void **)&certificateDescription_, 
    &m_Idp->getCertificateDescription()[0], m_Idp->getCertificateDescription().size()).code != RC_OK)
  {
    eCardCore_debug(DEBUG_LEVEL_CLIENT, "nPAClient::getServiceName - Could not parse certificate description.");

    asn_DEF_CertificateDescription.free_struct(&asn_DEF_CertificateDescription, certificateDescription_, 0);
    
    return false;
  }

  serviceName.pDataBuffer = new unsigned char[certificateDescription_->subjectName.size];
  if (0x00 == serviceName.pDataBuffer)
	  return false;

  serviceName.bufferSize = certificateDescription_->subjectName.size;

  memcpy(serviceName.pDataBuffer, &certificateDescription_->subjectName.buf[0], 
    serviceName.bufferSize);

  asn_DEF_CertificateDescription.free_struct(&asn_DEF_CertificateDescription, certificateDescription_, 0);
  
  return true;
}

bool nPAClient::getServiceURL(
  nPADataBuffer_t &serviceURL)
{
  CertificateDescription_t* certificateDescription_ = 0x00;
  if (ber_decode(0, &asn_DEF_CertificateDescription, (void **)&certificateDescription_, 
    &m_Idp->getCertificateDescription()[0], m_Idp->getCertificateDescription().size()).code != RC_OK)
  {
    eCardCore_debug(DEBUG_LEVEL_CLIENT, "nPAClient::getServiceURL - Could not parse certificate description.");

    asn_DEF_CertificateDescription.free_struct(&asn_DEF_CertificateDescription, certificateDescription_, 0);
    
    return false;
  }
  
  if(0x00 == certificateDescription_->subjectURL)
  {
    asn_DEF_CertificateDescription.free_struct(&asn_DEF_CertificateDescription, certificateDescription_, 0);
	return false;
  }

  serviceURL.pDataBuffer = new unsigned char[certificateDescription_->subjectURL->size];
  if (0x00 == serviceURL.pDataBuffer)
	  return false;

  serviceURL.bufferSize = certificateDescription_->subjectURL->size;

  memcpy(serviceURL.pDataBuffer, &certificateDescription_->subjectURL->buf[0], 
    serviceURL.bufferSize);

  asn_DEF_CertificateDescription.free_struct(&asn_DEF_CertificateDescription, certificateDescription_, 0);
  
  return true;
}

bool nPAClient::passwordIsRequired(void) const
{
  if (!m_hCard)
    return false;

  // Try to get ePA card
  Bundesdruckerei::nPA::ePACard& ePA_ = dynamic_cast<Bundesdruckerei::nPA::ePACard&>(*m_hCard);

  return !(ePA_.getSubSystem()->supportsPACE());
}

NPACLIENT_ERROR nPAClient::performPACE(
  const nPADataBuffer_t * const password,
  const nPADataBuffer_t * const chatSelectedByUser,
  const nPADataBuffer_t * const certificateDescription)
{
  // Check the state of the protocol. We can only run PACE if the
  // protocol is in the unauthenticated state.
  if (Unauthenticated != m_protocolState)
    return NPACLIENT_ERROR_INVALID_PROTOCOL_STATE;

  std::vector<unsigned char> passwordInput;

  if (!chatSelectedByUser)
    return NPACLIENT_ERROR_INVALID_PARAMETER2;
  if (!certificateDescription)
    return NPACLIENT_ERROR_INVALID_PARAMETER3;

  // Actually we running the PACE protocol
  m_protocolState = PACE_Running;
  
  if (password)
	passwordInput = std::vector<unsigned char> (password->pDataBuffer,
          password->pDataBuffer + password->bufferSize);

  std::vector<unsigned char> certificateDescriptionInput
      (certificateDescription->pDataBuffer,
       certificateDescription->pDataBuffer + certificateDescription->bufferSize);

  m_chatUsed = std::vector<unsigned char> (chatSelectedByUser->pDataBuffer,
          chatSelectedByUser->pDataBuffer + chatSelectedByUser->bufferSize);


  PaceInput pace_input = PaceInput(PaceInput::pin, passwordInput, m_chatUsed,
          certificateDescriptionInput);

  // Running the protocol
  ECARD_STATUS status = ECARD_SUCCESS; 
  if ((status = m_clientProtocol->PACE(pace_input)) != ECARD_SUCCESS)
  {
    // @TODO: Do logging ...

    return NPACLIENT_ERROR_PACE_FAILED;
  }
  
  // PACE runs successfully
  m_protocolState = PACE_Done;

  // @TODO: Do logging ...
  return NPACLIENT_ERROR_SUCCESS;
}

/*
 *
 */
NPACLIENT_ERROR nPAClient::performTerminalAuthentication(
  void)
{
  std::vector<unsigned char> idPICC;
  std::vector<std::vector<unsigned char> > list_certificates;

  // Check the state of the protocol. We can only run TA if the
  // PACE protocol is done.
  if (PACE_Done != m_protocolState)
    return NPACLIENT_ERROR_INVALID_PROTOCOL_STATE;

  m_protocolState = TA_Running;

  std::vector<unsigned char> idPICC_;

  m_clientProtocol->GetIDPICC(idPICC_);
  
  idPICC = idPICC_;

  if (!m_hCard)
    return ECARD_ERROR;

  // Try to get ePA card
  Bundesdruckerei::nPA::ePACard& ePA_ = dynamic_cast<Bundesdruckerei::nPA::ePACard&>(*m_hCard);

  if (!m_Idp->getTerminalAuthenticationData(ePA_.get_ef_cardaccess(), m_chatUsed, m_clientProtocol->GetCARCVCA(), idPICC, list_certificates, 
      m_x_Puk_IFD_DH_CA_, m_y_Puk_IFD_DH_CA_))
  {
    return NPACLIENT_ERROR_TA_INITIALIZATION_FAILD;
  }

  std::vector<unsigned char> termCertificate = m_Idp->getTerminalCertificate();
  std::vector<unsigned char> authenticatedAuxiliaryData = m_Idp->getAuthenticatedAuxiliaryData();

  std::vector<unsigned char> termDummy = termCertificate;
  std::vector<unsigned char> terminalCertificate_;
  terminalCertificate_ = termDummy;

  std::vector<unsigned char> authenticatedAuxiliaryDataDummy = authenticatedAuxiliaryData;
  std::vector<unsigned char> authenticatedAuxiliaryData_;
  if(authenticatedAuxiliaryDataDummy.size() > 0)
  {
    authenticatedAuxiliaryData_ = authenticatedAuxiliaryDataDummy;
  }
  else
  {
	  authenticatedAuxiliaryData_.clear();
  }

  // Used in TA and CA
  std::vector<unsigned char> x_Puk_IFD_DH_;
  x_Puk_IFD_DH_ = m_x_Puk_IFD_DH_CA_;


  // Only used in CA
  std::vector<unsigned char> y_Puk_IFD_DH_;
  y_Puk_IFD_DH_ = m_y_Puk_IFD_DH_CA_;

  std::vector<unsigned char> toBeSigned_;

  ECARD_STATUS status = ECARD_SUCCESS;
  // Run the Terminal authentication until the signature action.
  if ((status = m_clientProtocol->TerminalAuthentication(list_certificates, 
      terminalCertificate_, x_Puk_IFD_DH_, authenticatedAuxiliaryData_, toBeSigned_)) != ECARD_SUCCESS)
  {
    return NPACLIENT_ERROR_TA_FAILED;
  }

  std::vector<unsigned char> toBeSigned;
  std::vector<unsigned char> signature;

  toBeSigned = toBeSigned_;

  if (!m_Idp->createSignature(toBeSigned, signature))
    return NPACLIENT_ERROR_CREATE_SIGNATURE_ERROR;

  std::vector<unsigned char> sendSignature_;
  sendSignature_ = signature;
  if ((status = m_clientProtocol->SendSignature(sendSignature_)) != ECARD_SUCCESS)
  {
    return NPACLIENT_ERROR_SEND_SIGNATURE_ERROR;
  }
  // Terminal Authentication runs successfully
  m_protocolState = TA_Done;

  // @TODO: Do logging ...
  return NPACLIENT_ERROR_SUCCESS;
}

/*
 *
 */
NPACLIENT_ERROR nPAClient::performChipAuthentication(
  void)
{
  ECARD_STATUS status = ECARD_SUCCESS;

  if (!m_hCard)
    return ECARD_ERROR;

  // Try to get ePA card
  Bundesdruckerei::nPA::ePACard& ePA_ = dynamic_cast<Bundesdruckerei::nPA::ePACard&>(*m_hCard);

  if (TA_Done != m_protocolState)
    return NPACLIENT_ERROR_INVALID_PROTOCOL_STATE;

  const vector<unsigned char> ef_cardsecurity = ePA_.get_ef_cardsecurity();

  // Used in TA and CA
  std::vector<unsigned char> x_Puk_IFD_DH_;
  x_Puk_IFD_DH_ = m_x_Puk_IFD_DH_CA_;

  // Only used in CA
  std::vector<unsigned char> y_Puk_IFD_DH_;
  y_Puk_IFD_DH_ = m_y_Puk_IFD_DH_CA_;

  std::vector<unsigned char> GeneralAuthenticationResult;

  if ((status = m_clientProtocol->ChipAuthentication(x_Puk_IFD_DH_, 
    y_Puk_IFD_DH_, GeneralAuthenticationResult)) != ECARD_SUCCESS)
  {
    return NPACLIENT_ERROR_CA_FAILED;
  }

  std::vector<unsigned char> GAResult;
  GAResult = GeneralAuthenticationResult;

  if (!m_Idp->finalizeAuthentication(ef_cardsecurity, GAResult, m_capdus))
  {
    return NPACLIENT_ERROR_CA_SERVER_FAILED;
  }
 
  m_protocolState = Authenticated;

  // @TODO: Do logging ...
  return NPACLIENT_ERROR_SUCCESS;
}

NPACLIENT_ERROR nPAClient::readAttributed(void)
{
  if (Authenticated != m_protocolState)
    return NPACLIENT_ERROR_INVALID_PROTOCOL_STATE;

  for (size_t i = 0; i < m_capdus.size(); ++i)
  {
      try {
          m_rapdus.push_back(m_hCard->sendAPDU(m_capdus[i]));
      } catch (...) {
		  return NPACLIENT_ERROR_TRANSMISSION_ERROR;
      }
  }

  std::string attributes;
  if (!m_Idp->readAttributes(m_rapdus))
    return NPACLIENT_ERROR_READ_FAILED;

  m_Idp->close();

  m_protocolState = Finished;

  return NPACLIENT_ERROR_SUCCESS;
}
