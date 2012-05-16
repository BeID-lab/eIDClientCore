// ---------------------------------------------------------------------------
// Copyright (c) 2010 Bundesdruckerei GmbH
// All rights reserved.
//
// $Id: nPAClient.cpp 775 2010-06-22 07:37:38Z dietrfra $
// ---------------------------------------------------------------------------

#include "nPAClient.h"
using namespace Bundesdruckerei::nPA;

#include <eIdUtils.h>
using namespace Bundesdruckerei::eIdUtils;

#include <CertificateBody.h>
#include <CVCertificate.h>
#include <CertificateDescription.h>
#include <PlainTermsOfUsage.h>

#include <eCardStatus.h>
#include <eCardCore.h>
#include <ePACard.h>
#include <ePACommon.h>

#include <cassert>

void eCardCore_debug(
                     const char* format,
                     ...);

#define OUTPUT_TO_VECTOR(a, b) for (int i = 0; i < a.m_dataSize; i++) b.push_back(a.m_pDataBuffer[i]);

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
  m_protocolState(Unauthenticated), m_userSelectedChat(0x0000000000000000)
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
    eCardCloseReader(m_hCard);
    m_hCard = 0x00;
  }

  // Close the card subsystem.
  if (0x00 != m_hSystem)
  {
    eCardClose(m_hSystem);
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
  ECARD_STATUS status = ECARD_SUCCESS;

  assert(0x00 != m_Idp);

  // Check that we have an valid IdP instance. If not return 
  // an error.
  if (0x00 == m_Idp)
    return NPACLIENT_ERROR_IDP_INVALID_CONNECTION;

  // Initialize the IdP connection.
  if ((error = m_Idp->initialize(paraMap, this)) != NPACLIENT_ERROR_SUCCESS)
    return error;

  // Connect to the underlying smart card system.
  if ((status = eCardOpen(&m_hSystem, usedProtocol)) != ECARD_SUCCESS)
    return NPACLIENT_ERROR_PCSC_INITIALIZATION_FAILED;

  assert(0x00 != m_hSystem);

  // Add an instance of an detection object to the smart card system. We only
  // handle the nPA card!
  if ((status = eCardAddCardDetector(m_hSystem, new ePACardDetector())) != ECARD_SUCCESS)
    return NPACLIENT_ERROR_INVALID_CARD_DETECTOR;

  int readerCount_ = eCardGetReaderCount(m_hSystem);
  
  eCardCore_debug("eCardGetReaderCount(%08X) returnd %d", m_hSystem, readerCount_);
  
  if (0 == readerCount_)
    return NPACLIENT_ERROR_NO_USABLE_READER_PRESENT;

  DWORD ePACounter_ = 0;
  // Is there a specified CardReader?

//  if(paraMap->find("CardReaderName") == paraMap->end())
//  {
    // Try to find an valid nPA card.
    for (int i = 0; i < readerCount_; i++)
    {  
      ECARD_HANDLE hTempCard_ = 0x00;
      if (ECARD_SUCCESS == eCardOpenReader(m_hSystem, i, &hTempCard_))
      {    
        ePACounter_++;
        // We have more than one card ... So we have to close the old one.
        if (m_hCard != 0x00) 
        {
          eCardCloseReader(m_hCard);
          m_hCard = 0x00;
        } // if (m_hCard != 0x00) 

        m_hCard = hTempCard_;
        break;
      } // if (ECARD_SUCCESS == eCardOpenReader(hSystem, i, &hTempCard))
    } // for (int i = 0; i < readerCount; i++)

  //}
  //else
  //{
  //  // Try to use the specified reader
  //  ECARD_HANDLE hTempCard_ = 0x00;
  //  eCardCore_debug("Open Reader with Name == %s", * paraMap->find("CardReaderName")->second);
  //  if(ECARD_SUCCESS == eCardOpenReaderByName(m_hSystem, * paraMap->find("CardReaderName")->second, &hTempCard_))
  //  {
  //    ePACounter_++;
  //    // We have more than one card ... So we have to close the old one.
  //    if (m_hCard != 0x00) 
  //    {
  //      eCardCloseReader(m_hCard);
  //      m_hCard = 0x00;
  //    } // if (m_hCard != 0x00) 

  //    m_hCard = hTempCard_;
  //  }
  //}
  eCardCore_debug("ePACounter_ == %d", readerCount_);

  // We can only handle one nPA.
  if (1 < ePACounter_)
   return NPACLIENT_ERROR_TO_MANY_CARDS_FOUND;

  // We need at least one nPA.
  if (1 > ePACounter_)
    return NPACLIENT_ERROR_NO_VALID_CARD_FOUND;

  // Create the new protocol.
  m_clientProtocol = new ePAClientProtocol(m_hCard);
  assert(0x00 != m_clientProtocol);

  if (0x00 == m_clientProtocol)
    return NPACLIENT_ERROR_PROTCOL_INITIALIZATION_FAILD;

  eCardCore_debug("nPAClient::initialize ok");

  return NPACLIENT_ERROR_SUCCESS;
}

/*
 *
 */
bool nPAClient::getCHAT(
  chat_t &chatFromCertificate)
{
  CVCertificate_t	*CVCertificate = 0x00;
  if (ber_decode(0, &asn_DEF_CVCertificate, (void **)&CVCertificate,
    &m_Idp->getTerminalCertificate().data()[0], m_Idp->getTerminalCertificate().data().size()).code != RC_OK)
  {
    eCardCore_debug("nPAClient::getCHAT - Could not parse terminal certificate.");
    hexdump("CERT: ", &m_Idp->getTerminalCertificate().data()[0], m_Idp->getTerminalCertificate().data().size());

    // @TODO: Do logging ...
    
    asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
    return false;
  }

  ByteData chatValue(CVCertificate->certBody.certHolderAuthTemplate.chat.buf,
    CVCertificate->certBody.certHolderAuthTemplate.chat.size);
  chatFromCertificate += (long long) chatValue.elementAt(0) << 32; 
  chatFromCertificate += (long long) chatValue.elementAt(1) << 24;
  chatFromCertificate += (long long) chatValue.elementAt(2) << 16; 
  chatFromCertificate += (long long) chatValue.elementAt(3) << 8;
  chatFromCertificate += (long long) chatValue.elementAt(4);

  // Save the original CHAT value from certificate
  m_originalCHAT = chatValue.data();

  // Save the Terminal role from the certificate for further usage.
  m_terminalRole.resize(CVCertificate->certBody.certHolderAuthTemplate.authTerminalID.size);
  m_terminalRole.assign(&CVCertificate->certBody.certHolderAuthTemplate.authTerminalID.buf[0], 
    &CVCertificate->certBody.certHolderAuthTemplate.authTerminalID.buf[
      CVCertificate->certBody.certHolderAuthTemplate.authTerminalID.size]);

  asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
  
  return true;
}

/*
 *
 */
bool nPAClient::getCHAT2(
  nPADataBuffer_t &chatFromCertificate)
{
  CVCertificate_t	*CVCertificate = 0x00;
  if (ber_decode(0, &asn_DEF_CVCertificate, (void **)&CVCertificate,
    &m_Idp->getTerminalCertificate().data()[0], m_Idp->getTerminalCertificate().data().size()).code != RC_OK)
  {
    eCardCore_debug("nPAClient::getCHAT2 - Could not parse terminal certificate.");
    hexdump("CERT: ", &m_Idp->getTerminalCertificate().data()[0], m_Idp->getTerminalCertificate().data().size());

    // @TODO: Do logging ...

    asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
    return false;
  }

  chatFromCertificate.pDataBuffer = new unsigned char[CVCertificate->certBody.certHolderAuthTemplate.chat.size];
  assert(0x00 != chatFromCertificate.pDataBuffer);

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
  requiredChat.pDataBuffer = new unsigned char[m_Idp->getRequiredChat().data().size()];
  assert(0x00 != requiredChat.pDataBuffer);

  requiredChat.bufferSize = m_Idp->getRequiredChat().data().size();

  memcpy(requiredChat.pDataBuffer, &m_Idp->getRequiredChat().data()[0], m_Idp->getRequiredChat().data().size());
  
  return true;
}

/*
 *
 */
bool nPAClient::getOptionalCHAT(
  nPADataBuffer_t &optionalChat)
{
  if (0x00 == m_Idp->getOptionalChat().data().size())
    return true;

  optionalChat.pDataBuffer = new unsigned char[m_Idp->getOptionalChat().data().size()];
  assert(0x00 != optionalChat.pDataBuffer);

  optionalChat.bufferSize = m_Idp->getOptionalChat().data().size();

  memcpy(optionalChat.pDataBuffer, &m_Idp->getOptionalChat().data()[0], m_Idp->getOptionalChat().data().size());
  
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
    &m_Idp->getTerminalCertificate().data()[0], m_Idp->getTerminalCertificate().data().size()).code != RC_OK)
  {
    eCardCore_debug("nPAClient::getValidFromDate - Could not parse terminal certificate.");
    hexdump("CERT: ", &m_Idp->getTerminalCertificate().data()[0], m_Idp->getTerminalCertificate().data().size());

    asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
    
    // @TODO: Do logging ...
    return false;
  }

  ByteData validFromBuffer(CVCertificate->certBody.certEffectiveDate.buf, 
    CVCertificate->certBody.certEffectiveDate.size);
  certificateValidFrom = BDRDate::timeFromBCD(validFromBuffer);

  asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
  
  return true;
}

/*
 *
 */
//bool nPAClient::getValidFromDateString(
//  std::string &certificateValidFrom)
//{
//  CVCertificate_t	*CVCertificate = 0x00;
//  if (ber_decode(0, &asn_DEF_CVCertificate, (void **)&CVCertificate,
//    &m_Idp->getTerminalCertificate().data()[0], m_Idp->getTerminalCertificate().data().size()).code != RC_OK)
//  {
//    eCardCore_debug("nPAClient::getValidFromDateString - Could not parse terminal certificate.");
//    hexdump("CERT: ", &m_Idp->getTerminalCertificate().data()[0], m_Idp->getTerminalCertificate().data().size());
//
//    asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
//    
//    // @TODO: Do logging ...
//    return false;
//  }
//
//  ByteData validFromBuffer(CVCertificate->certBody.certEffectiveDate.buf, 
//    CVCertificate->certBody.certEffectiveDate.size);
//  certificateValidFrom = BDRDate::fromBCD(validFromBuffer);
//
//  asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
//  
//  return true;
//}

/*
 *
 */
bool nPAClient::getValidToDate(
  time_t &certificateValidTo)
{
  CVCertificate_t	*CVCertificate = 0x00;
  if (ber_decode(0, &asn_DEF_CVCertificate, (void **)&CVCertificate, 
    &m_Idp->getTerminalCertificate().data()[0], m_Idp->getTerminalCertificate().data().size()).code != RC_OK)
  {
    eCardCore_debug("nPAClient::getValidToDate - Could not parse terminal certificate.");
    hexdump("CERT: ", &m_Idp->getTerminalCertificate().data()[0], m_Idp->getTerminalCertificate().data().size());

    asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
    
    // @TODO: Do logging ...
    return false;
  }

  ByteData validFromBuffer(CVCertificate->certBody.certExpirationDate.buf, 
    CVCertificate->certBody.certExpirationDate.size);
  certificateValidTo = BDRDate::timeFromBCD(validFromBuffer);

  asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
  
  return true;
}

/*
 *
 */
//bool nPAClient::getValidToDateString(
//  std::string &certificateValidTo)
//{
//  CVCertificate_t	*CVCertificate = 0x00;
//  if (ber_decode(0, &asn_DEF_CVCertificate, (void **)&CVCertificate, 
//    &m_Idp->getTerminalCertificate().data()[0], m_Idp->getTerminalCertificate().data().size()).code != RC_OK)
//  {
//    eCardCore_debug("nPAClient::getValidToDateString - Could not parse terminal certificate.");
//    hexdump("CERT: ", &m_Idp->getTerminalCertificate().data()[0], m_Idp->getTerminalCertificate().data().size());
//
//    asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
//    
//    // @TODO: Do logging ...
//    return false;
//  }
//
//  ByteData validFromBuffer(CVCertificate->certBody.certExpirationDate.buf, 
//    CVCertificate->certBody.certExpirationDate.size);
//  certificateValidTo = BDRDate::fromBCD(validFromBuffer);
//
//  asn_DEF_CVCertificate.free_struct(&asn_DEF_CVCertificate, CVCertificate, 0);
//  
//  return true;
//}

/*
 *
 */
bool nPAClient::getCertificateDescription(
  nPADataBuffer_t &certificateDescription)
{
  CertificateDescription_t* certificateDescription_ = 0x00;
  if (ber_decode(0, &asn_DEF_CertificateDescription, (void **)&certificateDescription_, 
    &m_Idp->getCertificateDescription().data()[0], m_Idp->getCertificateDescription().data().size()).code != RC_OK)
  {
    eCardCore_debug("nPAClient::getCertificateDescription - Could not parse certificate description.");
    hexdump("CERT DESC: ", &m_Idp->getCertificateDescription().data()[0], m_Idp->getCertificateDescription().data().size());

    asn_DEF_CertificateDescription.free_struct(&asn_DEF_CertificateDescription, certificateDescription_, 0);
    
    // @TODO: Do logging ...
    return false;
  }

  PlainTermsOfUsage_t* usage = 0x00;
  if (ber_decode(0, &asn_DEF_PlainTermsOfUsage, (void **)&usage, 
    &certificateDescription_->termsOfUsage.buf[0], certificateDescription_->termsOfUsage.size).code != RC_OK)
  {
    eCardCore_debug("nPAClient::getCertificateDescription - Could not parse certificate description.");
    hexdump("CERT DESC TERMS: ", &certificateDescription_->termsOfUsage.buf[0], certificateDescription_->termsOfUsage.size);

    asn_DEF_PlainTermsOfUsage.free_struct(&asn_DEF_PlainTermsOfUsage, usage, 0);
    
    // @TODO: Do logging ...
    return false;
  }


  certificateDescription.pDataBuffer = new unsigned char[usage->size];
  assert(0x00 != certificateDescription.pDataBuffer);

  certificateDescription.bufferSize = usage->size;

  memcpy(certificateDescription.pDataBuffer, &usage->buf[0], 
    usage->size);

  asn_DEF_CertificateDescription.free_struct(&asn_DEF_CertificateDescription, certificateDescription_, 0);
  asn_DEF_PlainTermsOfUsage.free_struct(&asn_DEF_PlainTermsOfUsage, usage, 0);
  return true;
}

/*
 *
 */
//bool nPAClient::getCertificateDescriptionRaw(
//  nPADataBuffer_t &certificateDescription)
//{
//  certificateDescription.pDataBuffer = new unsigned char[m_Idp->getCertificateDescription().data().size()];
//  assert(0x00 != certificateDescription.pDataBuffer);
//
//  certificateDescription.bufferSize = m_Idp->getCertificateDescription().data().size();
//
//  memcpy(certificateDescription.pDataBuffer, &m_Idp->getCertificateDescription().data()[0], m_Idp->getCertificateDescription().data().size());
//  
//  return true;
//}

/*
 *
 */
bool nPAClient::getServiceName(
  nPADataBuffer_t &serviceName)
{
  CertificateDescription_t* certificateDescription_ = 0x00;
  if (ber_decode(0, &asn_DEF_CertificateDescription, (void **)&certificateDescription_, 
    &m_Idp->getCertificateDescription().data()[0], m_Idp->getCertificateDescription().data().size()).code != RC_OK)
  {
    eCardCore_debug("nPAClient::getServiceName - Could not parse certificate description.");
    hexdump("CERT DESC: ", &m_Idp->getCertificateDescription().data()[0], m_Idp->getCertificateDescription().data().size());

    asn_DEF_CertificateDescription.free_struct(&asn_DEF_CertificateDescription, certificateDescription_, 0);
    
    // @TODO: Do logging ...
    return false;
  }

  serviceName.pDataBuffer = new unsigned char[certificateDescription_->subjectName.size];
  assert(0x00 != serviceName.pDataBuffer);

  serviceName.bufferSize = certificateDescription_->subjectName.size;

  memcpy(serviceName.pDataBuffer, &certificateDescription_->subjectName.buf[0], 
    serviceName.bufferSize);

  asn_DEF_CertificateDescription.free_struct(&asn_DEF_CertificateDescription, certificateDescription_, 0);
  
  return true;
}

/*
 *
 */
bool nPAClient::getServiceURL(
  nPADataBuffer_t &serviceURL)
{
  CertificateDescription_t* certificateDescription_ = 0x00;
  if (ber_decode(0, &asn_DEF_CertificateDescription, (void **)&certificateDescription_, 
    &m_Idp->getCertificateDescription().data()[0], m_Idp->getCertificateDescription().data().size()).code != RC_OK)
  {
    eCardCore_debug("nPAClient::getServiceURL - Could not parse certificate description.");
    hexdump("CERT DESC: ", &m_Idp->getCertificateDescription().data()[0], m_Idp->getCertificateDescription().data().size());

    asn_DEF_CertificateDescription.free_struct(&asn_DEF_CertificateDescription, certificateDescription_, 0);
    
    // @TODO: Do logging ...
    return false;
  }
  
  if(0x00 == certificateDescription_->subjectURL)
  {
    asn_DEF_CertificateDescription.free_struct(&asn_DEF_CertificateDescription, certificateDescription_, 0);
	return false;
  }

  serviceURL.pDataBuffer = new unsigned char[certificateDescription_->subjectURL->size];
  assert(0x00 != serviceURL.pDataBuffer);

  serviceURL.bufferSize = certificateDescription_->subjectURL->size;

  memcpy(serviceURL.pDataBuffer, &certificateDescription_->subjectURL->buf[0], 
    serviceURL.bufferSize);

  asn_DEF_CertificateDescription.free_struct(&asn_DEF_CertificateDescription, certificateDescription_, 0);
  
  return true;
}

/*
 *
 */
NPACLIENT_ERROR nPAClient::performPACE(
  const char* password,
  chat_t chatSelectedByUser,
  unsigned char* retryCounter /*unused*/)
{
  // Check the state of the protocol. We can only run PACE if the
  // protocol is in the unauthenticated state.
  if (Unauthenticated != m_protocolState)
    return NPACLIENT_ERROR_INVALID_PROTOCOL_STATE;

  // Actually we running the PACE protocol
  m_protocolState = PACE_Running;

  BYTE_INPUT_DATA passwordInput;
  passwordInput.dataSize = strlen(password);
  passwordInput.pData = (BYTE*) password;

  std::vector<BYTE> chat_;
  chat_.push_back(0x7F); chat_.push_back(0x4C);
  chat_.push_back(0xFF); // Size will be set later

  // Append the role of the terminal
  chat_.push_back(0x06); // OID
  chat_.push_back(m_terminalRole.size());

  for (size_t i = 0; i < m_terminalRole.size(); i++)
    chat_.push_back(m_terminalRole[i]);

  // Append CHAT
  chat_.push_back(0x53);
  chat_.push_back(m_originalCHAT.size());
  chat_.push_back(m_originalCHAT[0] & ((chatSelectedByUser >> 32) & 0xFF));
  chat_.push_back(m_originalCHAT[1] & ((chatSelectedByUser >> 24) & 0xFF));
  chat_.push_back(m_originalCHAT[2] & ((chatSelectedByUser >> 16) & 0xFF));
  chat_.push_back(m_originalCHAT[3] & ((chatSelectedByUser >> 8) & 0xFF));
  chat_.push_back(m_originalCHAT[4] & (chatSelectedByUser & 0xFF));

  chat_[2] = chat_.size() - 3;

  ByteData chat = m_Idp->getRequiredChat();

  BYTE_INPUT_DATA chatInput;
  chatInput.dataSize = chat_.size();
  chatInput.pData = &chat_[0];

  for (int i = 0; i < chat_.size(); ++i)
  {
    m_chatUsed.push_back(chat_[i]);
  }

  //for (int i = 0; i < chat.data().size(); ++i)
  //{
  //  m_chatUsed.push_back(chat.data()[i]);
  //}

  chatInput.dataSize = chat_.size();
  chatInput.pData = &chat_[0];
  //chatInput.dataSize = m_chatUsed.size();
  //chatInput.pData = &m_chatUsed[0];

  // Running the protocol
  ECARD_STATUS status = ECARD_SUCCESS; 
  if ((status = m_clientProtocol->PACE(chatInput, passwordInput, 
    PIN, *retryCounter)) != ECARD_SUCCESS)
  {
    // @TODO: Do logging ...

    return NPACLIENT_ERROR_PACE_FAILED;
  }
  
  m_userSelectedChat = chatSelectedByUser;

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
  std::vector<unsigned char> efCardAccess;
  std::vector<unsigned char> idPICC;
  std::vector<unsigned char> dvcaCertificate;

  // Check the state of the protocol. We can only run TA if the
  // PACE protocol is done.
  if (PACE_Done != m_protocolState)
    return NPACLIENT_ERROR_INVALID_PROTOCOL_STATE;

  m_protocolState = TA_Running;

  BYTE_OUTPUT_DATA efCardAccess_(&nPAClient_allocator, nPAClient_deallocator);
  BYTE_OUTPUT_DATA idPICC_(&nPAClient_allocator, nPAClient_deallocator);

  m_clientProtocol->GetEFCardAccess(efCardAccess_);
  m_clientProtocol->GetIDPICC(idPICC_);
  
  for (int i = 0; i < efCardAccess_.m_dataSize; i++)
    efCardAccess.push_back(efCardAccess_.m_pDataBuffer[i]);
  for (int i = 0; i < idPICC_.m_dataSize; i++)
      idPICC.push_back(idPICC_.m_pDataBuffer[i]);


  if (!m_Idp->getTerminalAuthenticationData(efCardAccess, m_chatUsed, m_clientProtocol->GetCARCVCA(), idPICC, dvcaCertificate, 
      m_x_Puk_IFD_DH_CA_, m_y_Puk_IFD_DH_CA_))
  {
    return NPACLIENT_ERROR_TA_INITIALIZATION_FAILD;
  }

  BYTE_INPUT_DATA dvCertificate_;
  dvCertificate_.dataSize = dvcaCertificate.size();
  dvCertificate_.pData = &dvcaCertificate[0];

  ByteData termCertificate = m_Idp->getTerminalCertificate();
  ByteData authenticatedAuxiliaryData = m_Idp->getAuthenticatedAuxiliaryData();

  std::vector<unsigned char> termDummy = termCertificate.data();
  BYTE_INPUT_DATA terminalCertificate_;
  terminalCertificate_.dataSize = termDummy.size();
  terminalCertificate_.pData = &termDummy[0];

  std::vector<unsigned char> authenticatedAuxiliaryDataDummy = authenticatedAuxiliaryData.data();
  BYTE_INPUT_DATA authenticatedAuxiliaryData_;
  if(authenticatedAuxiliaryDataDummy.size() > 0)
  {
    authenticatedAuxiliaryData_.dataSize = authenticatedAuxiliaryDataDummy.size();
    authenticatedAuxiliaryData_.pData = &authenticatedAuxiliaryDataDummy[0];
  }
  else
  {
	  authenticatedAuxiliaryData_.dataSize = 0;
	  authenticatedAuxiliaryData_.pData = 0;
  }

  // Used in TA and CA
  BYTE_INPUT_DATA x_Puk_IFD_DH_;
  x_Puk_IFD_DH_.dataSize = m_x_Puk_IFD_DH_CA_.size();
  x_Puk_IFD_DH_.pData =&m_x_Puk_IFD_DH_CA_[0];


  // Only used in CA
  BYTE_INPUT_DATA y_Puk_IFD_DH_;
  y_Puk_IFD_DH_.dataSize = m_y_Puk_IFD_DH_CA_.size();
  y_Puk_IFD_DH_.pData =&m_y_Puk_IFD_DH_CA_[0];

  BYTE_OUTPUT_DATA toBeSigned_(&nPAClient_allocator, &nPAClient_deallocator);

  ECARD_STATUS status = ECARD_SUCCESS;
  // Run the Terminal authentication until the signature action.
  if ((status = m_clientProtocol->TerminalAuthentication(IN dvCertificate_, 
      IN terminalCertificate_, IN x_Puk_IFD_DH_, IN authenticatedAuxiliaryData_, OUT toBeSigned_)) != ECARD_SUCCESS)
  {
    return NPACLIENT_ERROR_TA_FAILED;
  }

  std::vector<unsigned char> toBeSigned;
  std::vector<unsigned char> signature;

  OUTPUT_TO_VECTOR(toBeSigned_, toBeSigned);

  if (!m_Idp->createSignature(toBeSigned, signature))
    return NPACLIENT_ERROR_CREATE_SIGNATURE_ERROR;

  BYTE_INPUT_DATA sendSignature_;
  sendSignature_.dataSize = signature.size();
  sendSignature_.pData = &signature[0];
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

  if (TA_Done != m_protocolState)
    return NPACLIENT_ERROR_INVALID_PROTOCOL_STATE;

  // Used in TA and CA
  BYTE_INPUT_DATA x_Puk_IFD_DH_;
  x_Puk_IFD_DH_.dataSize = m_x_Puk_IFD_DH_CA_.size();
  x_Puk_IFD_DH_.pData =&m_x_Puk_IFD_DH_CA_[0];

  // Only used in CA
  BYTE_INPUT_DATA y_Puk_IFD_DH_;
  y_Puk_IFD_DH_.dataSize = m_y_Puk_IFD_DH_CA_.size();
  y_Puk_IFD_DH_.pData =&m_y_Puk_IFD_DH_CA_[0];

  BYTE_OUTPUT_DATA GeneralAuthenticationResult(&nPAClient_allocator, &nPAClient_deallocator);

  if ((status = m_clientProtocol->ChipAuthentication(IN x_Puk_IFD_DH_, 
    IN y_Puk_IFD_DH_, GeneralAuthenticationResult)) != ECARD_SUCCESS)
  {
    return NPACLIENT_ERROR_CA_FAILED;
  }

  BYTE_OUTPUT_DATA efCardSecurity_(&nPAClient_allocator, nPAClient_deallocator);
  m_clientProtocol->GetEFCardSecurity(efCardSecurity_);

  std::vector<unsigned char> efCardSecurity;
  OUTPUT_TO_VECTOR(efCardSecurity_, efCardSecurity);

  std::vector<unsigned char> GAResult;
  OUTPUT_TO_VECTOR(GeneralAuthenticationResult, GAResult);

  if (!m_Idp->finalizeAuthentication(efCardSecurity, GAResult, m_capdus))
  {
    return NPACLIENT_ERROR_CA_SERVER_FAILED;
  }
 
  m_protocolState = Authenticated;

  // @TODO: Do logging ...
  return NPACLIENT_ERROR_SUCCESS;
}

NPACLIENT_ERROR nPAClient::readAttributed(
  nPADataBuffer_t &samlEncodedAttributes)
{
  if (Authenticated != m_protocolState)
    return NPACLIENT_ERROR_INVALID_PROTOCOL_STATE;

  for (int i = 0; i < m_capdus.size(); ++i)
  {
      BYTE_INPUT_DATA capdu;
      capdu.dataSize = m_capdus.at(i).size();
      capdu.pData =&(m_capdus.at(i))[0];

      BYTE_OUTPUT_DATA rapdu(&nPAClient_allocator, &nPAClient_deallocator);

      ePASendAPDU(m_hCard, capdu, rapdu);

      std::vector<unsigned char> tempAPDU;

      for (int j = 0; j < rapdu.m_dataSize; j++)
        tempAPDU.push_back(rapdu.m_pDataBuffer[j]);

      m_rapdus.push_back(tempAPDU);
  }

  std::string attributes;
  if (!m_Idp->readAttributes(m_rapdus))
    return NPACLIENT_ERROR_READ_FAILED;

  m_Idp->close();

  m_protocolState = Finished;

  return NPACLIENT_ERROR_SUCCESS;
}

/*
 *
 */
NPACLIENT_ERROR nPAClient::sendAPDU(
  BYTE_INPUT_DATA capdu,
  BYTE_OUTPUT_DATA& rapdu)
{
  ePASendAPDU(m_hCard, capdu, rapdu);

  return NPACLIENT_ERROR_SUCCESS;
}