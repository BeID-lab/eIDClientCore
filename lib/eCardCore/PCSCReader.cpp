// ---------------------------------------------------------------------------
// Copyright (c) 2007 Bundesruckerei GmbH
// All rights reserved.
//
// $Id: PCSCReader.cpp 1373 2011-11-24 15:10:52Z x_schrom $
// ---------------------------------------------------------------------------

#include "PCSCReader.h"
#include "ICard.h"
#include "eCardCore_intern.h"

#if defined(_DEBUG) && !defined(WINCE)
# include <crtdbg.h>
# define DEBUG_CLIENTBLOCK   new( _CLIENT_BLOCK, __FILE__, __LINE__)
# define new DEBUG_CLIENTBLOCK
#else
# define DEBUG_CLIENTBLOCK
#endif

#include <stdlib.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <reader.h>
#include <arpa/inet.h>
#endif
#include <string.h>

#ifndef PCSC_TLV_ELEMENT_SIZE
#define PCSC_TLV_ELEMENT_SIZE (1+1+4)
#endif

#ifndef CM_IOCTL_GET_FEATURE_REQUEST
#define CM_IOCTL_GET_FEATURE_REQUEST SCARD_CTL_CODE(3400)
#endif
#ifndef FEATURE_EXECUTE_PACE
#define FEATURE_EXECUTE_PACE 0x20
#endif
#ifndef SCARD_PROTOCOL_ANY
#define SCARD_PROTOCOL_ANY (SCARD_PROTOCOL_T0|SCARD_PROTOCOL_T1)
#endif

#define ENABLE_PACE 1

#define FUNCTION_GetReadersPACECapabilities 0x01
#define FUNCTION_EstabishPACEChannel        0x02

#define BITMAP_Qualified_Signature 0x10
#define BITMAP_German_eID          0x20
#define BITMAP_PACE                0x40
#define BITMAP_DestroyPACEChannel  0x80

#define PIN_ID_MRZ 0x01
#define PIN_ID_CAN 0x02
#define PIN_ID_PIN 0x03
#define PIN_ID_PUK 0x04

/*
 *
 */
PCSCReader::PCSCReader (
  const string& readerName,
  vector<ICardDetector*>& detector ) : IReader ( readerName, detector ),
    m_hCard ( 0x0 ),
#if defined(_WIN32)
    m_dwProtocol(SCARD_PROTOCOL_UNDEFINED),
#else
    m_dwProtocol(SCARD_PROTOCOL_UNSET),
#endif
    m_hScardContext ( 0x0 )
{
  DWORD retValue = SCARD_S_SUCCESS, recvlen, result;
  BYTE recvbuf[1024];
  BYTE sendbuf[] = {
      FUNCTION_GetReadersPACECapabilities,
      0x00,              /* lengthInputData */
      0x00,              /* lengthInputData */
  };
  size_t i;
  
  if ( ( retValue = SCardEstablishContext ( /*SCARD_SCOPE_USER*/ SCARD_SCOPE_SYSTEM,
                    0x0, 0x0, &m_hScardContext ) ) != SCARD_S_SUCCESS )
    eCardCore_warn ( "SCardEstablishContext failed. 0x%08X (%s:%d)", retValue,
                     __FILE__, __LINE__ );

#if defined(UNICODE) || defined(_UNICODE)
  WCHAR* _readerName = new WCHAR[m_readerName.size() + 1];  
  mbstowcs(_readerName, m_readerName.c_str(), m_readerName.size());
  _readerName[m_readerName.size()] = 0;
  
  retValue = SCardConnect ( m_hScardContext, _readerName, SCARD_SHARE_DIRECT,
                                   m_dwProtocol, &m_hCard, &m_dwProtocol );

  delete [] _readerName;
#else
  retValue = SCardConnect ( m_hScardContext, m_readerName.c_str(), SCARD_SHARE_DIRECT,
                                   m_dwProtocol, &m_hCard, &m_dwProtocol );
#endif

  if ( retValue != SCARD_S_SUCCESS )
  {
    eCardCore_warn ( "SCardConnect for %s failed. 0x%08X (%s:%d)",
                     m_readerName.c_str(), retValue,  __FILE__, __LINE__ );
  }

  /* does the reader support PACE? */
  m_ioctl_pace = 0;
#if ENABLE_PACE
  recvlen = sizeof(recvbuf);
  retValue = SCardControl(m_hCard, CM_IOCTL_GET_FEATURE_REQUEST, NULL, 0,
          recvbuf, sizeof(recvbuf), &recvlen);
  if (retValue != SCARD_S_SUCCESS) {
      eCardCore_warn ( "SCardControl for the reader's features failed. 0x%08X (%s:%d)",
              retValue,  __FILE__, __LINE__ );
  }

  for (i = 0; i <= recvlen-PCSC_TLV_ELEMENT_SIZE; i += PCSC_TLV_ELEMENT_SIZE) {
      if (recvbuf[i] == FEATURE_EXECUTE_PACE) {
          memcpy(&m_ioctl_pace, recvbuf+i+2, 4);
      }
  }

  if (0 == m_ioctl_pace)
      eCardCore_info ("Reader does not support PACE");
  else {
      /* convert to host byte order to use for SCardControl */
      m_ioctl_pace = ntohl(m_ioctl_pace);

      recvlen = sizeof(recvbuf);
      retValue = SCardControl(m_hCard, m_ioctl_pace, sendbuf, sizeof sendbuf,
              recvbuf, sizeof(recvbuf), &recvlen);
      if (retValue == SCARD_S_SUCCESS
              && recvlen == 7
              && recvbuf[0] == 0 && recvbuf[1] == 0
              && recvbuf[2] == 0 && recvbuf[3] == 0) {
          if (recvbuf[6] & BITMAP_Qualified_Signature)
              eCardCore_info ("Reader supports qualified signature");
          if (recvbuf[6] & BITMAP_German_eID)
              eCardCore_info ("Reader supports German eID");
          if (recvbuf[6] & BITMAP_PACE)
              eCardCore_info ("Reader supports PACE");
          else
              m_ioctl_pace = 0;
          if (recvbuf[6] & BITMAP_DestroyPACEChannel)
              eCardCore_info ("Reader supports DestroyPACEChannel");
      } else {
          eCardCore_warn ("Error executing GetReadersPACECapabilities");
          m_ioctl_pace = 0;
      }
  }
#endif
}

/*
 *
 */
PCSCReader::~PCSCReader (
  void )
{
  SCardReleaseContext ( m_hScardContext );
}

/*
 *
 */
bool PCSCReader::open (
  void )
{
  // No valid context so we should leave ...

  if ( 0x00 == m_hScardContext )
    return false;

  long retValue = SCARD_S_SUCCESS;

  retValue = SCardReconnect(m_hCard, SCARD_SHARE_SHARED, SCARD_PROTOCOL_ANY,
          SCARD_LEAVE_CARD, &m_dwProtocol);

#if !defined(__APPLE__)
  BYTE atr[512];
  DWORD len = sizeof(atr);

  SCardGetAttrib(m_hCard, SCARD_ATTR_ATR_STRING, (LPBYTE) &atr, &len);
#else
  unsigned char atr[512];
  uint32_t len = sizeof(atr);
    
  char szReader[128];
  uint32_t cch = 128;
  uint32_t dwState;
  uint32_t dwProtocol;	  
    
  SCardStatus(m_hCard, szReader, &cch, &dwState, &dwProtocol, (unsigned char*)&atr, &len);
#endif
    
  for (DWORD i = 0; i < len; i++)
    eCardCore_debug ( "ATR: 0x%02X", atr[i]);
                     
  return true;
}

/*
 *
 */
ICard* PCSCReader::getCard (
  void )
{
  ICard* card = 0x0;

  for ( vector<ICardDetector*>::iterator it = m_cardDetectors.begin();
        it != m_cardDetectors.end(); it++ )
  {
    card = ( ( ICardDetector* ) * it )->getCard ( this );

    if ( card != 0x0 )
      break;
  }

  return card;
}

/*
 *
 */
void PCSCReader::close (
  void )
{
  SCardDisconnect ( m_hCard, SCARD_RESET_CARD );
  m_hCard = 0x0;
}

/*!
 *
 */
bool PCSCReader::sendAPDU (
  UINT64 cardID,
  const CardCommand& cmd,
  CardResult& res,
  const string& logMsg)
{
  // No valid card so we should leave ...

  if ( 0x00 == m_hCard )
    return false;
#if !defined(__APPLE__)
  DWORD returned = ( DWORD ) res.size();
#else
  uint32_t returned = (uint32_t) res.size();
#endif

  long retValue = SCARD_S_SUCCESS;

  CardCommand& c = const_cast<CardCommand&> ( cmd );

  if (logMsg.length() > 0)
    eCardCore_debug ( "###-> %s",  logMsg.c_str());

#if defined(_WIN32)
  eCardCore_debug ( "Send APDU to card 0x%I64X: %s", cardID, c.asString().c_str() );
#else
  eCardCore_debug ( "Send APDU to card 0x%llX: %s", cardID, c.asString().c_str() );
#endif    

  if((retValue = SCardTransmit ( m_hCard, SCARD_PCI_T1, &cmd[0],
    ( DWORD ) cmd.size(), NULL, &res[0], &returned )) != SCARD_S_SUCCESS)
  {
    eCardCore_warn ( "SCardTransmit failed. 0x%08X (%s:%lu)", retValue,
                     __FILE__, __LINE__ );
    return false;
  }
  
  if ( 0 == returned )
  {
    eCardCore_debug ( "SCardTransmit failed. No SW is returned." );
    return false;
  }
    
  res.resize ( returned );

  eCardCore_debug ( "Returned data: %s", res.asString().c_str() );
  eCardCore_debug ( "SW: 0x%04X", res.getSW() );

  return res.isOK();
}

vector<BYTE> PCSCReader::getATRForPresentCard()
{
  vector<BYTE> atr;

  if (0x00 == m_hCard)
    return atr;

#if !defined(__APPLE__)
  DWORD atrSize;
  SCardGetAttrib(m_hCard, SCARD_ATTR_ATR_STRING, 0x00, &atrSize);

  atr.reserve(atrSize);
  atr.resize(atrSize);
  SCardGetAttrib(m_hCard, SCARD_ATTR_ATR_STRING, &atr[0], &atrSize);
#else
  unsigned char atr_[512];
	uint32_t len = sizeof(atr_);
	
	char szReader[128];
	uint32_t cch = 128;
	uint32_t dwState;
	uint32_t dwProtocol;	  
	
	SCardStatus(m_hCard, szReader, &cch, &dwState, &dwProtocol, (unsigned char*)&atr_, &len); 
	
	for (int i = 0; i < len; i++)
		atr.push_back(atr_[i]);
#endif
  return atr;
}

bool PCSCReader::supportsPACE(void)
{
    if (0 == m_ioctl_pace)
        return false;

    return true;
}

static PaceOutput
parse_EstablishPACEChannel_OutputData(BYTE *output, size_t output_length)
{
    size_t parsed = 0;
    BYTE lengthCAR, lengthCARprev;
    USHORT lengthOutputData, lengthEF_CardAccess, length_IDicc, mse_setat;
    vector<BYTE> CAR, CARprev, EF_CardAccess, IDicc;
    DWORD result;
    PaceOutput paceoutput;

    /* Output Data */
    if (parsed+sizeof result > output_length) {
        eCardCore_warn("Malformed Establish PACE Channel output data.");
        return paceoutput;
    }
    memcpy(&result, output+parsed, sizeof result);
    switch (result) {
        case 0x00000000:
            break;
        case 0xD0000001:
            eCardCore_warn("Längen im Input sind inkonsistent");
            return paceoutput;
        case 0xD0000002:
            eCardCore_warn("Unerwartete Daten im Input");
            return paceoutput;
        case 0xD0000003:
            eCardCore_warn("Unerwartete Kombination von Daten im Input");
            return paceoutput;
        case 0xE0000001:
            eCardCore_warn("Syntaxfehler im Aufbau der TLV-Antwortdaten");
            return paceoutput;
        case 0xE0000002:
            eCardCore_warn("Unerwartete/fehlende Objekte in den TLV-Antwortdaten");
            return paceoutput;
        case 0xE0000003:
            eCardCore_warn("Der Kartenleser kennt die PIN-ID nicht.");
            return paceoutput;
        case 0xE0000006:
            eCardCore_warn("Fehlerhaftes PACE-Token");
            return paceoutput;
        case 0xE0000007:
            eCardCore_warn("Zertifikatskette für Terminalauthentisierung kann nicht gebildet werden");
            return paceoutput;
        case 0xE0000008:
            eCardCore_warn("Unerwartete Datenstruktur in Rückgabe der Chipauthentisierung");
            return paceoutput;
        case 0xE0000009:
            eCardCore_warn("Passive Authentisierung fehlgeschlagen");
            return paceoutput;
        case 0xE000000A:
            eCardCore_warn("Fehlerhaftes Chipauthentisierung-Token");
            return paceoutput;
        case 0xF0100001:
            eCardCore_warn("Kommunikationsabbruch mit Karte.");
            return paceoutput;
        default:
            eCardCore_warn("Reader reported some error.");
            return paceoutput;
    }
    paceoutput.set_result(result);
    parsed += sizeof result;

    /* Output Data */
    if (parsed+sizeof lengthOutputData > output_length) {
        eCardCore_warn("Malformed Establish PACE Channel output data.");
        return paceoutput;
    }
    memcpy(&lengthOutputData, output+parsed, sizeof lengthOutputData);
    parsed += sizeof lengthOutputData;
    if (lengthOutputData != output_length-parsed) {
        eCardCore_warn("Malformed Establish PACE Channel output data.");
        return paceoutput;
    }

    /* MSE:Set AT */
    if (parsed+sizeof mse_setat > output_length) {
        eCardCore_warn("Malformed Establish PACE Channel output data.");
        return paceoutput;
    }
    memcpy(&mse_setat, output+parsed, sizeof mse_setat);
    paceoutput.set_status_mse_set_at(mse_setat);
    parsed += sizeof mse_setat;

    /* lengthEF_CardAccess */
    if (parsed+2 > output_length) {
        eCardCore_warn("Malformed Establish PACE Channel output data.");
        return paceoutput;
    }
    memcpy(&lengthEF_CardAccess, output+parsed, sizeof lengthEF_CardAccess);
    parsed += sizeof lengthEF_CardAccess;

    /* EF.CardAccess */
    if (parsed+lengthEF_CardAccess > output_length) {
        eCardCore_warn("Malformed Establish PACE Channel output data.");
        return paceoutput;
    }
    EF_CardAccess.reserve(lengthEF_CardAccess);
    EF_CardAccess.resize(lengthEF_CardAccess);
    memcpy(&EF_CardAccess[0], output+parsed, lengthEF_CardAccess);
    parsed += lengthEF_CardAccess;

    /* lengthCAR */
    if (parsed+sizeof lengthCAR > output_length) {
        eCardCore_warn("Malformed Establish PACE Channel output data.");
        return paceoutput;
    }
    memcpy(&lengthCAR, output+parsed, sizeof lengthCAR);
    parsed += sizeof lengthCAR;

    /* CAR */
    if (parsed+lengthCAR > output_length) {
        eCardCore_warn("Malformed Establish PACE Channel output data.");
        return paceoutput;
    }
    CAR.reserve(lengthCAR);
    CAR.resize(lengthCAR);
    memcpy(&CAR[0], output+parsed, lengthCAR);
    parsed += lengthCAR;

    /* lengthCARprev */
    if (parsed+sizeof lengthCARprev > output_length) {
        eCardCore_warn("Malformed Establish PACE Channel output data.");
        return paceoutput;
    }
    memcpy(&lengthCARprev, output+parsed, sizeof lengthCARprev);
    parsed += sizeof lengthCARprev;

    /* CARprev */
    if (parsed+lengthCARprev > output_length) {
        eCardCore_warn("Malformed Establish PACE Channel output data.");
        return paceoutput;
    }
    CARprev.reserve(lengthCARprev);
    CARprev.resize(lengthCARprev);
    memcpy(&CARprev[0], output+parsed, lengthCARprev);
    parsed += lengthCARprev;

    /* lengthIDicc */
    if (parsed+sizeof length_IDicc > output_length) {
        eCardCore_warn("Malformed Establish PACE Channel output data.");
        return paceoutput;
    }
    memcpy(&length_IDicc , output+parsed, sizeof length_IDicc);
    parsed += sizeof length_IDicc;

    /* IDicc */
    if (parsed+length_IDicc > output_length) {
        eCardCore_warn("Malformed Establish PACE Channel output data.");
        return paceoutput;
    }
    IDicc.reserve(length_IDicc);
    IDicc.resize(length_IDicc);
    memcpy(&IDicc[0], output+parsed, length_IDicc);
    parsed += length_IDicc;

    if (parsed != output_length) {
        eCardCore_warn("Overrun by %d bytes", output_length - parsed);
        return paceoutput;
    }

    return paceoutput;
}

PaceOutput PCSCReader::establishPACEChannel(PaceInput input)
{
    PaceOutput output;

    DWORD r, recvlen, result;
    BYTE length_CHAT, length_PIN, PinID;
    USHORT lengthInputData, lengthCertificateDescription;
    BYTE recvbuf[1024];

    length_CHAT = input.get_chat().size();
    length_PIN = input.get_pin().size();
    lengthCertificateDescription = input.get_certificate_description().size();
    lengthInputData = sizeof PinID
        + sizeof length_CHAT + length_CHAT
        + sizeof length_PIN + length_PIN
        + sizeof lengthCertificateDescription + lengthCertificateDescription;

    size_t sendlen = 1+2+lengthInputData;
    BYTE *sendbuf = (BYTE *) malloc(sendlen);
    if (!sendbuf) {
        eCardCore_warn("%s:%d", __FILE__, __LINE__);
        return output;
    }


    switch (input.get_pin_id()) {
        case PaceInput::mrz:
            PinID = PIN_ID_MRZ;
            break;
        case PaceInput::pin:
            PinID = PIN_ID_PIN;
            break;
        case PaceInput::can:
            PinID = PIN_ID_CAN;
            break;
        case PaceInput::puk:
            PinID = PIN_ID_PUK;
            break;
        default:
            PinID = 0;
            break;
    }

    *sendbuf = FUNCTION_EstabishPACEChannel;
    memcpy(sendbuf+1,
            &lengthInputData, sizeof lengthInputData);
    memcpy(sendbuf+1+sizeof lengthInputData,
            &PinID, sizeof PinID);
    memcpy(sendbuf+1+sizeof lengthInputData+sizeof PinID,
            &length_CHAT, sizeof length_CHAT);
    memcpy(sendbuf+1+sizeof lengthInputData+sizeof PinID+sizeof length_CHAT,
            &input.get_chat()[0], length_CHAT);
    memcpy(sendbuf+1+sizeof lengthInputData+sizeof PinID+sizeof length_CHAT+length_CHAT,
            &length_PIN, sizeof length_PIN);
    memcpy(sendbuf+1+sizeof lengthInputData+sizeof PinID+sizeof length_CHAT+length_CHAT+sizeof length_PIN,
            &input.get_pin()[0], length_PIN);
    memcpy(sendbuf+1+sizeof lengthInputData+sizeof PinID+sizeof length_CHAT+length_CHAT+sizeof length_PIN+length_PIN,
            &lengthCertificateDescription, sizeof lengthCertificateDescription);
    memcpy(sendbuf+1+sizeof lengthInputData+sizeof PinID+sizeof length_CHAT+length_CHAT+sizeof length_PIN+length_PIN+sizeof lengthCertificateDescription,
            &input.get_certificate_description()[0], lengthCertificateDescription);

    recvlen = sizeof(recvbuf);
    r = SCardControl(m_hCard, m_ioctl_pace, sendbuf, sendlen,
            recvbuf, sizeof(recvbuf), &recvlen);

    free(sendbuf);

    return parse_EstablishPACEChannel_OutputData(recvbuf, recvlen);
}
