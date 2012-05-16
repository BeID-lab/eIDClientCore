// ---------------------------------------------------------------------------
// Copyright (c) 2007 Bundesruckerei GmbH
// All rights reserved.
//
// $Id: PCSCReader.cpp 1373 2011-11-24 15:10:52Z x_schrom $
// ---------------------------------------------------------------------------

#if defined(__IPHONE_OS_VERSION_MIN_REQUIRED) && __IPHONE_OS_VERSION_MIN_REQUIRED >= __IPHONE_3_0
#else

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
  long retValue = SCARD_S_SUCCESS;
  
  if ( ( retValue = SCardEstablishContext ( /*SCARD_SCOPE_USER*/ SCARD_SCOPE_SYSTEM,
                    0x0, 0x0, &m_hScardContext ) ) != SCARD_S_SUCCESS )
    eCardCore_warn ( "SCardEstablishContext failed. 0x%08X (%s:%d)", retValue,
                     __FILE__, __LINE__ );
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

#if defined(UNICODE) || defined(_UNICODE)
  WCHAR* readerName = new WCHAR[m_readerName.size() + 1];  
  mbstowcs(readerName, m_readerName.c_str(), m_readerName.size());
  readerName[m_readerName.size()] = 0;
  
  if ( ( retValue = SCardConnect ( m_hScardContext, readerName, SCARD_SHARE_SHARED,
                                   SCARD_PROTOCOL_T1, &m_hCard, &m_dwProtocol ) ) != SCARD_S_SUCCESS )
  {
    delete [] readerName;
#else
  if ( ( retValue = SCardConnect ( m_hScardContext, m_readerName.c_str(), /*SCARD_SHARE_EXCLUSIVE*/ SCARD_SHARE_SHARED,
                                   SCARD_PROTOCOL_T1, &m_hCard, &m_dwProtocol ) ) != SCARD_S_SUCCESS )
  {
#endif
    eCardCore_warn ( "SCardConnect for %s failed. 0x%08X (%s:%d)",
                     m_readerName.c_str(), retValue,  __FILE__, __LINE__ );
    return false;
  }

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
                     
#if defined(UNICODE) || defined(_UNICODE)
  delete [] readerName;
#endif  
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

#endif // __IPHONE_OS_VERSION_MIN_REQUIRED >= __IPHONE_3_0