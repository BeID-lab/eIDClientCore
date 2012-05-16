// ---------------------------------------------------------------------------
// Copyright (c) 2007 Bundesruckerei GmbH
// All rights reserved.
//
// $Id: ICard.cpp 627 2010-01-28 09:19:47Z rfiedler $
// ---------------------------------------------------------------------------

/*!
 * @file ICard.cpp
 */

#include "ICard.h"
#include "IReaderManager.h"

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
ICard::ICard (
  ECARD_HANDLE subSystem ) : m_subSystem ( subSystem ),
     m_lastSW(0x0000), m_chipID(0xFFFFFFFFFFFFFFFFLL)
{}

/*
 *
 */
ICard::~ICard()
{
  IReader* reader = ( IReader* ) m_subSystem;
  reader->close();
}

/*
 *
 */
bool ICard::selectFile (
  unsigned short FID,
  const string& logMsg)
{
  CardCommand cardCmd = CardCommand::selectFile ( FID );
  CardResult cardRes;

  IReader* reader = ( IReader* ) m_subSystem;

  bool retValue = reader->sendAPDU ( m_chipID, cardCmd, cardRes, logMsg );
  m_lastSW = cardRes.getSW();

  return retValue;
}

/*
 *
 */
bool ICard::selectFile (
  const vector<BYTE>& longPath,
  vector<BYTE>& fci,
  const string& logMsg)
{
  CardResult cardRes;
  CardCommand cardCmd;
  cardCmd << 0x00 << 0xA4 << 0x08 << 0x00 << (BYTE) longPath.size();

  for (size_t i = 0; i < longPath.size(); i++)
    cardCmd << longPath[i];
  cardCmd << 0xFA;

  IReader* reader = ( IReader* ) m_subSystem;
  bool retValue = reader->sendAPDU ( m_chipID, cardCmd, cardRes, logMsg );
  m_lastSW = cardRes.getSW();

  if (cardRes.isOK())
  {
    vector<BYTE> data = cardRes.getData();
    for (size_t i = 0; i < data.size(); i++)
      fci.push_back(data[i]);
  }
  return retValue;
}

/*
 *
 */
bool ICard::selectFile (
  const vector<BYTE>& longPath,
  const string& logMsg)
{
  CardResult cardRes;
  CardCommand cardCmd;
  cardCmd << 0x00 << 0xA4 << 0x08 << 0x0C << (BYTE) longPath.size();

  for (size_t i = 0; i < longPath.size(); i++)
    cardCmd << longPath[i];
  //cardCmd << 0xFA;

  IReader* reader = ( IReader* ) m_subSystem;
  bool retValue = reader->sendAPDU ( m_chipID, cardCmd, cardRes, logMsg );
  m_lastSW = cardRes.getSW();

  return retValue;
}

/*
 *
 */
bool ICard::readRecord (
  BYTE record,
  vector<BYTE>& result)
{
  IReader* reader = ( IReader* ) m_subSystem;

  CardCommand cardCmd;
  cardCmd << 0x00 << 0xB2 << record << 0x00 << 0xFA;

  CardResult cardRes;
  bool retValue = reader->sendAPDU ( m_chipID, cardCmd, cardRes );
  m_lastSW = cardRes.getSW();

  if ( cardRes.isOK() )
    result = cardRes.getData();

  return retValue;
}

/*
 *
 */
bool ICard::readBinary (
  vector<BYTE>& result,
  const string& logMsg)
{
  IReader* reader = ( IReader* ) m_subSystem;

  CardCommand cardCmd;
  cardCmd << 0x00 << 0xB0 << 0x00 << 0x00 << 0x00;

  CardResult cardRes;
  bool retValue = reader->sendAPDU ( m_chipID, cardCmd, cardRes, logMsg );

  m_lastSW = cardRes.getSW();

  if ( cardRes.isOK() )
    result = cardRes.getData();

  return retValue;
}

/*
 *
 */
bool ICard::readBinary (
  vector<BYTE>& result,
  unsigned short size,
  const string& logMsg)
{
  IReader* reader = ( IReader* ) m_subSystem;

  CardCommand cardCmd;
  if (size < 0xC8)
    cardCmd << 0x00 << 0xB0 << 0x00 << 0x00 << (BYTE) size;
  else
    cardCmd << 0x00 << 0xB0 << 0x00 << 0x00 << 0xC8;

  unsigned short offset = 0;
  bool retValue = false;
  
  while (offset < size)
  {
    CardResult cardRes;
    cardCmd[2] = offset >> 8;
    cardCmd[3] = offset & 0xFF;

    if (size - offset > 0xC8)
      cardCmd[4] = 0xC8;
    else
      cardCmd[4] = size - offset;

    retValue = reader->sendAPDU ( m_chipID, cardCmd, cardRes, logMsg );

    m_lastSW = cardRes.getSW();

    if ( cardRes.isOK() )
    {
      for (size_t i = 0; i < cardRes.getData().size(); i++)
        result.push_back(cardRes.getData()[i]);
      
      offset += (unsigned short) cardRes.getData().size();

    } else {
      return retValue;
    }
  }

  return retValue;
}

/*!
 *
 */
bool ICard::writeBinary (
  const vector<BYTE>& data,
  const string& logMsg)
{
  IReader* reader  = ( IReader* ) m_subSystem;
  size_t offset    = 0;
  size_t blocksize = 0;
  bool retValue    = true;

  CardCommand cardCmd;
  CardResult cardRes;

  while (offset < data.size())
  {
    cardCmd.clear();
    blocksize = data.size() - offset;
    if (blocksize > CardResult::MAX_DATASIZE)
	  blocksize = CardResult::MAX_DATASIZE;

    cardCmd << 0x00 << 0xD6 << (BYTE) (offset >> 8) << (BYTE) (offset & 0xFF) << (BYTE) blocksize;
    for (size_t i = offset; i < offset + blocksize; i++)
      cardCmd << data[i];

    offset += blocksize;

    retValue = reader->sendAPDU ( m_chipID, cardCmd, cardRes, logMsg );
    m_lastSW = cardRes.getSW();

    if (!cardRes.isOK())
      break;
  }

  return retValue;
}

/*
 *
 */
bool ICard::generateRandom (
  BYTE size,
  vector<BYTE>& result)
{
  IReader* reader = ( IReader* ) m_subSystem;

  CardCommand cardCmd;
  cardCmd << 0x00 << 0x84 << 0x00 << 0x00 << size;

  CardResult cardRes;
  bool retValue = reader->sendAPDU ( m_chipID, cardCmd, cardRes );
  m_lastSW = cardRes.getSW();

  if ( cardRes.isOK() )
    result = cardRes.getData();

  return retValue;
}

/*
 *
 */
CardResult ICard::sendAPDU(
  const CardCommand& cmd,
  const string& logMsg)
{
  IReader* reader = ( IReader* ) m_subSystem;

  CardResult cardRes;
  reader->sendAPDU( m_chipID, cmd, cardRes, logMsg);

  return cardRes;
}

/*
 *
 */
bool ICard::verify(
  const string& pin,
  BYTE FID,
  PBYTE retryCount)
{
  IReader* reader = ( IReader* ) m_subSystem;

  CardCommand cardCmd;
  cardCmd << 0x00 << 0x20 << 0x00 << FID << (BYTE) pin.length();

  for(size_t i = 0; i < pin.length(); i++)
    cardCmd << pin[i];

  CardResult cardRes;

  reader->sendAPDU ( m_chipID, cardCmd, cardRes );
  m_lastSW = cardRes.getSW();

  if (cardRes.isOK())
    return true;

  if (0x6983 == m_lastSW)
    *retryCount = (BYTE) -2;
  else
    *retryCount = cardRes[1] & 0x0F;

  return false;
}

/*
 *
 */
bool ICard::readRetryCount(
  BYTE FID,
  PBYTE retryCount)
{
  IReader* reader = ( IReader* ) m_subSystem;

  CardCommand cardCmd;
  cardCmd << 0x00 << 0x20 << 0x00 << FID << 0x00;

  CardResult cardRes;

  reader->sendAPDU ( m_chipID, cardCmd, cardRes );
  m_lastSW = cardRes.getSW();

  if (0x6a81 == m_lastSW)
  {
    *retryCount = 0;
    return false;
  }

  if (0x6983 == m_lastSW)
    *retryCount = (BYTE) -2;
  else
    *retryCount = cardRes[1] & 0x0F;

  return true;
}

/*
 *
 */
UINT64 ICard::getChipId(
  void)
{
  return m_chipID;
}
