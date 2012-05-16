// ---------------------------------------------------------------------------
// Copyright (c) 2008 Bundesdruckerei GmbH.
// All rights reserved.
//
// $Id: ePACard.cpp 1310 2011-09-20 11:41:06Z x_schrom $
// ---------------------------------------------------------------------------

#include "ePACard.h"
using namespace Bundesdruckerei::nPA;

/*
 *
 */
ePACard::ePACard(
  ECARD_HANDLE hSubSystem) : ICard(hSubSystem)
{
}

/*
 *
 */
string ePACard::getCardDescription (
  void )
{
  return "German nPA";
}

/*
 *
 */
ECARD_PIN_STATE ePACard::getPinState (
  void )
{
  return PIN_STATE_ACTIVATED;
}

/*
 *
 */
bool ePACard::selectEF(
  unsigned short FID)
{
  CardCommand cardCmd;
  CardResult cardRes;

  IReader* reader = ( IReader* ) m_subSystem;

  cardCmd << 0x00 << 0xA4 << 0x02 << 0x0C << 0x02 << ((FID & 0xFF00) >> 8) << (FID & 0xFF);

  bool retValue = reader->sendAPDU ( m_chipID, cardCmd, cardRes, "" );
  m_lastSW = cardRes.getSW();

  return retValue;
}

bool ePACard::selectEF(
  unsigned short FID,
  vector<BYTE>& fcp)
{
  CardCommand cardCmd;
  CardResult cardRes;

  IReader* reader = ( IReader* ) m_subSystem;

  cardCmd << 0x00 << 0xA4 << 0x02 << 0x04 << 0x02 << ((FID & 0xFF00) >> 8) << (FID & 0xFF) << 0x00;

  bool retValue = reader->sendAPDU ( m_chipID, cardCmd, cardRes, "" );
  m_lastSW = cardRes.getSW();

  if (cardRes.isOK())
  {
    vector<BYTE> data = cardRes.getData();
    for (size_t i = 0; i < data.size(); i++)
      fcp.push_back(data[i]);
  }

  return retValue;
}

/*
 *
 */
bool ePACard::selectDF(
  unsigned short FID)
{
  CardCommand cardCmd;
  CardResult cardRes;

  IReader* reader = ( IReader* ) m_subSystem;

  cardCmd << 0x00 << 0xA4 << 0x01 << 0x0C << 0x02 << ((FID & 0xFF00) >> 8) << (FID & 0xFF);

  bool retValue = reader->sendAPDU ( m_chipID, cardCmd, cardRes, "" );
  m_lastSW = cardRes.getSW();

  return retValue;
}

/*
*
*/
bool ePACard::selectMF(
  void)
{
  CardCommand cardCmd;
  CardResult cardRes;

  IReader* reader = ( IReader* ) m_subSystem;

  cardCmd << 0x00 << 0xA4 << 0x00 << 0x0C << 0x02 << 0x3F << 0x00;

  bool retValue = reader->sendAPDU ( m_chipID, cardCmd, cardRes, "" );
  m_lastSW = cardRes.getSW();

  return retValue;
}

/*!
 *
 */
unsigned short ePACard::getFileSize(
  IN unsigned short FID)
{
  vector<BYTE> fci;
  selectEF(FID, fci);

  if (fci.size() == 0)
    return 0;

  if (fci[2] == 0x80)
  {
    //Very rarely used, but allowed
    if(fci[3] == 0x01)
      return fci[4];
    else if(fci[3] == 0x02)
      return (fci[4] << 8) + fci[5];
  }

  return 0;
}

/*
 *
 */
bool ePACard::readFile(
  unsigned short size,
  vector<BYTE>& result)
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

    retValue = reader->sendAPDU ( m_chipID, cardCmd, cardRes );

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

bool ePACard::sentAPDU(
  const CardCommand& cmd,
  vector<BYTE>& result)
{
  CardResult cardRes;
  IReader* reader = ( IReader* ) m_subSystem;
  bool retValue = false;

  retValue = reader->sendAPDU ( m_chipID, cmd, cardRes );
  m_lastSW = cardRes.getSW();

  for (size_t i = 0; i < cardRes.size(); i++)
    result.push_back(cardRes[i]);

  return retValue;
}

ICard* ePACardDetector::getCard(IReader* reader)
{    
  // @ATTENTION: Quick fix for BDr card reader. Remove for release!!
  return new ePACard(reader);

  vector<BYTE> atr = reader->getATRForPresentCard();
  if (atr.size() == 0)
    return 0x00;

  vector<BYTE> ePA_ATR;
  ePA_ATR.push_back(0x3B); ePA_ATR.push_back(0x84); 
  ePA_ATR.push_back(0x80); ePA_ATR.push_back(0x01); 
  ePA_ATR.push_back(0x00); ePA_ATR.push_back(0x00); 
  ePA_ATR.push_back(0x90); ePA_ATR.push_back(0x00); 
  ePA_ATR.push_back(0x95); 

  vector<BYTE> ePA_ATR2;
  ePA_ATR.push_back(0x3B); ePA_ATR.push_back(0xB4); 
  ePA_ATR.push_back(0x11); ePA_ATR.push_back(0x00); 
  ePA_ATR.push_back(0x81); ePA_ATR.push_back(0x31); 
  ePA_ATR.push_back(0x46); ePA_ATR.push_back(0x15); 
  ePA_ATR.push_back(0x00); ePA_ATR.push_back(0x00); 
  ePA_ATR.push_back(0x90); ePA_ATR.push_back(0x00);
  ePA_ATR.push_back(0xD6); 

  if (ePA_ATR == atr || ePA_ATR2 == atr)
    return new ePACard(reader);

  return 0x00;
}
