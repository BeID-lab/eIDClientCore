/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#include "ICard.h"
#include "IReaderManager.h"

/*
 *
 */
ICard::ICard (
  IReader* subSystem ) : m_subSystem ( subSystem )
{}

/*
 *
 */
ICard::~ICard()
{
  m_subSystem->close();
}


/*
 *
 */
RAPDU ICard::sendAPDU(const CAPDU& cmd)
{
  eCardCore_info(DEBUG_LEVEL_APDU, "Outgoing APDU:  CLA=%02X  INS=%02X  P1=%02X  P2=%02X  Nc=%-' '5u  Ne=%u",
          cmd.getCLA(), cmd.getINS(), cmd.getP1(), cmd.getP2(),
          cmd.getData().size(), cmd.getNe());
  if (!cmd.getData().empty())
      hexdump(DEBUG_LEVEL_APDU, NULL, &cmd.getData()[0], cmd.getData().size());

  RAPDU rapdu = RAPDU(m_subSystem->sendAPDU( cmd.asBuffer()));

  eCardCore_info(DEBUG_LEVEL_APDU, "Incoming APDU:  SW=%04X  Nr=%u", rapdu.getSW(), rapdu.getData().size());
  if (!rapdu.getData().empty())
      hexdump(DEBUG_LEVEL_APDU, NULL, &rapdu.getData()[0], rapdu.getData().size());

  return rapdu;
}


const IReader *ICard::getSubSystem(void) const
{
  return ( IReader* ) m_subSystem;
}
