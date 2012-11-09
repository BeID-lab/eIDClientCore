/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#include "ICard.h"
#include "IReaderManager.h"

ICard::ICard(
	IReader *subSystem) : m_subSystem(subSystem)
{}

ICard::~ICard()
{
	if (m_subSystem)
		m_subSystem->close();
}

RAPDU ICard::sendAPDU(const CAPDU &cmd)
{
	eCardCore_info(DEBUG_LEVEL_APDU, "Outgoing APDU:  CLA=%02X  INS=%02X  P1=%02X  P2=%02X  Nc=%-' '5u  Ne=%u",
				   cmd.getCLA(), cmd.getINS(), cmd.getP1(), cmd.getP2(),
				   cmd.getData().size(), cmd.getNe());

	hexdump(DEBUG_LEVEL_APDU, NULL, cmd.getData().data(), cmd.getData().size());

	RAPDU rapdu = RAPDU(m_subSystem->sendAPDU(cmd.asBuffer()));
	eCardCore_info(DEBUG_LEVEL_APDU, "Incoming APDU:  SW=%04X  Nr=%u", rapdu.getSW(), rapdu.getData().size());

	if (!rapdu.getData().empty())
		hexdump(DEBUG_LEVEL_APDU, NULL, rapdu.getData().data(), rapdu.getData().size());

	return rapdu;
}

std::vector<RAPDU> ICard::sendAPDUs(const std::vector<CAPDU> &cmds)
{
	std::vector<vector<unsigned char> > apdus, rapdus;
	vector<RAPDU> r;

	for (size_t i = 0; i < cmds.size(); i++) {
		eCardCore_info(DEBUG_LEVEL_APDU, "Outgoing APDU:  CLA=%02X  INS=%02X  P1=%02X  P2=%02X  Nc=%-' '5u  Ne=%u",
				   cmds[i].getCLA(), cmds[i].getINS(), cmds[i].getP1(), cmds[i].getP2(),
				   cmds[i].getData().size(), cmds[i].getNe());

		hexdump(DEBUG_LEVEL_APDU, NULL, cmds[i].getData().data(), cmds[i].getData().size());

		apdus.push_back(cmds[i].asBuffer());
	}

	rapdus = m_subSystem->sendAPDUs(apdus);

	for (size_t i = 0; i < rapdus.size(); i++) {
		RAPDU response = RAPDU(rapdus[i]);

		eCardCore_info(DEBUG_LEVEL_APDU, "Incoming APDU:  SW=%04X  Nr=%u", response.getSW(), response.getData().size());

		hexdump(DEBUG_LEVEL_APDU, NULL, response.getData().data(), response.getData().size());

		r.push_back(response);
	}

	return r;
}

const IReader *ICard::getSubSystem(void) const
{
	return m_subSystem;
}
