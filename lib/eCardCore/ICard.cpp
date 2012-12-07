/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#include "ICard.h"
#include "CardCommand.h"
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

bool ICard::selectMF(
	void)
{
	SelectFile select(SelectFile::P1_SELECT_FID, SelectFile::P2_NO_RESPONSE);
	RAPDU response = sendAPDU(select);
	return response.isOK();
}

bool ICard::selectEF(
	unsigned short FID)
{
	SelectFile select(SelectFile::P1_SELECT_EF, SelectFile::P2_NO_RESPONSE, FID);
	RAPDU response = sendAPDU(select);
	return response.isOK();
}

bool ICard::selectEF(
	unsigned short FID,
	vector<unsigned char>& fcp)
{
	SelectFile select(SelectFile::P1_SELECT_EF, SelectFile::P2_FCP_TEMPLATE, FID);
	select.setNe(CAPDU::DATA_SHORT_MAX);
	RAPDU response = sendAPDU(select);
	fcp = response.getData();
	return response.isOK();
}

bool ICard::selectDF(
	unsigned short FID)
{
	SelectFile select(SelectFile::P1_SELECT_DF, SelectFile::P2_NO_RESPONSE, FID);
	RAPDU response = sendAPDU(select);
	return response.isOK();
}

bool ICard::readFile(
	unsigned char sfid,
	size_t chunk_size,
	vector<unsigned char>& result)
{
	ReadBinary read = ReadBinary(0, sfid);
	read.setNe(chunk_size);
	RAPDU response = sendAPDU(read);

	while (response.isOK() && response.getData().size() == chunk_size) {
		result.insert(result.end(), response.getData().begin(), response.getData().end());

		read = ReadBinary(result.size());
		read.setNe(chunk_size);
		response = sendAPDU(read);
	}

	result.insert(result.end(), response.getData().begin(), response.getData().end());

	if (result.empty()) {
		return response.isOK();
	}

	return true;
}

bool ICard::readFile(
	vector<unsigned char>& result)
{
	ReadBinary read = ReadBinary();
	read.setNe(CAPDU::DATA_EXTENDED_MAX);
	RAPDU response = sendAPDU(read);
	result = response.getData();
	return response.isOK();
}
