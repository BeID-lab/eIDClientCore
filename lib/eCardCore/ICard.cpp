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

void ICard::debug_CAPDU(const char *label, const CAPDU& capdu) const
{
	eCardCore_info(DEBUG_LEVEL_APDU, "%s%sC-APDU:  CLA=%02X  INS=%02X  P1=%02X  P2=%02X  Nc=%-' '5u  Ne=%u",
			label, label ? " " : "", capdu.getCLA(), capdu.getINS(), capdu.getP1(),
			capdu.getP2(), capdu.getData().size(), capdu.getNe());
	hexdump(DEBUG_LEVEL_APDU, NULL,
			DATA(capdu.getData()), capdu.getData().size());
}

void ICard::debug_RAPDU(const char *label, const RAPDU& rapdu) const
{
	eCardCore_info(DEBUG_LEVEL_APDU, "%s%sR-APDU:  SW=%04X  Nr=%u",
			label, label ? " " : "", rapdu.getSW(), rapdu.getData().size());
	if (!rapdu.getData().empty())
		hexdump(DEBUG_LEVEL_APDU, NULL,
				DATA(rapdu.getData()), rapdu.getData().size());
}

std::vector<std::vector<unsigned char> >
ICard::get_buffers(std::vector<CAPDU> apdus)
{
	std::vector<std::vector<unsigned char> > buffers;

	for (std::vector<CAPDU>::const_iterator i = apdus.begin(); i < apdus.end(); ++i) {
		debug_CAPDU("Outgoing", *i);
		buffers.push_back(i->asBuffer());
	}

	return buffers;
}

std::vector<RAPDU>
ICard::get_rapdus(std::vector<std::vector<unsigned char> > buffers)
{
	std::vector<RAPDU> rapdus;

	for (std::vector<std::vector<unsigned char> >::const_iterator i = buffers.begin(); i < buffers.end(); ++i) {
		RAPDU rapdu(*i);
		debug_RAPDU("Incoming", rapdu);
		rapdus.push_back(rapdu);
	}

	return rapdus;
}

RAPDU ICard::transceive(const CAPDU &cmd)
{
	debug_CAPDU("Outgoing", cmd);
	
	RAPDU rapdu(m_subSystem->transceive(cmd.asBuffer()));
	debug_RAPDU("Incoming", rapdu);

	return rapdu;
}

std::vector<RAPDU> ICard::transceive(const std::vector<CAPDU> &cmds)
{
	return get_rapdus(m_subSystem->transceive(get_buffers(cmds)));
}

IReader *ICard::getSubSystem(void) const
{
	return m_subSystem;
}

bool ICard::selectMF(
	void)
{
	SelectFile select(SelectFile::P1_SELECT_FID, SelectFile::P2_NO_RESPONSE);
	RAPDU response = transceive(select);
	return response.isOK();
}

bool ICard::selectEF(
	unsigned short FID)
{
	SelectFile select(SelectFile::P1_SELECT_EF, SelectFile::P2_NO_RESPONSE, FID);
	RAPDU response = transceive(select);
	return response.isOK();
}

bool ICard::selectEF(
	unsigned short FID,
	std::vector<unsigned char>& fcp)
{
	SelectFile select(SelectFile::P1_SELECT_EF, SelectFile::P2_FCP_TEMPLATE, FID);
	select.setNe(CAPDU::DATA_SHORT_MAX);
	RAPDU response = transceive(select);
	fcp = response.getData();
	return response.isOK();
}

bool ICard::selectDF(
	unsigned short FID)
{
	SelectFile select(SelectFile::P1_SELECT_DF, SelectFile::P2_NO_RESPONSE, FID);
	RAPDU response = transceive(select);
	return response.isOK();
}

bool ICard::readFile(
	unsigned char sfid,
	size_t chunk_size,
	std::vector<unsigned char>& result)
{
	ReadBinary read = ReadBinary(0, sfid);
	read.setNe(chunk_size);
	RAPDU response = transceive(read);

	while (response.isOK() && response.getData().size() == chunk_size) {
		result.insert(result.end(), response.getData().begin(), response.getData().end());

		read = ReadBinary(result.size());
		read.setNe(chunk_size);
		response = transceive(read);
	}

	result.insert(result.end(), response.getData().begin(), response.getData().end());

	if (result.empty()) {
		return response.isOK();
	}

	return true;
}

bool ICard::readFile(
	std::vector<unsigned char>& result)
{
	ReadBinary read = ReadBinary();
	read.setNe(CAPDU::DATA_EXTENDED_MAX);
	RAPDU response = transceive(read);
	result = response.getData();
	return response.isOK();
}
