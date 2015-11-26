/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#include "ICard.h"
#include "PCSCReader.h"
#include "eCardCore/pace_reader.h"
#include <debug.h>

#ifdef _WIN32
//#include <winsock2.h>
#else
#include <reader.h>
#include <arpa/inet.h>
#endif
#if defined(__APPLE__)
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#else
#include <cstdint>
#include <cstdlib>
#include <cstring>
#endif //defined(__APPLE__)

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

/*
 *
 */
PCSCReader::PCSCReader(
	const std::string &readerName,
	std::vector<ICardDetector *>& detector) : IndividualReader(readerName, detector),
	m_hCard(0x0),
#if defined(_WIN32)
	m_dwProtocol(SCARD_PROTOCOL_UNDEFINED),
#elif defined(__APPLE__)
	m_dwProtocol(SCARD_PROTOCOL_ANY),
#else
	m_dwProtocol(SCARD_PROTOCOL_UNSET),
#endif
	m_hScardContext(0x0)
{
	DWORD retValue = SCARD_S_SUCCESS;

	if ((retValue = SCardEstablishContext(/*SCARD_SCOPE_USER*/ SCARD_SCOPE_SYSTEM,
					0x0, 0x0, &m_hScardContext)) != SCARD_S_SUCCESS)
		eCardCore_warn(DEBUG_LEVEL_READER,  "SCardEstablishContext failed. 0x%08X (%s:%d)", retValue,
					   __FILE__, __LINE__);

#if defined(UNICODE) || defined(_UNICODE)
	WCHAR *_readerName = new WCHAR[m_readerName.size() + 1];
	mbstowcs(_readerName, m_readerName.c_str(), m_readerName.size());
	_readerName[m_readerName.size()] = 0;
	retValue = SCardConnect(m_hScardContext, _readerName, SCARD_SHARE_DIRECT,
							m_dwProtocol, &m_hCard, &m_dwProtocol);
	delete [] _readerName;
#else
	retValue = SCardConnect(m_hScardContext, m_readerName.c_str(), SCARD_SHARE_DIRECT,
							m_dwProtocol, &m_hCard, &m_dwProtocol);
#endif

	if (retValue != SCARD_S_SUCCESS) {
		eCardCore_warn(DEBUG_LEVEL_READER,  "SCardConnect for %s failed. 0x%08X (%s:%d)",
					   m_readerName.c_str(), retValue,  __FILE__, __LINE__);
	}

	/* does the reader support PACE? */
	m_ioctl_pace = 0;
#if ENABLE_PACE
	BYTE recvbuf[1024];
	DWORD recvlen = sizeof(recvbuf);
	retValue = SCardControl(m_hCard, CM_IOCTL_GET_FEATURE_REQUEST, NULL, 0,
							recvbuf, sizeof(recvbuf), &recvlen);

	if (retValue != SCARD_S_SUCCESS) {
		eCardCore_warn(DEBUG_LEVEL_READER,  "SCardControl for the reader's features failed. 0x%08X (%s:%d)",
					   retValue,  __FILE__, __LINE__);

	} else {
		for (size_t i = 0; i + PCSC_TLV_ELEMENT_SIZE <= recvlen; i += PCSC_TLV_ELEMENT_SIZE)
			if (recvbuf[i] == FEATURE_EXECUTE_PACE)
				memcpy(&m_ioctl_pace, recvbuf + i + 2, 4);
	}

	if (0 == m_ioctl_pace) {
		eCardCore_info(DEBUG_LEVEL_READER, "Reader does not support PACE");

	} else {
		/* convert to host byte order to use for SCardControl */
		m_ioctl_pace = ntohl(m_ioctl_pace);

		std::vector<unsigned char> sendbuf = getReadersPACECapabilities_getBuffer();

		hexdump(DEBUG_LEVEL_READER, "Execute PACE Input Data (FUNCTION=GetReadersPACECapabilities)", DATA(sendbuf), sendbuf.size());
		recvlen = sizeof(recvbuf);
		retValue = SCardControl(m_hCard, m_ioctl_pace, DATA(sendbuf), sendbuf.size(),
								recvbuf, sizeof(recvbuf), &recvlen);
		hexdump(DEBUG_LEVEL_READER, "Execute PACE Output Data (FUNCTION=GetReadersPACECapabilities)", recvbuf, recvlen);

		if (retValue == SCARD_S_SUCCESS) {
			if (!getReadersPACECapabilities_supportsPACE(recvbuf, recvlen))
				m_ioctl_pace = 0;
		} else {
			eCardCore_warn(DEBUG_LEVEL_READER, "Error executing GetReadersPACECapabilities");
			m_ioctl_pace = 0;
		}
	}

#endif
}

/*
 *
 */
PCSCReader::~PCSCReader(
	void)
{
	SCardReleaseContext(m_hScardContext);
}

/*
 *
 */
bool PCSCReader::open(
	void)
{
	// No valid context so we should leave ...
	if (0x00 == m_hScardContext)
		return false;

	long retValue = SCARD_S_SUCCESS;
	retValue = SCardReconnect(m_hCard, SCARD_SHARE_SHARED, SCARD_PROTOCOL_ANY,
							  SCARD_RESET_CARD, &m_dwProtocol);
	if(0x00 == m_hCard)
		return false;

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
	SCardStatus(m_hCard, szReader, &cch, &dwState, &dwProtocol, (unsigned char *)&atr, &len);
#endif
	return true;
}

/*
 *
 */
void PCSCReader::close(
	void)
{
	SCardDisconnect(m_hCard, SCARD_RESET_CARD);
	m_hCard = 0x0;
}

std::vector <unsigned char> PCSCReader::transceive(
	const std::vector<unsigned char>& cmd)
{
	BYTE res[RAPDU::RAPDU_EXTENDED_MAX];
	DWORD reslen = sizeof res;
	DWORD r = SCARD_S_SUCCESS;
	std::vector <unsigned char> result;

	if (0x00 == m_hCard) {
		eCardCore_info(DEBUG_LEVEL_READER, "Not connected to any card");
		throw WrongHandle();
	}

	hexdump(DEBUG_LEVEL_READER, "SCardTransmit data", DATA(cmd), cmd.size());

	//startTimer on Smartcard Operationtime if Debugging
	startTimer();

	r = SCardTransmit(m_hCard, SCARD_PCI_T1, DATA(cmd),
					  (DWORD) cmd.size(), NULL, res, &reslen);

	//stopTimer on Smartcard Operationtime if Debugging
	stopTimer();

	if (r != SCARD_S_SUCCESS)
		throw TransactionFailed();

	hexdump(DEBUG_LEVEL_READER, "SCardTransmit response", res, reslen);

	return std::vector<unsigned char>(res, res + reslen);
}

std::vector<BYTE> PCSCReader::getATRForPresentCard()
{
	std::vector<BYTE> atr;

	if (0x00 == m_hCard)
		return atr;

#if !defined(__APPLE__)
	DWORD atrSize = 0;
	if (SCARD_S_SUCCESS != SCardGetAttrib(m_hCard, SCARD_ATTR_ATR_STRING, 0x00, &atrSize))
		goto err;
	atr.reserve(atrSize);
	atr.resize(atrSize);
	if (SCARD_S_SUCCESS != SCardGetAttrib(m_hCard, SCARD_ATTR_ATR_STRING, DATA(atr), &atrSize)) {
		atr.clear();
		goto err;
	}
#else
	unsigned char atr_[512];
	uint32_t len = sizeof(atr_);
	char szReader[128];
	uint32_t cch = 128;
	uint32_t dwState;
	uint32_t dwProtocol;
	if (SCARD_S_SUCCESS != SCardStatus(m_hCard, szReader, &cch, &dwState, &dwProtocol, (unsigned char *)&atr_, &len))
		goto err;

	for (int i = 0; i < len; i++)
		atr.push_back(atr_[i]);

#endif
err:
	return atr;
}

bool PCSCReader::supportsPACEnative(void)
{
	if (0 == m_ioctl_pace)
		return false;

	return true;
}

PaceOutput PCSCReader::establishPACEChannelNative(const PaceInput &input)
{
	PaceOutput output;
	DWORD r, recvlen;
	BYTE recvbuf[1024];

	std::vector<unsigned char> sendbuf = establishPACEChannel_getBuffer(input);

	hexdump(DEBUG_LEVEL_READER, "Execute PACE Input Data (FUNCTION=EstabishPACEChannel)", DATA(sendbuf), sendbuf.size());
	recvlen = sizeof(recvbuf);
	r = SCardControl(m_hCard, m_ioctl_pace, DATA(sendbuf), sendbuf.size(),
					 recvbuf, sizeof(recvbuf), &recvlen);
	hexdump(DEBUG_LEVEL_READER, "Execute PACE Output Data (FUNCTION=EstabishPACEChannel)", recvbuf, recvlen);

	return establishPACEChannel_parseBuffer(recvbuf, recvlen);
}
