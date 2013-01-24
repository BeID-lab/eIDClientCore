/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#include "ICard.h"
#include "PCSCReader.h"
#include <debug.h>

#ifdef _WIN32
//#include <winsock2.h>
#else
#include <reader.h>
#include <arpa/inet.h>
#endif
#include <stdint.h>
#include <stdlib.h>
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
PCSCReader::PCSCReader(
	const string &readerName,
	vector<ICardDetector *>& detector) : IndividualReader(readerName, detector),
	m_hCard(0x0),
#if defined(_WIN32)
	m_dwProtocol(SCARD_PROTOCOL_UNDEFINED),
#else
	m_dwProtocol(SCARD_PROTOCOL_UNSET),
#endif
	m_hScardContext(0x0)
{
	DWORD retValue = SCARD_S_SUCCESS;
	BYTE sendbuf[] = {
		FUNCTION_GetReadersPACECapabilities,
		0x00,              /* lengthInputData */
		0x00,              /* lengthInputData */
	};

	if ((retValue = SCardEstablishContext(/*SCARD_SCOPE_USER*/ SCARD_SCOPE_SYSTEM,
					0x0, 0x0, &m_hScardContext)) != SCARD_S_SUCCESS)
		eCardCore_warn(DEBUG_LEVEL_CARD,  "SCardEstablishContext failed. 0x%08X (%s:%d)", retValue,
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
		eCardCore_warn(DEBUG_LEVEL_CARD,  "SCardConnect for %s failed. 0x%08X (%s:%d)",
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
		eCardCore_warn(DEBUG_LEVEL_CARD,  "SCardControl for the reader's features failed. 0x%08X (%s:%d)",
					   retValue,  __FILE__, __LINE__);

	} else {
		for (size_t i = 0; i + PCSC_TLV_ELEMENT_SIZE <= recvlen; i += PCSC_TLV_ELEMENT_SIZE)
			if (recvbuf[i] == FEATURE_EXECUTE_PACE)
				memcpy(&m_ioctl_pace, recvbuf + i + 2, 4);
	}

	if (0 == m_ioctl_pace) {
		eCardCore_info(DEBUG_LEVEL_CARD, "Reader does not support PACE");

	} else {
		/* convert to host byte order to use for SCardControl */
		m_ioctl_pace = ntohl(m_ioctl_pace);
		hexdump(DEBUG_LEVEL_CARD, "Execute PACE Input Data (FUNCTION=GetReadersPACECapabilities)", sendbuf, sizeof sendbuf);
		recvlen = sizeof(recvbuf);
		retValue = SCardControl(m_hCard, m_ioctl_pace, sendbuf, sizeof sendbuf,
								recvbuf, sizeof(recvbuf), &recvlen);
		hexdump(DEBUG_LEVEL_CARD, "Execute PACE Output Data (FUNCTION=GetReadersPACECapabilities)", recvbuf, recvlen);

		if (retValue == SCARD_S_SUCCESS
			&& recvlen == 7
			&& recvbuf[0] == 0 && recvbuf[1] == 0
			&& recvbuf[2] == 0 && recvbuf[3] == 0) {
			if (recvbuf[6] & BITMAP_Qualified_Signature)
				eCardCore_info(DEBUG_LEVEL_CARD, "Reader supports qualified signature");

			if (recvbuf[6] & BITMAP_German_eID)
				eCardCore_info(DEBUG_LEVEL_CARD, "Reader supports German eID");

			if (recvbuf[6] & BITMAP_PACE) {
				eCardCore_info(DEBUG_LEVEL_CARD, "Reader supports PACE");

			} else
				m_ioctl_pace = 0;

			if (recvbuf[6] & BITMAP_DestroyPACEChannel)
				eCardCore_info(DEBUG_LEVEL_CARD, "Reader supports DestroyPACEChannel");

		} else {
			eCardCore_warn(DEBUG_LEVEL_CARD, "Error executing GetReadersPACECapabilities");
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
							  SCARD_LEAVE_CARD, &m_dwProtocol);
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

vector <unsigned char> PCSCReader::transceive(
	const vector<unsigned char>& cmd)
{
	BYTE res[RAPDU::RAPDU_EXTENDED_MAX];
	DWORD reslen = sizeof res;
	DWORD r = SCARD_S_SUCCESS;
	vector <unsigned char> result;

	if (0x00 == m_hCard)
		throw WrongHandle();

	r = SCardTransmit(m_hCard, SCARD_PCI_T1, cmd.data(),
					  (DWORD) cmd.size(), NULL, res, &reslen);

	if (r != SCARD_S_SUCCESS)
		throw TransactionFailed();

	return vector<unsigned char>(res, res + reslen);
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
	SCardGetAttrib(m_hCard, SCARD_ATTR_ATR_STRING, atr.data(), &atrSize);
#else
	unsigned char atr_[512];
	uint32_t len = sizeof(atr_);
	char szReader[128];
	uint32_t cch = 128;
	uint32_t dwState;
	uint32_t dwProtocol;
	SCardStatus(m_hCard, szReader, &cch, &dwState, &dwProtocol, (unsigned char *)&atr_, &len);

	for (int i = 0; i < len; i++)
		atr.push_back(atr_[i]);

#endif
	return atr;
}

bool PCSCReader::supportsPACE(void) const
{
	if (0 == m_ioctl_pace)
		return false;

	return true;
}

static PaceOutput
parse_EstablishPACEChannel_OutputData(BYTE *output, size_t output_length)
{
	size_t parsed = 0;
	uint8_t lengthCAR, lengthCARprev;
	uint16_t lengthOutputData, lengthEF_CardAccess, length_IDicc, mse_setat;
	vector<BYTE> CAR, CARprev, EF_CardAccess, IDicc;
	uint32_t result;
	PaceOutput paceoutput;

	/* Output Data */
	if (parsed + sizeof result > output_length) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "Malformed Establish PACE Channel output data.");
		throw PACEException();
	}

	memcpy(&result, output + parsed, sizeof result);

	switch (result) {
		case 0x00000000:
			break;
		case 0xD0000001:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Längen im Input sind inkonsistent");
			throw PACEException();
		case 0xD0000002:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Unerwartete Daten im Input");
			throw PACEException();
		case 0xD0000003:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Unerwartete Kombination von Daten im Input");
			throw PACEException();
		case 0xE0000001:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Syntaxfehler im Aufbau der TLV-Antwortdaten");
			throw PACEException();
		case 0xE0000002:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Unerwartete/fehlende Objekte in den TLV-Antwortdaten");
			throw PACEException();
		case 0xE0000003:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Der Kartenleser kennt die PIN-ID nicht.");
			throw PACEException();
		case 0xE0000006:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Fehlerhaftes PACE-Token");
			throw PACEException();
		case 0xE0000007:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Zertifikatskette für Terminalauthentisierung kann nicht gebildet werden");
			throw PACEException();
		case 0xE0000008:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Unerwartete Datenstruktur in Rückgabe der Chipauthentisierung");
			throw PACEException();
		case 0xE0000009:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Passive Authentisierung fehlgeschlagen");
			throw PACEException();
		case 0xE000000A:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Fehlerhaftes Chipauthentisierung-Token");
			throw PACEException();
		case 0xF0100001:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Kommunikationsabbruch mit Karte.");
			throw PACEException();
		default:
			eCardCore_warn(DEBUG_LEVEL_CARD, "Reader reported some error: %0X.", result);
			throw PACEException();
	}

	paceoutput.set_result(result);
	parsed += sizeof result;

	/* Output Data */
	if (parsed + sizeof lengthOutputData > output_length) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "Malformed Establish PACE Channel output data.");
		throw PACEException();
	}

	memcpy(&lengthOutputData, output + parsed, sizeof lengthOutputData);
	parsed += sizeof lengthOutputData;

	if (lengthOutputData != output_length - parsed) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "Malformed Establish PACE Channel output data.");
		throw PACEException();
	}

	/* MSE:Set AT */
	if (parsed + sizeof mse_setat > output_length) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "Malformed Establish PACE Channel output data.");
		throw PACEException();
	}

	memcpy(&mse_setat, output + parsed, sizeof mse_setat);
	paceoutput.set_status_mse_set_at(mse_setat);
	parsed += sizeof mse_setat;

	/* lengthEF_CardAccess */
	if (parsed + 2 > output_length) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "Malformed Establish PACE Channel output data.");
		throw PACEException();
	}

	memcpy(&lengthEF_CardAccess, output + parsed, sizeof lengthEF_CardAccess);
	parsed += sizeof lengthEF_CardAccess;

	/* EF.CardAccess */
	if (parsed + lengthEF_CardAccess > output_length) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "Malformed Establish PACE Channel output data.");
		throw PACEException();
	}

	EF_CardAccess.assign(output + parsed, output + parsed + lengthEF_CardAccess);
	paceoutput.set_ef_cardaccess(EF_CardAccess);
	parsed += lengthEF_CardAccess;

	/* lengthCAR */
	if (parsed + sizeof lengthCAR > output_length) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "Malformed Establish PACE Channel output data.");
		throw PACEException();
	}

	memcpy(&lengthCAR, output + parsed, sizeof lengthCAR);
	parsed += sizeof lengthCAR;

	/* CAR */
	if (parsed + lengthCAR > output_length) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "Malformed Establish PACE Channel output data.");
		throw PACEException();
	}

	CAR.assign(output + parsed, output + parsed + lengthCAR);
	paceoutput.set_car_curr(CAR);
	parsed += lengthCAR;

	/* lengthCARprev */
	if (parsed + sizeof lengthCARprev > output_length) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "Malformed Establish PACE Channel output data.");
		throw PACEException();
	}

	memcpy(&lengthCARprev, output + parsed, sizeof lengthCARprev);
	parsed += sizeof lengthCARprev;

	/* CARprev */
	if (parsed + lengthCARprev > output_length) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "Malformed Establish PACE Channel output data.");
		throw PACEException();
	}

	CARprev.assign(output + parsed, output + parsed + lengthCARprev);
	paceoutput.set_car_prev(CARprev);
	parsed += lengthCARprev;

	/* lengthIDicc */
	if (parsed + sizeof length_IDicc > output_length) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "Malformed Establish PACE Channel output data.");
		throw PACEException();
	}

	memcpy(&length_IDicc , output + parsed, sizeof length_IDicc);
	parsed += sizeof length_IDicc;

	/* IDicc */
	if (parsed + length_IDicc > output_length) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "Malformed Establish PACE Channel output data.");
		throw PACEException();
	}

	IDicc.assign(output + parsed, output + parsed + length_IDicc);
	paceoutput.set_id_icc(IDicc);
	parsed += length_IDicc;

	if (parsed != output_length) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "Overrun by %d bytes", output_length - parsed);
		throw PACEException();
	}

	return paceoutput;
}

PaceOutput PCSCReader::establishPACEChannel(const PaceInput &input) const
{
	PaceOutput output;
	DWORD r, recvlen;
	uint8_t length_CHAT, length_PIN, PinID;
	uint16_t lengthInputData, lengthCertificateDescription;
	BYTE recvbuf[1024];

	if (input.get_chat().size() > 0xff || input.get_pin().size() > 0xff)
		throw PACEException();

	length_CHAT = (uint8_t) input.get_chat().size();
	length_PIN = (uint8_t) input.get_pin().size();
	/* FIXME */
#if REINERSCT_ACCEPTS_TESTDESCRIPTION
	lengthCertificateDescription = (unsigned int) input.get_certificate_description().size();
#else
	lengthCertificateDescription = 0;
#endif
	lengthInputData = sizeof PinID
					  + sizeof length_CHAT + length_CHAT
					  + sizeof length_PIN + length_PIN
					  + sizeof lengthCertificateDescription + lengthCertificateDescription;
	size_t sendlen = 1 + 2 + lengthInputData;
	BYTE *sendbuf = (BYTE *) malloc(sendlen);

	if (!sendbuf)
		throw TransactionFailed();

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
	memcpy(sendbuf + 1,
		   &lengthInputData, sizeof lengthInputData);
	memcpy(sendbuf + 1 + sizeof lengthInputData,
		   &PinID, sizeof PinID);
	memcpy(sendbuf + 1 + sizeof lengthInputData + sizeof PinID,
		   &length_CHAT, sizeof length_CHAT);
	memcpy(sendbuf + 1 + sizeof lengthInputData + sizeof PinID + sizeof length_CHAT,
		   input.get_chat().data(), length_CHAT);
	memcpy(sendbuf + 1 + sizeof lengthInputData + sizeof PinID + sizeof length_CHAT + length_CHAT,
		   &length_PIN, sizeof length_PIN);
	memcpy(sendbuf + 1 + sizeof lengthInputData + sizeof PinID + sizeof length_CHAT + length_CHAT + sizeof length_PIN,
		   input.get_pin().data(), length_PIN);
	memcpy(sendbuf + 1 + sizeof lengthInputData + sizeof PinID + sizeof length_CHAT + length_CHAT + sizeof length_PIN + length_PIN,
		   &lengthCertificateDescription, sizeof lengthCertificateDescription);
	memcpy(sendbuf + 1 + sizeof lengthInputData + sizeof PinID + sizeof length_CHAT + length_CHAT + sizeof length_PIN + length_PIN + sizeof lengthCertificateDescription,
		   input.get_certificate_description().data(), lengthCertificateDescription);
	hexdump(DEBUG_LEVEL_CARD, "Execute PACE Input Data (FUNCTION=EstabishPACEChannel)", sendbuf, sendlen);
	recvlen = sizeof(recvbuf);
	r = SCardControl(m_hCard, m_ioctl_pace, sendbuf, sendlen,
					 recvbuf, sizeof(recvbuf), &recvlen);
	hexdump(DEBUG_LEVEL_CARD, "Execute PACE Output Data (FUNCTION=EstabishPACEChannel)", recvbuf, recvlen);
	free(sendbuf);
	return parse_EstablishPACEChannel_OutputData(recvbuf, recvlen);
}
