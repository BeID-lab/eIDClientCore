/*
 * Copyright (C) 2013 Bundesdruckerei GmbH
 */

#include "ExternalReader.h"
#include "debug.h"
#include <cstdlib>

#ifndef STATIC_LINK_EXTERNAL_READER
#include "loadlib.h"

bool ExternalReader::m_libload(void)
{
	bool r = false;

	if (!m_hLib) {
#if defined(WIN32)
#if defined(_DEBUG) || defined(DEBUG)
		m_hLib = LOAD_LIBRARY("externalReaderd.dll");
#else
		m_hLib = LOAD_LIBRARY("externalReader.dll");
#endif
#elif defined(__APPLE__)
		m_hLib = LOAD_LIBRARY("libexternalReader.dylib");
#else
		m_hLib = LOAD_LIBRARY("libexternalReader.so");
#endif

		if (m_hLib) {
			m_hOpen = (CardReaderOpen_t) GET_FUNCTION(m_hLib, CardReaderOpen);
			m_hSend = (CardReaderSend_t) GET_FUNCTION(m_hLib, CardReaderSend);
			m_hGetATR = (CardReaderGetATR_t) GET_FUNCTION(m_hLib, CardReaderGetATR);
			m_hSupportsPACE = (CardReaderSupportsPACE_t) GET_FUNCTION(m_hLib, CardReaderSupportsPACE);
			m_hDoPACE = (CardReaderDoPACE_t) GET_FUNCTION(m_hLib, CardReaderDoPACE);
			m_hClose = (CardReaderClose_t) GET_FUNCTION(m_hLib, CardReaderClose);
		} else {
			eCardCore_warn(DEBUG_LEVEL_READER, "could not load external reader library");
		}
	}

	if (!m_hLib || !m_hOpen || !m_hSend || !m_hGetATR || !m_hSupportsPACE || !m_hDoPACE || !m_hClose) {
		eCardCore_warn(DEBUG_LEVEL_READER, "could not load external reader library functions");
		m_libcleanup();
	} else {
		r = true;
	}

	return r;
}

void ExternalReader::m_libcleanup(void)
{
	close();

	FREE_LIBRARY(m_hLib);

	m_hLib = 0;
	m_hOpen = 0;
	m_hClose = 0;
	m_hSend = 0;
	m_hGetATR = 0;
	m_hSupportsPACE = 0;
	m_hDoPACE = 0;
}
#else
bool ExternalReader::m_libload(void)
{
	m_hLib = (void*) 1;
	m_hOpen = CardReaderOpen;
	m_hClose = CardReaderClose;
	m_hSend = CardReaderSend;
	m_hGetATR = CardReaderGetATR;
	m_hSupportsPACE = CardReaderSupportsPACE;
	m_hDoPACE = CardReaderDoPACE;

	return true;
}

void ExternalReader::m_libcleanup(void)
{
	close();
}

#endif

#include "eIdClientCardReader.h"

ExternalReader::ExternalReader(const std::string &readerName, std::vector<ICardDetector *>& detector) : IndividualReader(readerName, detector)
{
	m_hCardReader = 0x00;
	m_hLib = 0;
	m_hOpen = 0;
	m_hClose = 0;
	m_hSend = 0;
	m_hGetATR = 0;
	m_hSupportsPACE = 0;
	m_hDoPACE = 0;
	m_libload();
}

ExternalReader::~ExternalReader(void)
{
	m_libcleanup();
}

bool ExternalReader::open(void)
{
	bool r = false;

	if (!m_hOpen)
		goto err;

	if (ECARD_SUCCESS == m_hOpen(&m_hCardReader, "ExternalCardReader"))
		r = true;
	else
		eCardCore_warn(DEBUG_LEVEL_READER, "external open failed");

err:
	return r;
}

void ExternalReader::close(void)
{
	if (m_hClose) {
		m_hClose(m_hCardReader);
	}

	m_hCardReader = 0;
}

std::vector<unsigned char> ExternalReader::getATRForPresentCard(void)
{
    std::vector<unsigned char> atr;
	unsigned long	nLengthResult = MAX_BUFFER_SIZE;

	if (!m_hGetATR)
		goto err;

	if (ECARD_SUCCESS == m_hGetATR(m_hCardReader, buffer, &nLengthResult))
		atr.insert(atr.end(), buffer, buffer+nLengthResult);
	else
		eCardCore_warn(DEBUG_LEVEL_READER, "external get atr failed");

err:
	return atr;
}

std::vector<unsigned char> ExternalReader::transceive(const std::vector<unsigned char>& cmd)
{
    std::vector<unsigned char> response;
	
	unsigned long	nLengthResult = MAX_BUFFER_SIZE;

	if (ECARD_SUCCESS == m_hSend(m_hCardReader, DATA(cmd), cmd.size(), buffer, &nLengthResult)) {
		response.clear();
		response.insert(response.end(), buffer, buffer+nLengthResult);
	} else
		eCardCore_warn(DEBUG_LEVEL_READER, "external send failed");
  
	return response;
}

bool ExternalReader::supportsPACEnative(void)
{
	bool r = false;

	if (m_hSupportsPACE
		   	&& ECARD_SUCCESS == m_hSupportsPACE(m_hCardReader)) {
		r = true;
		eCardCore_info(DEBUG_LEVEL_READER, "Reader supports PACE");
	}

    return r;
}

static std::vector<unsigned char> buffer2vector(const nPADataBuffer_t *src)
{
	std::vector<unsigned char> dest;
	if (src && src->pDataBuffer)
		dest.assign(src->pDataBuffer, src->pDataBuffer + src->bufferSize);
	return dest;
}

PaceOutput ExternalReader::establishPACEChannelNative(const PaceInput &input)
{
	PaceOutput paceoutput;

	if (m_hDoPACE) {
		enum PinID pinid = PI_UNDEF;
		switch (input.get_pin_id()) {
			case PaceInput::pin:
				pinid = PI_PIN;
				break;
			case PaceInput::can:
				pinid = PI_CAN;
				break;
			case PaceInput::mrz:
				pinid = PI_MRZ;
				break;
			case PaceInput::puk:
				pinid = PI_PUK;
				break;
			default:
				eCardCore_warn(DEBUG_LEVEL_READER, "Unknown type of secret");
				break;
		}
		const nPADataBuffer_t pin = {
			(unsigned char *) DATA(input.get_pin()),
			input.get_pin().size()};
		const nPADataBuffer_t chat = {
			(unsigned char *) DATA(input.get_chat()),
			input.get_chat().size()};
		const nPADataBuffer_t chat_required = {
			(unsigned char *) DATA(input.get_chat_required()),
			input.get_chat_required().size()};
		const nPADataBuffer_t chat_optional = {
			(unsigned char *) DATA(input.get_chat_optional()),
			input.get_chat_optional().size()};
		const nPADataBuffer_t certificate_description = {
			(unsigned char *) DATA(input.get_certificate_description()),
			input.get_certificate_description().size()};
		const nPADataBuffer_t transaction_info_hidden = {
			(unsigned char *) DATA(input.get_transaction_info_hidden()),
			input.get_transaction_info_hidden().size()};
		unsigned int result;
		unsigned short status_mse_set_at;
		nPADataBuffer_t ef_cardaccess = {NULL, 0};
		nPADataBuffer_t car_curr = {NULL, 0};
		nPADataBuffer_t car_prev = {NULL, 0};
		nPADataBuffer_t id_icc = {NULL, 0};
		nPADataBuffer_t chat_used = {NULL, 0};

		if (ECARD_SUCCESS == m_hDoPACE(m_hCardReader, pinid, &pin, &chat,
					&chat_required, &chat_optional, &certificate_description,
					&transaction_info_hidden, &result, &status_mse_set_at,
					&ef_cardaccess, &car_curr, &car_prev, &id_icc, &chat_used)) {
			paceoutput.set_result(result);
			paceoutput.set_status_mse_set_at(status_mse_set_at);
			paceoutput.set_ef_cardaccess(buffer2vector(&ef_cardaccess));
			paceoutput.set_car_curr(buffer2vector(&car_curr));
			paceoutput.set_car_prev(buffer2vector(&car_prev));
			paceoutput.set_id_icc(buffer2vector(&id_icc));
			paceoutput.set_chat(buffer2vector(&chat_used));

			free(car_curr.pDataBuffer);
			free(car_prev.pDataBuffer);
			free(ef_cardaccess.pDataBuffer);
			free(id_icc.pDataBuffer);
			free(chat_used.pDataBuffer);
		} else
			eCardCore_warn(DEBUG_LEVEL_READER, "external PACE failed");
	}

    return paceoutput;
}
