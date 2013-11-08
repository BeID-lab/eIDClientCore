// ---------------------------------------------------------------------------
// Copyright (c) 2013 Bundesdruckerei GmbH
// All rights reserved.
//
// $Id$
// ---------------------------------------------------------------------------

#include "eIDClientCardReader.h"

#if defined(__cplusplus)
extern "C"
{
#endif

ECARD_STATUS CardReaderOpen(P_EIDCLIENT_CARD_READER_HANDLE hCardReader, const char* const readerName)
{
	return ECARD_SUCCESS;
}

ECARD_STATUS CardReaderClose(EIDCLIENT_CARD_READER_HANDLE hCardReader)
{
	return ECARD_SUCCESS;
}

ECARD_STATUS CardReaderSend(EIDCLIENT_CARD_READER_HANDLE hCardReader,
												 const unsigned char* const cardCommand,
												 const unsigned long nLengthCardCommand,
												 unsigned char* const result,
												 unsigned long* const nLengthResult)
{
	return ECARD_SUCCESS;
}


ECARD_STATUS CardReaderGetATR(EIDCLIENT_CARD_READER_HANDLE hCardReader,
												 unsigned char* const result,
												 unsigned long* const nLengthResult)
{
	return ECARD_SUCCESS;
}


ECARD_STATUS CardReaderSupportsPACE(EIDCLIENT_CARD_READER_HANDLE hCardReader)
{
	return ECARD_SUCCESS;
}

ECARD_STATUS CardReaderDoPACE(EIDCLIENT_CARD_READER_HANDLE hCardReader,
		const enum PinID pinid,
		const nPADataBuffer_t *pin,
		const nPADataBuffer_t *chat,
		const nPADataBuffer_t *certificate_description,
		unsigned int *result,
		unsigned short *status_mse_set_at,
		nPADataBuffer_t *ef_cardaccess,
		nPADataBuffer_t *car_curr,
		nPADataBuffer_t *car_prev,
		nPADataBuffer_t *id_icc)
{
	return ECARD_SUCCESS;
}

#if defined(__cplusplus)
}
#endif

