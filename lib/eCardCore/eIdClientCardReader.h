// ---------------------------------------------------------------------------
// Copyright (c) 2013 Bundesdruckerei GmbH
// All rights reserved.
//
// $Id$
// ---------------------------------------------------------------------------

#if !defined(__EIDCLIENTCARDREADER_INCLUDE__)
#define __EIDCLIENTCARDREADER_INCLUDE__

#include "eIDClientCore/eIDClientCore.h"
#include "eCardCore/eCardStatus.h"

typedef void *EIDCLIENT_CARD_READER_HANDLE;
typedef EIDCLIENT_CARD_READER_HANDLE *P_EIDCLIENT_CARD_READER_HANDLE;

#if defined(__cplusplus)
extern "C"
{
#endif

ECARD_STATUS CardReaderOpen(P_EIDCLIENT_CARD_READER_HANDLE hCardReader, const char* const readerName);
ECARD_STATUS CardReaderClose(EIDCLIENT_CARD_READER_HANDLE hCardReader);
ECARD_STATUS CardReaderSend(EIDCLIENT_CARD_READER_HANDLE hCardReader,
												 const unsigned char* const cardCommand,
												 const unsigned long nLengthCardCommand,
												 unsigned char* const result,
												 unsigned long* const nLengthResult);
ECARD_STATUS CardReaderGetATR(EIDCLIENT_CARD_READER_HANDLE hCardReader,
												 unsigned char* const result,
												 unsigned long* const nLengthResult);
ECARD_STATUS CardReaderSupportsPACE(EIDCLIENT_CARD_READER_HANDLE hCardReader);
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
		nPADataBuffer_t *id_icc);


typedef ECARD_STATUS (*CardReaderOpen_t)(P_EIDCLIENT_CARD_READER_HANDLE hCardReader, const char* const readerName);
typedef ECARD_STATUS (*CardReaderClose_t)(EIDCLIENT_CARD_READER_HANDLE hCardReader);
typedef ECARD_STATUS (*CardReaderSend_t)(EIDCLIENT_CARD_READER_HANDLE hCardReader,
												 const unsigned char* const cardCommand,
												 const unsigned long nLengthCardCommand,
												 unsigned char* const result,
												 unsigned long* const nLengthResult);
typedef ECARD_STATUS (*CardReaderGetATR_t)(EIDCLIENT_CARD_READER_HANDLE hCardReader,
												 unsigned char* const result,
												 unsigned long* const nLengthResult);
typedef ECARD_STATUS (*CardReaderSupportsPACE_t)(EIDCLIENT_CARD_READER_HANDLE hCardReader);
typedef ECARD_STATUS (*CardReaderDoPACE_t)(EIDCLIENT_CARD_READER_HANDLE hCardReader,
		const enum PinID pinid,
		const nPADataBuffer_t *pin,
		const nPADataBuffer_t *chat,
		const nPADataBuffer_t *certificate_description,
		unsigned int *result,
		unsigned short *status_mse_set_at,
		nPADataBuffer_t *ef_cardaccess,
		nPADataBuffer_t *car_curr,
		nPADataBuffer_t *car_prev,
		nPADataBuffer_t *id_icc);
#if defined(__cplusplus)
}
#endif

#endif // __EIDCLIENTCARDREADER_INCLUDE__

