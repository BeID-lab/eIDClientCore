/*
 * Copyright (C) 2013 Bundesdruckerei GmbH
 */

#if !defined(__EXTERNALREADER_INCLUDED__)
#define __EXTERNALREADER_INCLUDED__

#include "IReader.h"
#include "eCardTypes.h"
#include "eIdClientCardReader.h"

class ExternalReader : public IndividualReader
{
	private:
		void* m_hLib;
		CardReaderOpen_t m_hOpen;
		CardReaderClose_t m_hClose;
		CardReaderSend_t m_hSend;
		CardReaderGetATR_t m_hGetATR;
		CardReaderSupportsPACE_t m_hSupportsPACE;
		CardReaderDoPACE_t m_hDoPACE;
    	EIDCLIENT_CARD_READER_HANDLE m_hCardReader;
		void m_libcleanup(void);
		bool m_libload(void);

	public:
		ExternalReader(const std::string &, std::vector<ICardDetector *>&);
		~ExternalReader(void);

		bool open(void);
		void close(void);

		std::vector<unsigned char> transceive(const std::vector<unsigned char>& cmd);

		std::vector<unsigned char> getATRForPresentCard(void);

		bool supportsPACE(void);
		PaceOutput establishPACEChannel(const PaceInput &input);
};

#endif // __EXTERNALREADER_INCLUDED__
