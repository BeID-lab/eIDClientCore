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
		static const size_t MAX_BUFFER_SIZE = 0xFFF;
		unsigned char buffer[MAX_BUFFER_SIZE];

	public:
		ExternalReader(const std::string &, std::vector<ICardDetector *>&);
		~ExternalReader(void);

		bool open(void);
		void close(void);

		std::vector<unsigned char> transceive(const std::vector<unsigned char>& cmd);

		std::vector<unsigned char> getATRForPresentCard(void);

		bool supportsPACEnative(void);
		PaceOutput establishPACEChannelNative(const PaceInput &input);
};

#endif // __EXTERNALREADER_INCLUDED__
