/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */
#include "PCSCManager.h"
#include "PCSCReader.h"
#include <debug.h>

#if defined(WIN32)
#  include <tchar.h>
#endif
#if !(defined(UNICODE) || defined(_UNICODE))
#include <cstring>
#endif

/*
 *
 */
PCSCManager::PCSCManager(const char * userSelectedCardReader) : IReaderManager()
{
	findReaders(userSelectedCardReader);
}

/*
 *
 */
void PCSCManager::findReaders(const char * userSelectedCardReader)
{
	long retValue = SCARD_S_SUCCESS;
	SCARDCONTEXT hScardContext = 0x0;

	if ((retValue = SCardEstablishContext(SCARD_SCOPE_SYSTEM, 0x0,
										  0x0, &hScardContext)) != SCARD_S_SUCCESS) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "SCardEstablishContext failed. 0x%08X (%s:%d)",
					   retValue, __FILE__, __LINE__);
		return;
	}

	DWORD dwSize = 0;

	if ((retValue = SCardListReaders(hScardContext, NULL,
									 NULL, &dwSize)) != SCARD_S_SUCCESS) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "SCardListReaders failed. 0x%08X (%s:%d)",
					   retValue, __FILE__, __LINE__);
		return;
	}

#if defined(WIN32) || defined(WINCE)
	LPTSTR readers = new TCHAR[dwSize];
#else
	char *readers = new char[dwSize];
#endif

	if ((retValue = SCardListReaders(hScardContext, NULL,
									 readers, &dwSize)) != SCARD_S_SUCCESS) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "SCardListReaders failed. 0x%08X (%s:%d)",
					   retValue, __FILE__, __LINE__);
		return;
	}

	if (0x00 == readers) {
		eCardCore_warn(DEBUG_LEVEL_CARD, "No readers available. (%s:%d)",
					   __FILE__, __LINE__);
		return;
	}

#if defined(WIN32) || defined(WINCE)
	LPTSTR pReader = readers;
#else
	char *pReader = readers;
#endif

	while ('\0' != *pReader) {
#if defined(UNICODE) || defined(_UNICODE)
		int size = wcslen(pReader) + 1;
		char *pMBBuffer = new char[size];
		memset(pMBBuffer, 0, size);
		wcstombs(pMBBuffer, pReader, wcslen(pReader));
		/*Dont know if this is correct or we have to do some conversions before*/
		if(!userSelectedCardReader || strstr(pMBBuffer, userSelectedCardReader))
			IReader *newReader = new PCSCReader(pMBBuffer, m_cardDetectors);
		m_readerList.push_back(newReader);
		delete [] pMBBuffer;
		pReader = pReader + wcslen(pReader) + 1;
#else
		/*To Do: Case insensitive compare*/
		if(!userSelectedCardReader || !strlen(userSelectedCardReader) || strstr(pReader, userSelectedCardReader))
			m_readerList.push_back(new PCSCReader(pReader, m_cardDetectors));
		pReader = pReader + strlen(pReader) + 1;
#endif
	}

	delete [] readers;
	SCardReleaseContext(hScardContext);
}
