// ---------------------------------------------------------------------------
// Copyright (c) 2007 Bundesruckerei GmbH
// All rights reserved.
//
// $Id: eCardCore.cpp 1392 2011-12-15 13:04:40Z dietrfra $
// ---------------------------------------------------------------------------

#if defined(WIN32)
#  pragma warning(push)
#  pragma warning(disable : 4244)
#  pragma warning(disable : 4996)
#endif

#if defined(WIN32)
#  pragma warning(pop)
#include <windows.h>
#include <tchar.h>
#endif

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "eCardCore.h"

#include "PCSCManager.h"

#include <eCardStatus.h>

#include "ICard.h"

#if defined(_DEBUG) && !defined(_WIN32_WCE)
# include <crtdbg.h>
# define DEBUG_CLIENTBLOCK   new( _CLIENT_BLOCK, __FILE__, __LINE__)
# define new DEBUG_CLIENTBLOCK
#else
# define DEBUG_CLIENTBLOCK
#endif

/*
*
*/
void initCore(void)
{
}

/*
*
*/
void eCardCore_info(
                    const char* format,
                    ...)
{
  va_list params;
  va_start (params, format);

  char newMessage[4096];
  vsprintf(newMessage, format, params);

#if defined(WIN32)
  OutputDebugStringA(newMessage);
#else
  std::cout << newMessage << std::endl;
#endif
}

/*
*
*/
void eCardCore_debug(
                     const char* format,
                     ...)
{
  va_list params;
  va_start (params, format);

  char newMessage[4096];
  vsprintf(newMessage, format, params);

#if defined(WIN32)
  OutputDebugStringA(newMessage);
#else
  std::cout << newMessage << std::endl;
#endif
}

/*
*
*/
void eCardCore_warn(
                    const char* format,
                    ...)
{
  va_list params;
  va_start (params, format);

  char newMessage[4096];
  vsprintf(newMessage, format, params);

#if defined(WIN32)
  OutputDebugStringA(newMessage);
#else
  std::cout << newMessage << std::endl;
#endif
}

/*
*
*/
ECARD_STATUS __STDCALL__ eCardOpen(
                                   OUT PECARD_HANDLE hCardSystem,
                                   IN ECARD_PROTOCOL protocol)
{
  switch (protocol)
  {
    case PROTOCOL_PCSC:
      {
        PCSCManager* pcscReaderManager = new PCSCManager();
        *hCardSystem = pcscReaderManager;
        eCardCore_info("Start new session via PC/SC interface (0x%08X).", hCardSystem);

      }
      break;
    default:
      {
        *hCardSystem = ECARD_INVALID_HANDLE_VALUE;
        return ECARD_PROTOCOL_UNKNOWN;
      }
  }

  return ECARD_SUCCESS;
}

ECARD_STATUS __STDCALL__ eCardAddCardDetector(
  IN ECARD_HANDLE hCardSystem,
  IN ECARD_HANDLE hCardDetector)
{
  IReaderManager* manager = (IReaderManager*) hCardSystem;
  ICardDetector* detector  = (ICardDetector*) hCardDetector;

  manager->addCardDetector(detector);

  return ECARD_SUCCESS;
}

/*
*
*/
ECARD_STATUS __STDCALL__ eCardClose(
                                    IN ECARD_HANDLE hCardSystem)
{
  if (0x00 == hCardSystem  || ECARD_INVALID_HANDLE_VALUE == hCardSystem)
    return ECARD_INVALID_PARAMETER_1;

  eCardCore_info("Shutdown session (0x%08X).", hCardSystem);
  IReaderManager* manager = (IReaderManager*) hCardSystem;
  delete manager;

  return ECARD_SUCCESS; // Hmm what else?
}

/*
*
*/
int __STDCALL__ eCardGetReaderCount(
                                    IN ECARD_HANDLE hCardSystem)
{
  eCardCore_debug("call eCardGetReaderCount(0x%08X)", hCardSystem);

  if (0x00 == hCardSystem  || ECARD_INVALID_HANDLE_VALUE == hCardSystem)
    return -1;

  IReaderManager* manager = (IReaderManager*) hCardSystem;

  size_t readerCount = manager->getReaderCount();
  eCardCore_info("Found %d readers.", readerCount);

  return (int) readerCount;
}

/*
*
*/
ECARD_STATUS __STDCALL__ eCardGetReaderName(
  IN ECARD_HANDLE hCardSystem,
  int idx,
  char* szReaderName,
  PDWORD dwSize)
{
  eCardCore_debug("call eCardGetReaderName(0x%08X, %d, 0x%08X, 0x%08X)",
    hCardSystem, idx, szReaderName, dwSize);

  if (0x00 == hCardSystem  || ECARD_INVALID_HANDLE_VALUE == hCardSystem)
    return ECARD_INVALID_PARAMETER_1;

  IReaderManager* manager = (IReaderManager*) hCardSystem;
  IReader* reader = manager->getReader(idx);

  if (0x00 == reader)
  {
    eCardCore_debug("Could not get reader at index: %d. (%s:%d)", idx,
      __FILE__, __LINE__);
    return ECARD_NO_SUCH_READER;
  }

  // We hav no output buffer. So we return the size of the
  // expected data.
  if (0x00 == szReaderName)
  {
    *dwSize = (int) reader->getReaderName().length() + 1;
    return ECARD_SUCCESS;
  }

  string readerName = reader->getReaderName().c_str();

  if (*dwSize < readerName.length())
  {
    eCardCore_debug("The buffer is to small (%d < %d). (%s:%d) ", *dwSize,
      readerName.length(), __FILE__, __LINE__);
    return ECARD_BUFFER_TO_SMALL;
  }
#if defined (WIN32)
  strncpy_s(szReaderName, *dwSize, readerName.c_str(), readerName.length());
#else
  strncpy(szReaderName, readerName.c_str(), readerName.length());
#endif

  eCardCore_info("Found reader \"%s\" at index %d", readerName.c_str(), idx);

  return ECARD_SUCCESS;
}

/*
*
*/
ECARD_STATUS __STDCALL__ eCardOpenReader(
  IN ECARD_HANDLE hCardSystem,
  IN int idx,
  OUT PECARD_HANDLE hCard)
{
  eCardCore_debug("call eCardOpenReader(0x%08X, %d, 0x%08X)",
    hCardSystem, idx, hCard);

  if (0x00 == hCardSystem  || ECARD_INVALID_HANDLE_VALUE == hCardSystem)
  {
    *hCard = ECARD_INVALID_HANDLE_VALUE;
    return ECARD_INVALID_PARAMETER_1;
  }

  IReaderManager* manager = (IReaderManager*) hCardSystem;
  IReader* reader = manager->getReader(idx);

  if (0x00 == reader)
  {
    eCardCore_debug("Could not get reader at index: %d. (%s:%d)",
      idx, __FILE__, __LINE__);

    *hCard = ECARD_INVALID_HANDLE_VALUE;
    return ECARD_NO_SUCH_READER;
  }

  if (!reader->open())
  {
    eCardCore_debug("Could not open reader at index: %d (%s). (%s:%d)",
      idx, reader->getReaderName().c_str(), __FILE__, __LINE__);

    *hCard = ECARD_INVALID_HANDLE_VALUE;
    return ECARD_READER_NOT_AVAILABLE;
  }

  *hCard = reader->getCard();

  if (0x00 == *hCard) {
    eCardCore_debug("Could not get card from reader at index: %d (%s). (%s:%d)",
      idx, reader->getReaderName().c_str(), __FILE__, __LINE__);
    return ECARD_UNKNOWN_CARD;
  }

  eCardCore_info("Open reader \"%s\" at index %d succesfull (0x%08X).",
    reader->getReaderName().c_str(), idx, *hCard);

  return ECARD_SUCCESS;
}

/*
*
*/
ECARD_STATUS __STDCALL__ eCardOpenReaderByName(
  IN ECARD_HANDLE hCardSystem,
  IN const char* readerName,
  OUT PECARD_HANDLE hCard)
{
  eCardCore_debug("call eCardOpenReaderByName(0x%08X, %s, 0x%08X)",
    hCardSystem, readerName, hCard);

  if (0x00 == hCardSystem  || ECARD_INVALID_HANDLE_VALUE == hCardSystem)
  {
    *hCard = ECARD_INVALID_HANDLE_VALUE;
    return ECARD_INVALID_PARAMETER_1;
  }

  IReaderManager* manager = (IReaderManager*) hCardSystem;
  IReader* reader = manager->getReader(readerName);

  if (0x00 == reader)
  {
    eCardCore_debug("Could not get reader by name: %s. (%s:%d)",
      readerName, __FILE__, __LINE__);

    *hCard = ECARD_INVALID_HANDLE_VALUE;
    return ECARD_NO_SUCH_READER;
  }

  if (!reader->open())
  {
    eCardCore_debug("Could not open readerby name: (%s). (%s:%d)",
      readerName, __FILE__, __LINE__);

    *hCard = ECARD_INVALID_HANDLE_VALUE;
    return ECARD_READER_NOT_AVAILABLE;
  }

  *hCard = reader->getCard();

  if (0x00 == *hCard)
  {
    eCardCore_debug("Could not get card from reader by name: %s. (%s:%d)",
      readerName, __FILE__, __LINE__);
    return ECARD_UNKNOWN_CARD;
  }

  eCardCore_info("Open reader \"%s\" succesfull (0x%08X).",
    reader->getReaderName().c_str(), *hCard);

  return ECARD_SUCCESS;
}

/*
*
*/
ECARD_STATUS __STDCALL__ eCardCloseReader(
  IN ECARD_HANDLE hCard)
{
  eCardCore_debug("call eCardCloseReader (0x%08X)", hCard);

  if (0x00 == hCard  || ECARD_INVALID_HANDLE_VALUE == hCard)
    return ECARD_INVALID_PARAMETER_1;

  eCardCore_info("Close reader (0x%08X)", hCard);
  ICard* card = (ICard*) hCard;
  delete card;

  return ECARD_SUCCESS;
}

