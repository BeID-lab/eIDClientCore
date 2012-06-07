// ---------------------------------------------------------------------------
// Copyright (c) 2007 Bundesruckerei GmbH
// All rights reserved.
//
// $Id: eCardCore.h 627 2010-01-28 09:19:47Z rfiedler $
// ---------------------------------------------------------------------------

/*!
 * @file eCardCore.h
 */

#include <eCardTypes.h>
#include <eCardStatus.h>

#if !defined(__ECARDCORE_INCLUDED__)
#define __ECARDCORE_INCLUDED__

#if defined(WIN32) || defined(WINCE)// Windows related stuff
#   if defined(ECARD_EXPORTS)
#       define ECARD_API __declspec(dllexport)
#   else
#       define ECARD_API __declspec(dllimport)
#   endif
#   define __STDCALL__ __stdcall
#else // Linux related stuff
#   define ECARD_API
#   define __STDCALL__
#endif

/*!
 * @brief This function opens an handle to the eCardCore-API. 
 *        This handle can be used to make calls to the eCardCore-API. 
 *
 * @param hCardSystem [OUT] Pointer to the eCardCore-API handle.
 * @param protocol [IN] Specifies the communication protocol to use.
 *
 * @return ECARD_SUCCESS indicates success. All other values indication 
 *         an error. 
 *         Please refefr to the documentation for further information.
 *
 * @see eCardClose
 * @see ECARD_PROTOCOL
 */
ECARD_STATUS __STDCALL__ eCardOpen(
  OUT PECARD_HANDLE hCardSystem,
  IN ECARD_PROTOCOL protocol);

/*!
 *
 */
ECARD_STATUS __STDCALL__ eCardAddCardDetector(
  IN ECARD_HANDLE hCardSystem,
  IN ECARD_HANDLE hCardDetector);

/*!
 * @brief This function frees the handle to the eCardCore-API. 
 *        Once a key handle has been freed, it becomes invalid 
 *        and cannot be used again.
 *
 * @param hCardSystem [IN] handle to the eCardCore-API to be destroyed.
 *
 * @return ECARD_SUCCESS indicates success. All other values indication an error.
 *         Please refefr to the documentation for further information.
 *
 * @see eCard
 */

ECARD_STATUS __STDCALL__ eCardClose(
  IN ECARD_HANDLE hCardSystem);

/*!
 * @brief This function returns the number of known readers
 *        within the system.
 *
 * @param hCardSystem [IN] handle to the eCardCore-API.
 *
 * @return The number of installed readers.
 *
 * @remark If protocol PROTOCOL_PCSC is specified while openening the
 *         eCardCore-API the number of usable readers can be less or
 *         equal to the returned number of reades.
 *         If protocol PROTOCOL_CTAPI is specified the number of usable
 *         readers is equal to the returned number of readers.
 */
int __STDCALL__ eCardGetReaderCount(
  IN ECARD_HANDLE hCardSystem);

/*!
 * @brief This function is used to get the name of the reader specified
 *        by @ref idx.
 *
 * @param hCardSystem [IN] handle to the eCardCore-API.
 * @param idx [IN] zero based indes to the reader.
 * @param szReaderName [OUT] Destination string. The caller must allocate this
 *                     buffer. If this parameter is NULL only the resulting 
 *                     lenght will be retrieved in dwSize.
 * @param dwSize [IN OUT] Length of the szReaderName buffer in characters.
 *
 * @return ECARD_SUCCESS indicates success. All other values indication an error.
 *         Please refefr to the documentation for further information.
 *
 * @see eCardGetReaderCount
 */

ECARD_STATUS __STDCALL__ eCardGetReaderName(
  IN ECARD_HANDLE hCardSystem,
  int idx,
  char* szReaderName,
  PDWORD dwSize);

/*!
 * @brief This function opens a card connection. The reader is specified 
 *        by @ref idx.
 *
 * @param hEDA [IN] handle to the eCardCore-API.
 * @param idx [IN] zero based indes to the reader.
 * @param hCard [OUT] A handle that identifies the connection
 *              to the smart card in the designated reader.
 *
 * @return ECARD_SUCCESS indicates success. All other values indication an error.
 *         Please refefr to the documentation for further information.
 */

ECARD_STATUS __STDCALL__ eCardOpenReader(
  IN ECARD_HANDLE hCardSystem,
  IN int idx,
  OUT PECARD_HANDLE hCard);

/*!
 * @brief This function opens a card connection. The reader is
 *        specified by @ref readerName.
 *
 * @param hEDA [IN] handle to the eCardCore-API.
 * @param readerName [IN] Null-terminated string that holds the name 
 *        of the reader.
 * @param hCard [OUT] A handle that identifies the connection
 *              to the smart card in the designated reader.
 *
 * @return ECARD_SUCCESS indicates success. All other values indication an error.
 *         Please refefr to the documentation for further information.
 *
 * @see eCardGetReaderName
 */
ECARD_STATUS __STDCALL__ eCardOpenReaderByName(
  IN ECARD_HANDLE hCardSystem,
  IN const char* readerName,
  OUT PECARD_HANDLE hCard);

/*!
 * @brief Closes the card connection.
 *
 * @param hCard [IN] handle to the card connection.
 *
 * @return ECARD_SUCCESS indicates success. All other values indication an error.
 *         Please refer to the documentation for further information.
 *
 * @see eCardOpenReader
 * @see eCardOpenReaderByName
 */
ECARD_STATUS __STDCALL__ eCardCloseReader(
  IN ECARD_HANDLE hCard);

#endif
