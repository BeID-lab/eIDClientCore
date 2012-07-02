// ----------------------------------------------------------------------------
// Copyright (c) 2007 Bundesdruckerei GmbH
// All rights reserved.
//
// $Id: eCardTypes.h 1237 2011-07-27 09:36:51Z x_schrom $
// ----------------------------------------------------------------------------

/*!
 * @file eCardTypes.h
 */

#if !defined(__ECARDTYPES_INCLUDED__)
#define __ECARDTYPES_INCLUDED__

#include <cassert>
#include <stddef.h>

#define IN
#define OUT
#define OPTIONAL

typedef unsigned char BYTE;
typedef BYTE* PBYTE;

typedef unsigned long DWORD;
typedef DWORD* PDWORD;

typedef void* ECARD_HANDLE;
typedef ECARD_HANDLE* PECARD_HANDLE;

typedef long long INT64;
typedef unsigned long long UINT64;

typedef short SHORT;
typedef unsigned short USHORT;

typedef unsigned int UINT32;

typedef unsigned long ULONG;

typedef void * LPVOID;


#define ECARD_INVALID_HANDLE_VALUE ((ECARD_HANDLE) 0xFFFFFFFF)

/*!
 * @enum ECARD_PROTOCOL
 */
enum ECARD_PROTOCOL
{
  PROTOCOL_CTAPI,
  PROTOCOL_PCSC,
  PROTOCOL_BTRD,
  PROTOCOL_PCSC_TCP,
  PROTOCOL_PCSC_LIBRFID,
  PROTOCOL_EXTERNAL_LIB,
  PROTOCOL_TCP_GT
};

/*!
 * @enum ECARD_PIN_STATE
 */
enum ECARD_PIN_STATE
{
  PIN_STATE_ACTIVATED,   // The PIN is not activated
  PIN_STATE_NOT_ACTIVE,  // The PIN is activated
  PIN_STATE_UNKNOWN,     // The card is not known by the API
  PIN_STATE_NOPIN        // The card has no PIN protection
};

/*!
 *
 */
typedef struct ECARD_KEYBLOB_
{
  BYTE* keyData;
  DWORD keySize;
} ECARD_KEYBLOB, *PECARD_KEYBLOB;

#endif
