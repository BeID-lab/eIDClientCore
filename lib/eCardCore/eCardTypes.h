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

#define ECARD_INVALID_HANDLE_VALUE ((ECARD_HANDLE) 0xFFFFFFFF)

/*!
 * @enum ECARD_PROTOCOL
 */
typedef enum ECARD_PROTOCOL
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
typedef enum ECARD_PIN_STATE
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

typedef unsigned char* (*ByteDataAllocator_t)(size_t size);
typedef void (*ByteDataDeallocator_t)(unsigned char* data);

/*!
* @struct BYTE_INPUT_DATA
*/
typedef struct BYTE_INPUT_DATA_t
{
  BYTE* pData;
  size_t dataSize;
} BYTE_INPUT_DATA, *PBYTE_INPUT_DATA;

/*!
* @struct BYTE_OUTPUT_DATA
*/
typedef struct BYTE_OUTPUT_DATA_t
{
  unsigned char* m_pDataBuffer;
  size_t m_dataSize;

  ByteDataAllocator_t   m_allocator;
  ByteDataDeallocator_t m_deallocator;

  /*!
  *
  */
  BYTE_OUTPUT_DATA_t(
    ByteDataAllocator_t allocator,
    ByteDataDeallocator_t deallocator) : 
    m_pDataBuffer(0x00), m_dataSize(0), m_allocator(allocator), m_deallocator(deallocator)
  {
    assert(0x00 != m_allocator);
    assert(0x00 != m_deallocator);
  }

  /*!
   *
   */
  ~BYTE_OUTPUT_DATA_t(
    void)
  {
    if (0x00 != m_pDataBuffer)
      m_deallocator(m_pDataBuffer);
  }
} BYTE_OUTPUT_DATA, *PBYTE_OUTPUT_DATA;

#endif
