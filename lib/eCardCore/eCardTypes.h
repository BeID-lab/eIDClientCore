/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#if !defined(__ECARDTYPES_INCLUDED__)
#define __ECARDTYPES_INCLUDED__

#include <stddef.h>

typedef unsigned char BYTE;
typedef BYTE *PBYTE;

typedef unsigned long DWORD;
typedef DWORD *PDWORD;

typedef void *ECARD_HANDLE;
typedef ECARD_HANDLE *PECARD_HANDLE;
#define ECARD_INVALID_HANDLE_VALUE ((ECARD_HANDLE) 0xFFFFFFFF)

typedef long long INT64;
typedef unsigned long long UINT64;

typedef short SHORT;
typedef unsigned short USHORT;

typedef unsigned int UINT32;

typedef unsigned long ULONG;

typedef void *LPVOID;


/*!
 * @enum ECARD_PROTOCOL
 */
enum ECARD_PROTOCOL {
	PROTOCOL_PCSC,
};

#endif
