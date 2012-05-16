// ----------------------------------------------------------------------------
// Copyright (c) 2007 Bundesdruckerei GmbH
// All rights reserved.
//
// $Id: eCardStatus.h 846 2010-08-19 07:58:17Z fiedlrob $
// ----------------------------------------------------------------------------

/*!
 * @file eCardStatus.h
 */

#if !defined(__ECARDSTATUS_INCLUDED__)
#define __ECARDSTATUS_INCLUDED__

typedef unsigned long ECARD_STATUS;

#define ECARD_INFO    0xA0000000
#define ECARD_WARNING 0xB0000000
#define ECARD_ERROR   0xC0000000

#define IS_ECARD_INFO(x)    (EDA_INFO == (x & 0xF0000000))
#define IS_ECARD_WARNING(x) (EDA_WARNING == (x & 0xF0000000))
#define IS_ECARD_ERROR(x)   (EDA_ERROR == (x & 0xF0000000))

#define ECARD_SUCCESS (ECARD_STATUS) 0x00000000

#define ECARD_PROTOCOL_NOT_IMPLEMENTED  ECARD_ERROR + 0x00000001
#define ECARD_PROTOCOL_UNKNOWN          ECARD_ERROR + 0x00000002
#define ECARD_PIN_VERIFICATION_FAILED   ECARD_ERROR + 0x00000003
#define ECARD_INVALID_PARAMETER_1       ECARD_ERROR + 0x00000004
#define ECARD_NO_SUCH_READER            ECARD_ERROR + 0x00000005
#define ECARD_READER_NOT_AVAILABLE      ECARD_ERROR + 0x00000006
#define ECARD_BUFFER_TO_SMALL           ECARD_ERROR + 0x00000007
#define ECARD_UNKNOWN_CARD              ECARD_ERROR + 0x00000008
#define ECARD_READ_ERROR                ECARD_ERROR + 0x00000008
#define ECARD_WRITE_ERROR               ECARD_ERROR + 0x00000009
#define ECARD_SELECT_FILE_FAILD         ECARD_ERROR + 0x0000000A
#define ECARD_VERIFY_PIN_FAILD          ECARD_ERROR + 0x0000000B
#define ECARD_INVALID_FILE_SIZE         ECARD_ERROR + 0x0000000C
#define ECARD_INVALID_CA_DOMAIN_PARAMS  ECARD_ERROR + 0x0000000C
#define ECARD_INVALID_CA_CAPKI          ECARD_ERROR + 0x0000000D
#define ECARD_ASN1_PARSER_ERROR         ECARD_ERROR + 0x0000000E

#define ECARD_FILE_ALREADY_EXIST        ECARD_WARNING + 0x00000001

#define ECARD_USER_INFO_OFFSET          ECARD_INFO + 0x0000A000
#define ECARD_MAKE_USER_INFO(x)         ECARD_USER_INFO_OFFSET + x

#define ECARD_USER_WARNING_OFFSET       ECARD_WARNING + 0x0000B000
#define ECARD_MAKE_USER_WARNING(x)      ECARD_USER_WARNING_OFFSET + x

#define ECARD_USER_ERROR_OFFSET         ECARD_ERROR + 0x0000C000
#define ECARD_MAKE_USER_ERROR(x)        ECARD_USER_ERROR_OFFSET + x


#endif
