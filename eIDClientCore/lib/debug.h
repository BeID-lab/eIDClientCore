/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#if !defined(__DEBUG_H_INCLUDED__)
#define __DEBUG_H_INCLUDED__


#ifdef __cplusplus
extern "C" {
#endif


#define DEBUG_LEVEL_APDU   0x01
#define DEBUG_LEVEL_CRYPTO 0x02
#define DEBUG_LEVEL_SSL    0x04
#define DEBUG_LEVEL_PAOS   0x08
#define DEBUG_LEVEL_CARD   0x10
#define DEBUG_LEVEL_CLIENT 0x20
#define DEBUG_LEVEL_READER 0x40
#define DEBUG_LEVEL_TIME   0x80
#define DEBUG_LEVEL_ALL    (DEBUG_LEVEL_APDU|DEBUG_LEVEL_CRYPTO|DEBUG_LEVEL_SSL|DEBUG_LEVEL_PAOS|DEBUG_LEVEL_CARD|DEBUG_LEVEL_CLIENT)
extern unsigned char USED_DEBUG_LEVEL;

#ifdef __ANDROID__
/* stlport doesn't provide vector.data() */
#define DATA(v) ((v).size()?&v[0]:NULL)
#else
#define DATA(v) ((v).data())
#endif

#define hexdump(level, caption, buffer, length) { \
		if (level & USED_DEBUG_LEVEL) _hexdump(caption, buffer, length); }
#define startTimer(){ \
	    if ( DEBUG_LEVEL_TIME & USED_DEBUG_LEVEL) _startTimer(); }
#define stopTimer(){ \
	    if ( DEBUG_LEVEL_TIME & USED_DEBUG_LEVEL) _stopTimer(); }
#define eCardCore_info(level, ...) { \
		if (level & USED_DEBUG_LEVEL) _eCardCore_info(__VA_ARGS__); }
#define eCardCore_warn(level, ...) { \
		if (level & USED_DEBUG_LEVEL) _eCardCore_warn(__VA_ARGS__); }
#define eCardCore_debug(level, ...) { \
		if (level & USED_DEBUG_LEVEL) _eCardCore_debug(__VA_ARGS__); }


void timestamp();

#if defined(_WIN32) && !defined(_WIN32_WCE)
#include <windows.h>
#define my_puts(s) { timestamp(); OutputDebugStringA(s); OutputDebugStringA("\n"); }
#else
#include <stdio.h>
#define my_puts(s) { timestamp(); puts(s);fflush(stdout); }
#endif
void _hexdump(const char *const caption,
		const void *const buffer, size_t length);
void _startTimer();
void _stopTimer();
void _eCardCore_info(const char *format, ...);
void _eCardCore_warn(const char *format, ...);
void _eCardCore_debug(const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif
