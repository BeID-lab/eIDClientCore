/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#if !defined(__ECARDCORE_INTERN_INCLUDED__)
#define __ECARDCORE_INTERN_INCLUDED__


#ifdef __cplusplus
extern "C" {
#endif


#define DEBUG_LEVEL_APDU   0x01
#define DEBUG_LEVEL_CRYPTO 0x02
#define DEBUG_LEVEL_SSL    0x04
#define DEBUG_LEVEL_PAOS   0x08
#define DEBUG_LEVEL_CARD   0x10
#define DEBUG_LEVEL_CLIENT 0x20
#define DEBUG_LEVEL_ALL    (DEBUG_LEVEL_APDU|DEBUG_LEVEL_CRYPTO|DEBUG_LEVEL_SSL|DEBUG_LEVEL_PAOS|DEBUG_LEVEL_CARD|DEBUG_LEVEL_CLIENT)
#define USED_DEBUG_LEVEL DEBUG_LEVEL_ALL


#define hexdump(level, caption, buffer, length) { \
		if (level & USED_DEBUG_LEVEL) _hexdump(caption, buffer, length); }
#define eCardCore_info(level, ...) { \
		if (level & USED_DEBUG_LEVEL) _eCardCore_info(__VA_ARGS__); }
#define eCardCore_warn(level, ...) { \
		if (level & USED_DEBUG_LEVEL) _eCardCore_warn(__VA_ARGS__); }
#define eCardCore_debug(level, ...) { \
		if (level & USED_DEBUG_LEVEL) _eCardCore_debug(__VA_ARGS__); }

#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>

#if defined(WIN32) && !defined(_WIN32_WCE)
#include <windows.h>
#define my_puts(s) { OutputDebugStringA(s); OutputDebugStringA("\n"); }
#else
#define my_puts(s) puts(s)
#endif


#define BYTES_PER_LINE 16
#define ADDRESS_LENGTH 8

	static void _hexdump(const char *const caption,
						 const void *const buffer, size_t length)
	{
		char line[
			ADDRESS_LENGTH + 1 + /* Address */
			BYTES_PER_LINE / 8 + /* Extra separator between every 8 bytes */
			BYTES_PER_LINE * 3 + 1 + /* Byte printed in hex */
			2 +                  /* Left bar */
			BYTES_PER_LINE +     /* Byte Printed in ASCII */
			1 +                  /* Right bar */
			1                    /* Terminator */
		];
		char *pline;
		unsigned char *p = (unsigned char *) buffer;
		size_t done = 0;
		size_t i;
		int printed;

		if (caption)
			my_puts(caption);

		if (!length || !buffer) {
			my_puts("<absent>");

		} else
			while (length > done) {
				pline = line;
				/* Address */
				printed = sprintf(pline, "%0*lX ", ADDRESS_LENGTH, p - (unsigned char *) buffer);

				if (printed < 0)
					return;

				pline += printed;

				for (i = 0; i < BYTES_PER_LINE; i++) {
					/* Extra separator between every 8 bytes */
					if ((i % 8) == 0) {
						printed = sprintf(pline, " ");

						if (printed < 0)
							return;

						pline += printed;
					}

					/* Byte printed in hex */
					if (done + i >= length)
						printed = sprintf(pline, "   ");

					else
						printed = sprintf(pline, "%02X ", p[i]);

					if (printed < 0)
						return;

					pline += printed;
				}

				/* Left bar */
				printed = sprintf(pline, " |");

				if (printed < 0)
					return;

				pline += printed;

				/* Byte Printed in ASCII */
				for (i = 0; i < BYTES_PER_LINE; i++) {
					if (done + i >= length)
						printed = 0;

					else {
						if (isprint(p[i]))
							printed = sprintf(pline, "%c", p[i]);

						else
							printed = sprintf(pline, ".");
					}

					if (printed < 0)
						return;

					pline += printed;
				}

				/* Right bar */
				printed = sprintf(pline, "|");

				if (printed < 0)
					return;

				pline += printed;
				/* Terminator */
				*pline = '\0';
				my_puts(line);
				done += BYTES_PER_LINE;
				p += BYTES_PER_LINE;
			}
	}

	static void _eCardCore_info(const char *format, ...)
	{
		va_list params;
		va_start(params, format);
		char newMessage[4096];
		vsprintf(newMessage, format, params);
		my_puts(newMessage);
	}
	static void _eCardCore_warn(const char *format, ...)
	{
		va_list params;
		va_start(params, format);
		char newMessage[4096];
		vsprintf(newMessage, format, params);
		my_puts(newMessage);
	}
	static void _eCardCore_debug(const char *format, ...)
	{
		va_list params;
		va_start(params, format);
		char newMessage[4096];
		vsprintf(newMessage, format, params);
		my_puts(newMessage);
	}


#ifdef __cplusplus
}
#endif

#endif
