/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */
#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <time.h>
#include <stdlib.h>
#include "debug.h"

unsigned char USED_DEBUG_LEVEL;

#if defined(_WIN32) && !defined(_WIN32_WCE)
#include <windows.h>
#endif

#if defined(_WIN32)
void timestamp()
{
	SYSTEMTIME tv;
	char buffer[30];
	memset(buffer, 0, sizeof buffer);

	GetLocalTime(&tv);

	sprintf(buffer, "%02d:%02d:%02d.%03d ", tv.wHour, tv.wMinute, tv.wSecond, tv.wMilliseconds);

	OutputDebugStringA(buffer);
}
#else
#include <sys/time.h>
#include <string.h>
void timestamp()
{
	time_t curtime;
	struct timeval tv;
	char buffer[30];
	memset(buffer, 0, sizeof buffer);

	gettimeofday(&tv, NULL); 
	curtime=tv.tv_sec;

	strftime(buffer,30,"%T",localtime(&curtime));

	printf("%s.%03ld ",buffer,tv.tv_usec/1000);
}
#endif

#if defined(_WIN32) && !defined(_WIN32_WCE)
#include <windows.h>
#define my_puts(s) { timestamp(); OutputDebugStringA(s); OutputDebugStringA("\n"); }
#else
#define my_puts(s) { timestamp(); puts(s);fflush(stdout); }
#endif


#define BYTES_PER_LINE 16
#define ADDRESS_LENGTH 8
#define BUFFERSIZE 16384

void _hexdump(const char *const caption,
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
			printed = sprintf(pline, "%0*zX ", ADDRESS_LENGTH, p - (unsigned char *) buffer);

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

void _eCardCore_info(const char *format, ...)
{

	va_list params;
	char newMessage[BUFFERSIZE];
	int rlen = 0;
	va_start(params, format);

	rlen = vsnprintf(newMessage, BUFFERSIZE, format, params);
	if(rlen >= BUFFERSIZE)
	{
		/*Buffer is too small, have to dynamically alocate more memory*/
		char * dynMessage = (char*) malloc(rlen + 1);
		vsnprintf(dynMessage, rlen + 1, format , params);
		my_puts(dynMessage);
		free(dynMessage);
	}
	else
	{
		my_puts(newMessage);
	}
}
void _eCardCore_warn(const char *format, ...)
{
	va_list params;
	char newMessage[BUFFERSIZE];
	int rlen = 0;
	va_start(params, format);

	rlen = vsnprintf(newMessage, BUFFERSIZE, format, params);
	if(rlen >= BUFFERSIZE)
	{
		/*Buffer is too small, have to dynamically alocate more memory*/
		char * dynMessage = (char*) malloc(rlen + 1);
		vsnprintf(dynMessage, rlen + 1, format , params);
		my_puts(dynMessage);
		free(dynMessage);
	}
	else
	{
		my_puts(newMessage);
	}
}
void _eCardCore_debug(const char *format, ...)
{
	va_list params;
	char newMessage[BUFFERSIZE];
	int rlen = 0;
	va_start(params, format);

	rlen = vsnprintf(newMessage, BUFFERSIZE, format, params);
	if(rlen >= BUFFERSIZE)
	{
		/*Buffer is too small, have to dynamically alocate more memory*/
		char * dynMessage = (char*) malloc(rlen + 1);
		vsnprintf(dynMessage, rlen + 1, format , params);
		my_puts(dynMessage);
		free(dynMessage);
	}
	else
	{
		my_puts(newMessage);
	}
}


#ifdef __cplusplus
}
#endif
