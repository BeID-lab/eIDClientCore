// ---------------------------------------------------------------------------
// Copyright (c) 2009 Bundesdruckerei GmbH
// All rights reserved.
//
// $Id: BDRDate.cpp 731 2010-03-19 12:26:27Z dietrfra $
// ---------------------------------------------------------------------------

#include "eIdUtils.h"
using namespace Bundesdruckerei::eIdUtils;

#include <string>
#include <stdlib.h>
#include <stdio.h>

#include <cstdio>

#if defined(WIN32)
#	include <windows.h>
#else
#include <stdarg.h>
#endif

#if !defined(WIN32)

// _itoa isn't standard compliant :( I think to define _itoa is the best way to
// solve this problem.
char* _itoa (int value, char * str, int base)
{
  switch (base) {
    case 8:
      sprintf(str,"%o",value);
      break;
    case 10:
      sprintf(str,"%d",value);
      break;
    case 16:
      sprintf(str,"%x",value);
      break;
  }
  
  return str;
}

#endif

//Loggingfunctions
void debugOut(
	const char* format,
	...)
{
#if defined(_DEBUG) || defined(DEBUG)
	va_list params;
	va_start (params, format);

	char message[4096];
	memset(&message[0], 0x00, 4096);
	int ret = vsprintf(message, format, params);

	// hack
	printf ("%s\n", message);

#if defined(WIN32)
	if(ret > 0)
		OutputDebugStringA(message);
	else
		OutputDebugStringA("Logging went totally wrong");
#else
	std::cout << message << std::endl;
#endif
#endif
}

void errorOut(
	const char* format,
	...)
{
	va_list params;
	va_start (params, format);

	char message[4096];
	int ret = vsprintf(message, format, params);

#if defined(WIN32)
	if(ret > 0)
		OutputDebugStringA(message);
	else
		OutputDebugStringA("Logging went totally wrong");
#else
	std::cout << message << std::endl;
#endif
}

std::string BDRDate::fromBCD(
  const ByteData& data)
{
  char tempVal[2];
  std::string retValue;
  ByteData internalData(data);

  _itoa(internalData.elementAt(4), (char*) &tempVal, 10);  
  retValue += tempVal;

  _itoa(internalData.elementAt(5), (char*) &tempVal, 10);
  retValue += tempVal;
  retValue += ".";

  _itoa(internalData.elementAt(2), (char*) &tempVal, 10);
  retValue += tempVal;

  _itoa(internalData.elementAt(3), (char*) &tempVal, 10);  
  retValue += tempVal;
  retValue += ".";
  retValue += "20";

  _itoa(internalData.elementAt(0), (char*) &tempVal, 10);
  retValue += tempVal;

  _itoa(internalData.elementAt(1), (char*) &tempVal, 10);  
  retValue += tempVal;

  return retValue;
}

time_t BDRDate::timeFromBCD(
  const ByteData& data)
{
  ByteData internalData(data);
  struct tm tmReturn;
  char buf[5];
  int tempValue = 0;

  tempValue=  internalData.elementAt(4) << 4;
  tempValue += internalData.elementAt(5);

  sprintf(buf, "%02x", tempValue);
  tmReturn.tm_mday = atoi(buf);

  tempValue=  internalData.elementAt(2) << 4;
  tempValue += internalData.elementAt(3);

  sprintf(buf, "%02x", tempValue);
  tmReturn.tm_mon = atoi(buf);

  tempValue=  internalData.elementAt(0) << 4;
  tempValue += internalData.elementAt(1);

  sprintf(buf, "20%02x", tempValue);
  tmReturn.tm_year = atoi(buf) - 1900;

  tmReturn.tm_hour = 0;
  tmReturn.tm_isdst = 0;
  tmReturn.tm_min = 0;
  tmReturn.tm_sec = 0;
  tmReturn.tm_wday = 0;
  tmReturn.tm_yday = 0;

  return mktime(&tmReturn);
}

/*
 *
 */
ByteData::ByteData(
  void)
{
}

/*
 *
 */
ByteData::~ByteData(
  void)
{
}

/*
 *
 */
ByteData::ByteData(
  unsigned char const* pByteBuffer,
  size_t bufferSize)
{
  m_byteVector.assign(
    &pByteBuffer[0], 
    &pByteBuffer[bufferSize]);
}

/*
 *
 */
ByteData::ByteData(
  const ByteData& byteData)
{
  m_byteVector.assign(
    byteData.m_byteVector.begin(),
    byteData.m_byteVector.end());
}

/*
 *
 */
ByteData::ByteData(
  const std::vector<unsigned char>& vec)
{
  m_byteVector = vec;
}

/*
*
*/
ByteData& ByteData::operator =(
  const ByteData& byteData)
{
  m_byteVector.assign(
    byteData.m_byteVector.begin(),
    byteData.m_byteVector.end());

  return *this;
}

/*
*
*/
ByteData& ByteData::operator =(
  const std::vector<unsigned char>& vec)
{
  m_byteVector = vec;

  return *this;
}

/*
 *
 */
unsigned char ByteData::elementAt(
  size_t idx)
{
  return m_byteVector[idx];
}

/*
 *
 */
std::vector<unsigned char> ByteData::data() const
{
  return m_byteVector;
}
