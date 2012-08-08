#include "nPAAPI.h"
#include "nPAStatus.h"
#include "nPACard.h"
//#include "CHAT.h"
using namespace Bundesdruckerei::nPA;

#include "eCardCore/ICard.h"
#include "nPACommon.h"
#include <PACEDomainParameterInfo.h>
#include <SecurityInfos.h>
#include "eidasn1/eIDHelper.h"
#include "eidasn1/eIDOID.h"

#include <cstdio>

/** 
 */
ECARD_STATUS __STDCALL__ ePASelectFile(
  ECARD_HANDLE hCard,
  USHORT fid)
{
  // Check handle ...
  if (0x00 == hCard || ECARD_INVALID_HANDLE_VALUE == hCard)
    return ECARD_INVALID_PARAMETER_1;

  // Try to get ePA card
  ICard* card = (ICard*) hCard;
  ePACard* ePA = dynamic_cast<ePACard*>(card);

  // No ePA -> Leave
  if (0x00 == ePA)
    return ECARD_INVALID_EPA;

  // @TODO: This is a quick solution ... Make it better!!!
  // SELECT differs for EF's and DF's so we have to make separate functions.
  if (0x3F00 == fid)
  {
    if (!ePA->selectMF())
      return ECARD_SELECT_FILE_FAILD;
  }
  else
  {
    if (!ePA->selectEF(fid))
      return ECARD_SELECT_FILE_FAILD;
  }

  return ECARD_SUCCESS;
}

/**
 */
ECARD_STATUS __STDCALL__ ePAGetFileSize(
  ECARD_HANDLE hCard,
  USHORT fid,
  PDWORD dwSize)
{
  // Check handle ...
  if (0x00 == hCard || ECARD_INVALID_HANDLE_VALUE == hCard)
    return ECARD_INVALID_PARAMETER_1;

  // Try to get ePA card
  ICard* card = (ICard*) hCard;
  ePACard* ePA = dynamic_cast<ePACard*>(card);

  // No ePA -> Leave
  if (0x00 == ePA)
    return ECARD_INVALID_EPA;

  // Query the size of the file.
  *dwSize = ePA->getFileSize(fid);

  return ECARD_SUCCESS;
}

/**
 */
ECARD_STATUS __STDCALL__ ePAReadFile(
  ECARD_HANDLE hCard,
  size_t bytesToRead,
  std::vector<unsigned char>& fileContent)
{
  // Check handle ...
  if (0x00 == hCard || ECARD_INVALID_HANDLE_VALUE == hCard)
    return ECARD_INVALID_PARAMETER_1;

  // Try to get ePA card
  ICard* card = (ICard*) hCard;
  ePACard* ePA = dynamic_cast<ePACard*>(card);

  // No ePA -> Leave
  if (0x00 == ePA)
    return ECARD_INVALID_EPA;

  if (!ePA->readFile(bytesToRead, fileContent))
    return ECARD_READ_ERROR;

  return ECARD_SUCCESS;
}