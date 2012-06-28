// ---------------------------------------------------------------------------
// Copyright (c) 2009 Bundesdruckerei GmbH
// All rights reserved.
//
// $Id: ePAAPI.cpp 1192 2011-06-09 13:54:43Z dietrfra $
// ---------------------------------------------------------------------------

//#define PROTO_TEST

#include "ePAAPI.h"
#include "ePAStatus.h"
#include "ePACard.h"
//#include "CHAT.h"
using namespace Bundesdruckerei::nPA;

#include <ICard.h>
#include <SecurityInfos.h>
#include <PACEDomainParameterInfo.h>
#include <eIDHelper.h>
#include <eIDOID.h>
#include <ePACommon.h>

#include <cstdio>

/** 
 */
ECARD_STATUS __STDCALL__ ePASelectFile(
  IN ECARD_HANDLE hCard,
  IN USHORT fid)
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
    if (!ePA->selectFile(fid, ""))
      return ECARD_SELECT_FILE_FAILD;
  }

  return ECARD_SUCCESS;
}

/**
 */
ECARD_STATUS __STDCALL__ ePAGetFileSize(
  IN ECARD_HANDLE hCard,
  IN USHORT fid,
  IN OUT PDWORD dwSize)
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
ECARD_STATUS __STDCALL__ ePAGetFileSize(
  IN ECARD_HANDLE hCard,
  IN USHORT fid,
  IN std::vector<unsigned char>& kEnc,
  IN std::vector<unsigned char>& kMac,
  IN unsigned long long& ssc,
  IN OUT PDWORD dwSize)
{
  // Check handle ...
  if (0x00 == hCard || ECARD_INVALID_HANDLE_VALUE == hCard)
    return ECARD_INVALID_PARAMETER_1;

  // Try to get ePA card
  ICard* card_ = (ICard*) hCard;
  ePACard* ePA_ = dynamic_cast<ePACard*>(card_);

  // No ePA -> Leave
  if (0x00 == ePA_)
    return ECARD_INVALID_EPA;

  CardCommand SelectFile;
  SelectFile << 0x0C << 0xA4 << 0x02 << 0x04;

  // Build up command data field
  std::vector<unsigned char> dataPart_;
  dataPart_.push_back(((fid & 0xFF00) >> 8));
  dataPart_.push_back((fid & 0xFF));

  std::vector<unsigned char> do97_;
  do97_.push_back(0x97); do97_.push_back(0x01); do97_.push_back(0x00);

  // Build the SM related structures.
  std::vector<unsigned char> do87_ = buildDO87_AES(kEnc, dataPart_, ssc);
  std::vector<unsigned char> do8E_ = buildDO8E_AES(kMac, SelectFile, do87_, do97_, ssc);

  // Append LC
  SelectFile.push_back(do87_.size() + do97_.size() + do8E_.size());

  // Append DO87 to APDU
  for (size_t i = 0; i < do87_.size(); i++)
    SelectFile.push_back(do87_[i]);

  // Append DO97 to APDU
  for (size_t i = 0; i < do97_.size(); i++)
    SelectFile.push_back(do97_[i]);

  // Append DO8E to APDU
  for (size_t i = 0; i < do8E_.size(); i++)
    SelectFile.push_back(do8E_[i]);

  SelectFile.push_back(0x00);

  // Do the dirty work.
  CardResult MseSetDST_Result_ = ePA_->sendAPDU(SelectFile, "SELECT for EF.CardSecurity.");
  if (MseSetDST_Result_.getSW() != 0x9000)
    return ECARD_SELECT_FILE_FAILD;

  // Get returned data.
  std::vector<unsigned char> returnedData = MseSetDST_Result_.getData();

  // Verify the SM response from the card.
  if (!verifyResponse_AES(kMac, returnedData, ssc))
    return ECARD_VERIFY_RESPONSE_FAILED;

  std::vector<unsigned char> decryptedFCP = decryptResponse_AES(kEnc, returnedData, ssc);


  if (decryptedFCP[2] == 0x80)
    *dwSize = (decryptedFCP[4] << 8) + decryptedFCP[5];

  hexdump("###-> Decrypted response (FCP): ", &decryptedFCP[0], decryptedFCP.size());

  if (0x00 == *dwSize)
    return ECARD_INVALID_FILE_SIZE;

  return ECARD_SUCCESS;
}

/**
 */
ECARD_STATUS __STDCALL__ ePAReadFile(
  IN ECARD_HANDLE hCard,
  IN size_t bytesToRead,
  IN OUT std::vector<unsigned char>& fileContent)
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

  // Read the file data
  vector<BYTE> fileData;
  if (!ePA->readFile(bytesToRead, fileData))
    return ECARD_READ_ERROR;

  // Allocate the output buffer and copy the file content into.
  fileContent = fileData;

  return ECARD_SUCCESS;
}

/**
 */
ECARD_STATUS __STDCALL__ ePAReadFile(
  IN ECARD_HANDLE hCard,
  IN std::vector<unsigned char>& kEnc,
  IN std::vector<unsigned char>& kMac,
  IN unsigned long long& ssc,
  IN size_t bytesToRead,
  IN OUT std::vector<unsigned char>& fileContent)
{
  // Check handle ...
  if (0x00 == hCard || ECARD_INVALID_HANDLE_VALUE == hCard)
    return ECARD_INVALID_PARAMETER_1;

  // Try to get ePA card
  ICard* card_ = (ICard*) hCard;
  ePACard* ePA_ = dynamic_cast<ePACard*>(card_);

  // No ePA -> Leave
  if (0x00 == ePA_)
    return ECARD_INVALID_EPA;

  unsigned short offset_ = 0;
  std::vector<unsigned char> content;

  while (offset_ < bytesToRead)
  { 
    CardCommand ReadBinary;
    ReadBinary << 0x0C << 0xB0 << 0x00 << 0x00;

    ReadBinary[2] = offset_ >> 8;
    ReadBinary[3] = offset_ & 0xFF;

    std::vector<unsigned char> do97_;
    do97_.push_back(0x97); do97_.push_back(0x01); do97_.push_back(0x00);

    if (bytesToRead - offset_ > 0xC8)
      do97_[2] = 0xC8;
    else
      do97_[2] = bytesToRead - offset_;    

    std::vector<unsigned char> do87_; // Empty ... No data part!
    std::vector<unsigned char> do8E_ = buildDO8E_AES(kMac, ReadBinary, do87_, do97_, ssc);

    // Append LC
    ReadBinary.push_back(do87_.size() + do97_.size() + do8E_.size());

    // Append DO87 to APDU
    for (size_t i = 0; i < do87_.size(); i++)
      ReadBinary.push_back(do87_[i]);

    // Append DO97 to APDU
    for (size_t i = 0; i < do97_.size(); i++)
      ReadBinary.push_back(do97_[i]);

    // Append DO8E to APDU
    for (size_t i = 0; i < do8E_.size(); i++)
      ReadBinary.push_back(do8E_[i]);

    ReadBinary.push_back(0x00);

    // Do the dirty work.
    CardResult ReadBinary_Result = ePA_->sendAPDU(ReadBinary, "READ BINARY for EF.CardSecurity.");
    if (ReadBinary_Result.getSW() != 0x9000)
      return ECARD_READ_ERROR;

    // Get returned data.
    std::vector<unsigned char> returnedData = ReadBinary_Result.getData();

    // Verify the SM response from the card.
    if (!verifyResponse_AES(kMac, returnedData, ssc))
      return ECARD_VERIFY_RESPONSE_FAILED;

    std::vector<unsigned char> decryptedDataPart = decryptResponse_AES(kEnc, returnedData, ssc);

    hexdump("###-> Decrypted response (File content): ", &decryptedDataPart[0], decryptedDataPart.size());
    offset_ += (unsigned short) decryptedDataPart.size();

    for (size_t i = 0; i < decryptedDataPart.size(); i++)
      content.push_back(decryptedDataPart[i]);
  }

  fileContent = content;

  return ECARD_SUCCESS;
}

/**
*
*/
ECARD_STATUS __STDCALL__ ePASendAPDU(
  IN ECARD_HANDLE hCard,
  IN std::vector<unsigned char> capdu,
  IN OUT std::vector<unsigned char>& rapdu)
{
  // Check handle ...
  if (0x00 == hCard || ECARD_INVALID_HANDLE_VALUE == hCard)
    return ECARD_INVALID_PARAMETER_1;

  // Try to get ePA card
  ICard* card_ = (ICard*) hCard;
  ePACard* ePA_ = dynamic_cast<ePACard*>(card_);

  // No ePA -> Leave
  if (0x00 == ePA_)
    return ECARD_INVALID_EPA;

  CardCommand command;

  for (size_t i = 0; i < capdu.size(); i++)
    command.push_back(capdu[i]);

  std::vector<unsigned char> result_;
  ePA_->sentAPDU(command, result_);

  rapdu = result_;

  return ECARD_SUCCESS;
}
