// ---------------------------------------------------------------------------
// Copyright (c) 2007 Bundesruckerei GmbH
// All rights reserved.
//
// $Id: CardCommand.h 1427 2012-01-17 15:04:42Z x_schrom $
// ---------------------------------------------------------------------------

#if !defined(__CARDCOMMAND_INCLUDED__)
#define __CARDCOMMAND_INCLUDED__

#include <eCardTypes.h>

#include <vector>
#include <iostream>
using namespace std;

/*!
 * @class CardCommand
 */
class CardCommand : public vector<BYTE>
{
public:
  /*!
   * @TODO: We have to implement a more convenient class which can handle more then one
   *        COS.
   */
  static CardCommand selectFile (
    unsigned short FID)
  {
    CardCommand cardCmd;

    if (FID == 0x3F00)
      cardCmd << 0x00 << 0xA4 << 0x00 << 0x0C << 0x02 << ((FID & 0xFF00) >> 8) << (FID & 0xFF);
    else
      cardCmd << 0x00 << 0xA4 << 0x02 << 0x0C << 0x02 << ((FID & 0xFF00) >> 8) << (FID & 0xFF);

    return cardCmd;
  }

  /*!
   *
   */
  CardCommand& operator << (BYTE b)
  {
      push_back(b);
      return *this;
  }

  /*!
   *
   */
  string asString()
  {
    string ret;

    for (size_t i = 0; i < size(); i++)
    {
      char buffer[7] = { 0 };

      if (
        (operator[](1) != 0x20) && // required by BSI to supress verify log information ( PIN/PUK etc. )
        (operator[](1) != 0x24) &&
        (operator[](1) != 0xDA))
      {
        sprintf(buffer, "0x%02X ", operator[](i));
      } else {
        if (i < 4)
        {
          sprintf(buffer, "0x%02X ", operator[](i));
        }
      }

      ret += buffer;
    }

    return ret;
  }
};


class FilePath : public vector<BYTE>
{
public:
  /*!
   *
   */
  FilePath& operator << (BYTE b)
  {
      push_back(b);
      return *this;
  }

  /*!
   *
   */
  FilePath& operator = (const FilePath& path)
  {
    clear();

    for (size_t i = 0; i < path.size(); i++)
      push_back(path[i]);

    return *this;
  }
};

/*!
 * @class CardResult
 */

class CardResult:public vector < BYTE >
{
public:
  static const UINT32 MAX_DATASIZE = 0x400;

  /*!
   *
   */
  CardResult ()
  {
    resize (MAX_DATASIZE);
  }

  /*!
   *
   */
  bool isOK ()
  {
    if (0 == size())
      return false;

    if (operator[](size () - 2) == 0x90 &&
      operator[](size () - 1) == 0x00)
      return true;

    if (operator[](size () - 2) == 0x61)
      return true;

    return false;
  }

  /*!
   * TODO: Version for Secure Messaging which looks for the 3rd and 4th byte
   */
  unsigned short getSW (
    void)
  {
    if (size() == 0)
      return 0;

    unsigned short result = 0;
    result += operator[](size () - 2) << 8;
    result += operator[](size () - 1);

    return result;
  }

  /*!
   *
   */
  vector<BYTE> getData ()
  {
    vector < BYTE > data;

    if (size () > 2)
      data.assign (&operator[](0), &operator[](size () - 2));

    return data;
  }

  /*!
   *
   */
  string asString()
  {
    string ret;

    for (size_t i = 0; i < size() - 2; i++)
    {
      char buffer[7] = { 0 };
      sprintf(buffer, "0x%02X ", operator[](i));
      ret += buffer;
    }

    if (ret.size() == 0)
      ret = "NO RESPONSE DATA";

    return ret;
  }
};


#endif

