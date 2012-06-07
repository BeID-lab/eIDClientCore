// ---------------------------------------------------------------------------
// Copyright (c) 2009 Bundesdruckerei GmbH
// All rights reserved.
//
// $Id: BDRDate.h 682 2010-02-15 14:09:14Z rfiedler $
// ---------------------------------------------------------------------------

#if !defined(__EIDUTILS__)
#define __EIDUTILS__

#include <time.h>
#include <vector>
#include <iostream>


void debugOut(const char* format, ...);
void errorOut(const char* format, ...);

//using namespace std;

namespace Bundesdruckerei
{
  namespace eIdUtils
  {
    /*
    * @class ByteData
    *
    * This class represents a buffer of bytes.
    */
    class ByteData
    {
    private:
      std::vector<unsigned char> m_byteVector;

    public:
      /**
       * ctor
       */
      ByteData(
        void);

      /**
       * dtor
       */
      ~ByteData(
        void);

      /**
       * ctor
       *
       * @param pByteData Buffer to an array of unsigned char.
       * @param bufferSize Size of the array.
       */
      ByteData(
        unsigned char const* pByteBuffer,
        size_t bufferSize);

      /**
       * ctor
       *
       * @param Reference to a ByteData object to construct from.
       */
      ByteData(
        const ByteData& byteData);

      /**
       * ctor
       *
       * @param Reference to a ByteData object to construct from.
       */
      ByteData(
        const std::vector<unsigned char>& vec);

	  /**
       * Assignment operator
       */
      ByteData& operator=(
        const ByteData& byteData);

      ByteData& operator=(
        const std::vector<unsigned char>& vec);

	  /**
       *
       */
      unsigned char elementAt(
        size_t idx);

      /**
       *
       */
      std::vector<unsigned char> data() const;
    }; // class ByteData

    /*
    * @class BDRDate
    *
    */
    class BDRDate
    {
    public:
      static std::string fromBCD(
        const ByteData&);

      static time_t timeFromBCD(
        const ByteData&);
    };
  }
}

#endif // __EIDUTILS__
