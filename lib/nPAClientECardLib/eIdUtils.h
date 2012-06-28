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
    * @class BDRDate
    *
    */
    class BDRDate
    {
    public:
      static std::string fromBCD(
        const std::vector<unsigned char>&);

      static time_t timeFromBCD(
        const std::vector<unsigned char>&);
    };
  }
}

#endif // __EIDUTILS__
