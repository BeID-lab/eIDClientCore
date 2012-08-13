// ---------------------------------------------------------------------------
// Copyright (c) 2009 Bundesdruckerei GmbH
// All rights reserved.
//
// $Id: BDRDate.h 682 2010-02-15 14:09:14Z rfiedler $
// ---------------------------------------------------------------------------

#if !defined(__EIDUTILS__)
#define __EIDUTILS__

#include <string>
#include <time.h>
#include <vector>


namespace Bundesdruckerei
{
  namespace eIDUtils
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
