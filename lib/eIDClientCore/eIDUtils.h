/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#if !defined(__EIDUTILS__)
#define __EIDUTILS__

#include <string>
#include <ctime>
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
