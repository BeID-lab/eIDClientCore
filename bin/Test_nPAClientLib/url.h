#ifndef _URL_H
#define _URL_H

#include <algorithm>
#include <string.h>
#include <string>

class URL
{
	public:
		URL(const char *url) {
			if (!parse_url(url))
				_valid = false;
			else
				_valid = true;
		}

		std::string  _scheme;
		std::string  _hostname;
		std::string  _port;
		std::string  _path;
		bool _valid;

		bool parse_url(const char *str, const char *default_port = "80") {
			if (!str || !*str)
				return false;

			const char *p1 = strstr(str, "://");

			if (p1) {
				_scheme.assign(str, p1 - str);
				p1 += 3;
				std::transform(_scheme.begin(), _scheme.end(), _scheme.begin(), static_cast<int ( *)(int)>(tolower));

				if (0x00 == _scheme.compare("https")) {
					default_port = "443";
				}

			} else {
				p1 = str;
			}

			const char *p2 = strchr(p1, ':');

			//      const char* p3 = p2 ? strchr(p2+1, '/'): p2;
			const char *p3 = strchr(p1, '/');

			if (p2) {
				_hostname.assign(p1, p2 - p1);

				if (p3) {
					_port.assign(p2 + 1, p3 - (p2 + 1));
					_path = p3;

				} else {
					_port.assign(p2 + 1);
				}

			} else {
				_port = default_port;

				if (p3) {
					_hostname.assign(p1, p3 - p1);
					_path = p3;

				} else {
					_hostname = p1;
				}
			}

			if (_path.empty())
				_path = "";

			return true;
		}
};
#endif
