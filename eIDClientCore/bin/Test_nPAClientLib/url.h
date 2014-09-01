#ifndef _URL_H
#define _URL_H

#include <algorithm>
#include <string>

class URL
{
	public:
		URL(const char *const url) {
			_scheme.assign("");
			_hostname.assign("");
			_port.assign("");
			_path.assign("");

			if (url && *url) {
				std::string _str(url);
				_valid = parse_url(_str);
			} else _valid = false;
		}

		std::string _scheme;
		std::string _hostname;
		std::string _port;
		std::string _path;
		bool _valid;

		bool parse_url(std::string& url) {
			std::string prefix("https");
			std::string::size_type idx;

			_port.assign("80");

			if (prefix.length() >= url.length())
				return false;
			idx = url.find("://");
			if (idx != std::string::npos) {
				auto res = std::mismatch(prefix.begin(), prefix.end(), url.begin());
				if (res.first == prefix.end()) {
					_scheme = "https";
					_port = "443";
				} else if (res.first == (prefix.end()-1)) {
					_scheme = "http";
				} else {
					return false;
				}
				url.erase(0, (idx+3));
			}
			idx = url.find(":");
			if (idx != std::string::npos) {
				_hostname = url.substr(0, idx);
				url.erase(0, (idx+1));
				idx = url.find("/");
				if (idx != std::string::npos) {
					_port = url.substr(0, idx);
					url.erase(0, idx);
					_path = url;
				}
			} else {
				idx = url.find("/");
				if (idx != std::string::npos) {
					_hostname = url.substr(0, idx);
					url.erase(0, idx);
					_path = url;
				}
			}
			return true;
		}
};
#endif
