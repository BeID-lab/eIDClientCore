#if !defined(__TEST_NPACLIENTLIB_H_INCLUDED__)
#define __TEST_NPACLIENTLIB_H_INCLUDED__

int performEID(std::string strServiceURL,
		std::string strIdpAddress, 
		std::string strSessionIdentifier,
		std::string strPathSecurityParameters, 
		std::string strRef,
		std::string cardReaderName,
		std::string &response);
		
std::string str_replace_ifnot(std::string rep, std::string wit, std::string ifnot, std::string in);

#include "cmdline.h"

#ifdef __cplusplus
extern "C" {
#endif

extern enum enum_testcase SAML_VERSION;
extern const char *pin;

#ifdef __cplusplus
}
#endif

#endif
