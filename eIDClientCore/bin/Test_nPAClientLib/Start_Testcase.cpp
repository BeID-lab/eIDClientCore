#if defined(WIN32)
#   include <windows.h>
#   include <tchar.h>
#   include <wininet.h>
#   include <wincrypt.h>
#else
# include <unistd.h>
#endif

#include <vector>
#include <sstream>

#include <string>

#include <ctype.h>

#include <debug.h>
#include <testing.h>

#include "Test_nPAClientLib.h"

void printStatistics(int retValue, unsigned int size, int serverErrorCounter, time_t startTime){
	printf("Duration for eID dialog: %f seconds\n", difftime(time(0), startTime));
	printf("main -------------------- end of eID dialog --------------------\n");
	printf("Error Code: %X - Read Count: %u - Server Errors: %u\n", retValue, size, serverErrorCounter);
}

int main(int argc, char **argv)
{
	int loopCount = 1;
	int retValue = 0;
	int serverErrorCounter = 0;
	char buffer[500];
	std::vector<double> diffv;

	const char *serviceURL = NULL;
	std::string cardReaderName;
	
	pin = NULL;
	
	gengetopt_args_info args_info;
	if(cmdline_parser(argc, argv, &args_info) != 0){
		exit(1);
	}
	if(args_info.service_provider_given){
		serviceURL = args_info.service_provider_arg;
	}
	SAML_VERSION = args_info.testcase_arg;
	if(args_info.card_reader_given){
		cardReaderName = std::string(args_info.card_reader_arg);
	}
	if(args_info.pin_given){
		pin = args_info.pin_arg;
	}
	if(args_info.loopcount_given){
		loopCount = args_info.loopcount_arg;
	}
	CANCEL_AFTER_PAOS_CONNECTION_ESTABLISHMENT = args_info.cancel_after_paos_given;
	USED_DEBUG_LEVEL = args_info.debug_level_arg;

	const char *default_serviceURL;
	switch(SAML_VERSION){
		case testcase_arg_Selbstauskunft_Wuerzburg:
			default_serviceURL = "https://www.buergerserviceportal.de/bayern/wuerzburg/bspx_selbstauskunft";
			break;
		case testcase_arg_AutentApp:
			default_serviceURL = "https://www.autentapp.de/AusweisAuskunft/WebServiceRequesterServlet?mode=autentappde";
			break;
		default:
		 	default_serviceURL = "https://eidservices.bundesdruckerei.de"
											":443"
											"/ExampleSP/saml/Login?demo=Authentication+Request+Show-PKI";
			break;
	}
	
	if(serviceURL == NULL){
		serviceURL = default_serviceURL;
	}

	printf("Connection Parameters:\n");
	printf("SP URL\t\t%s\n", serviceURL);
	printf("eID PIN\t\t%s\n", pin);
	printf("Cardreader Substring\t%s\n", cardReaderName.c_str());
	printf("Loop Count\t%i\n", loopCount);
	printf("Debug Level\t%i\n", USED_DEBUG_LEVEL);

	int n = 0;
	srand(time(0));
	time_t loopStart = time(0);
	while (n < loopCount) {
		time_t startTime = time(0);
		retValue = 0;
		++n;
		std::string strServiceURL(serviceURL);
		std::string strIdpAddress(strServiceURL);
		std::string strSessionIdentifier = static_cast<std::ostringstream*>( &(std::ostringstream() << rand()) )->str();
		std::string strPathSecurityParameters("");
		std::string strRef("");
		std::string response;

		printf("main -------------------- start of %d. eID dialog --------------------\n", n);

		retValue = performEID(strServiceURL, strIdpAddress, strSessionIdentifier, strPathSecurityParameters,
			strRef, cardReaderName, response);

		//retValue may also be NPACLIENT_ERROR_SUCCESS or ECARD_SUCCESS. These are both also 0.
		if(retValue != 0)
		{
			printf("%s:%d Error %08lX\n", __FILE__, __LINE__, retValue);
			serverErrorCounter++;
			printStatistics(retValue, (unsigned int) diffv.size(), serverErrorCounter, startTime);
			continue;
		}

		if(SAML_VERSION == testcase_arg_SAML_2 || SAML_VERSION == testcase_arg_No_SAML){
			printf(response.c_str());
		}

		if (response.find("<errorStatus>") != std::string::npos || response.find("ResultMajor>http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error<") != std::string::npos ) {
			// In case of faulty eID dialog the Service Provider shows via
			// SAML-IF a <errorStatus> element
			// SOAP-IF a <ResultMajor> element with content "http://www.bsi.bund.de/ecard/api/1.1/resultmajor#error"
			printf("%s:%d Error: eID dialog with an error result detected\n", __FILE__, __LINE__);
			serverErrorCounter++;
		}

		//FIXME: We have to push_back sometime, otherwise statistic output is faulty
		diffv.push_back(difftime(time(0), startTime));

		if(SAML_VERSION == testcase_arg_AutentApp){
			int found = response.find("<html");

			if (found != std::string::npos) {
				response = response.substr(found);
			} else {
				printf("%s:%d Error\n", __FILE__, __LINE__);
				printStatistics(retValue, (unsigned int) diffv.size(), serverErrorCounter, startTime);
				return -2;
			}
		}

		if(SAML_VERSION == testcase_arg_Selbstauskunft_Wuerzburg || SAML_VERSION == testcase_arg_AutentApp){
			std::stringstream stream;
			response = str_replace_ifnot("\"", "\\\"", "\\\"", response);
			stream <<"echo \""<<response.c_str()<<"\" | lynx -stdin -xhtml-parsing";
			if(system(stream.str().c_str()))
				printf(response.c_str());
		}

		printStatistics(retValue, (unsigned int) diffv.size(), serverErrorCounter, startTime);

		printf("Wait 2 seconds before next request....\n");
#if defined(WIN32)
        Sleep(2000);
#else
		usleep(2000);
// as long as a bug in libc++ prevents clang from including chrono correctly, use usleep.
// but chrono is the more portable way, as its c++11 standard
//        std::this_thread::sleep_for(std::chrono::milliseconds(2000));
#endif

	}

	std::vector<double>::iterator it;
	double diffSum = 0;

	for (it = diffv.begin(); it != diffv.end(); ++it) {
		diffSum += *it;
	}

	printf("Overall duration for all %d eID dialogs: %f seconds\n", loopCount, (difftime(time(0), loopStart)));
	printf("Average time for %d eID dialogs: %f seconds\n",
	   	diffv.size(), (diffv.size()==0 ? 0 : diffSum/diffv.size()));
	sprintf(buffer, "########## Error Code: %X - Read Count: %u - Server Errors: %u\n", retValue, (unsigned int) diffv.size(), serverErrorCounter);
	puts(buffer);
	if (retValue != 0x00000000) std::exit(EXIT_FAILURE);
	std::exit(EXIT_SUCCESS);
}
