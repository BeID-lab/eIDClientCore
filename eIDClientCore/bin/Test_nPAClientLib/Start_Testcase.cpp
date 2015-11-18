#if defined(WIN32)
#   include <windows.h>
#   include <tchar.h>
#   include <wininet.h>
#   include <wincrypt.h>
#else
# include <unistd.h>
# include <pthread.h>
#endif

#include <vector>
#include <sstream>

#include <string>
#include <fstream>
#include <streambuf>

#include <getopt.h>
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

	std::string usageString = "Usage: ";
	usageString.append(argv[0]);
	usageString.append(" [OPTIONS]\n"
	"\tOptions:\n"
	"\t\t-s : Service Provider URL\n"
	"\t\t-t : SAML/Testcase selection. This option is mandatory. Testcases are:\n"
	"\t\t\t NO_SAML :\t\t\t1\n"
	"\t\t\t SAML_1 :\t\t\t2\n"
	"\t\t\t SAML_2 :\t\t\t3\n"
	"\t\t\t Selbstauskunft Würzburg :\t4\n"
	"\t\t\t AutentApp :\t\t\t5\n"
	"\t\t-c : Part of Card Reader Name (This parameter may consist of multiple strings)\n"
	"\t\t-p : PIN\n"
	"\t\t-l : Loopcount\n"
	"\t\t-a : Cancel after PAOS connection establishment\n"
	"\t\t-v : Debug level (verbosity) as a number. Debug levels are:\n"
	"\t\t\t APDU :\t\t1\n"
	"\t\t\t CRYPTO :\t2\n"
	"\t\t\t SSL :\t\t4\n"
	"\t\t\t PAOS :\t\t8\n"
	"\t\t\t CARD :\t\t16\n"
	"\t\t\t CLIENT :\t32\n"
	"\t\t\t To choose multiple Debug Levels at the same time, just sum "
	"the corresponding numbers and take the result as parameter.\n");

	USED_DEBUG_LEVEL = 0;
	CANCEL_AFTER_PAOS_CONNECTION_ESTABLISHMENT = 0;
	int c;
	bool appendToCardReaderName = false;
	bool testCaseSet = false;
	while ((c = getopt (argc, argv, "-s:t:p:l:av:c:")) != -1){
		if(c != 1){
			appendToCardReaderName = false;
		}
		switch (c){
			case 's':
				serviceURL = optarg;
				break;
			case 't':
				{
					int givenSamlVersion = atoi(optarg);
					if(givenSamlVersion >= 1 && givenSamlVersion <= 5){
						SAML_VERSION = givenSamlVersion;
						testCaseSet = true;
					} else {
						fprintf(stderr, "Value for testcase must be one from 1 to 5.\n");
						return 1;
					}
					break;
				}
			case 'p':
				pin = optarg;
				break;
			case 'l':
				loopCount = atoi(optarg);
				break;
			case 'v':
				USED_DEBUG_LEVEL = atoi(optarg);
				break;
			case 'a':
				CANCEL_AFTER_PAOS_CONNECTION_ESTABLISHMENT = 1;
				break;
			case 'c':
				cardReaderName.append(optarg);
				appendToCardReaderName = true;
				break;
			//Get all the strings of the Card Reader Name
			case 1:
				if(appendToCardReaderName == true){
					cardReaderName.push_back(' ');
					cardReaderName.append(optarg);
					break;
				} else {
					printf(usageString.c_str());
					printf("Unknown non-option argument: %s\n", optarg);
					return 1;
				}
			case '?':
				printf(usageString.c_str());
				if (isprint (optopt))
				  fprintf (stderr, "Unknown option `-%c'.\n", optopt);
				else
				  fprintf (stderr,
						   "Unknown option character `\\x%x'.\n",
						   optopt);
				return 1;
			default:
				printf(usageString.c_str());
				return 1;
		}
	}
	
	if(!testCaseSet){
		fprintf(stderr, "Error: Please set the SAML version/testcase.\n");
		return 1;
	}

	const char *default_serviceURL;
	switch(SAML_VERSION){
		case SAML_SELBSTAUSKUNFT_WUERZBURG:
			default_serviceURL = "https://www.buergerserviceportal.de/bayern/wuerzburg/bspx_selbstauskunft";
			break;
		case SAML_AUTENTAPP:
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

		if(SAML_VERSION == SAML_2 || SAML_VERSION == NO_SAML){
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

		if(SAML_VERSION == SAML_AUTENTAPP){
			int found = response.find("<html");

			if (found != std::string::npos) {
				response = response.substr(found);
			} else {
				printf("%s:%d Error\n", __FILE__, __LINE__);
				printStatistics(retValue, (unsigned int) diffv.size(), serverErrorCounter, startTime);
				return -2;
			}
		}

		if(SAML_VERSION == SAML_SELBSTAUSKUNFT_WUERZBURG || SAML_VERSION == SAML_AUTENTAPP){
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
