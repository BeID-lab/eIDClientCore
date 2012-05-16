#if !defined(__EPACOMMON_INCLUDED__)
#define __EPACOMMON_INCLUDED__

#include <vector>

#include <AlgorithmIdentifier.h>

//#if !defined(__APPLE__)
// CRYPTOPP includes
#include <cryptopp-5.6.0/sha.h>
#include <cryptopp-5.6.0/aes.h>
#include <cryptopp-5.6.0/modes.h>
#include <cryptopp-5.6.0/osrng.h>
#include <cryptopp-5.6.0/integer.h>
#include <cryptopp-5.6.0/ecp.h> // Elliptic curve over GF(p)
#include <cryptopp-5.6.0/cmac.h>
//#else
// CRYPTOPP includes
//#include <cryptopp/sha.h>
//#include <cryptopp/aes.h>
//#include <cryptopp/modes.h>
//#include <cryptopp/osrng.h>
//#include <cryptopp/integer.h>
//#include <cryptopp/ecp.h> // Elliptic curve over GF(p)
//#include <cryptopp/cmac.h>
//#endif

USING_NAMESPACE(CryptoPP)

/**
 */
void hexdump(
  IN const char* caption, 
  IN void* pAddressIn, 
  IN long lSize);

/**
 */
std::vector<unsigned char> buildDO87_AES(
  IN const BYTE_INPUT_DATA& kEnc,
  IN const std::vector<unsigned char>& data,
  IN unsigned long long ssc);

/**
 */
std::vector<unsigned char> buildDO8E_AES(
  IN const BYTE_INPUT_DATA& kMac,
  IN const std::vector<unsigned char>& data,	// header
  IN OUT unsigned long long &ssc);

/**
 */
std::vector<unsigned char> buildDO8E_AES(
  IN const BYTE_INPUT_DATA& kMac,
  IN const std::vector<unsigned char>& data,
  IN const std::vector<unsigned char>& do87,
  IN OUT unsigned long long &ssc);

/**
 */
std::vector<unsigned char> buildDO8E_AES(
  IN const BYTE_INPUT_DATA& kMac,
  IN const std::vector<unsigned char>& data,
  IN const std::vector<unsigned char>& do87,
  IN const std::vector<unsigned char>& do97,
  IN OUT unsigned long long &ssc);

/**
 * Verifies the MAC of an secure messaging RAPDU.
 */
bool verifyResponse_AES( 
  IN const BYTE_INPUT_DATA& kMac, 
  IN const std::vector<unsigned char>& dataPart,
  IN OUT unsigned long long &ssc);

/**
 */
std::vector<unsigned char> decryptResponse_AES(
  IN BYTE_INPUT_DATA& kEnc,
  IN const std::vector<unsigned char>& returnedData,
  IN unsigned long long ssc);

/**
 */
std::vector<unsigned char> generate_PrK_IFD_DHx(
  IN const AlgorithmIdentifier* PACEDomainParameterInfo_);

/**
 */
ECP::Point calculate_PuK_IFD_DHx(
  IN const std::vector<unsigned char>& PrK_IFD_DHx,
  IN const AlgorithmIdentifier* PACEDomainParameterInfo);

/**
 */
std::vector<unsigned char> calculateMAC(
  IN const std::vector<unsigned char>& toBeMaced,
  IN const std::vector<unsigned char>& kMac);

/**
 *
 */
std::string getCAR(
  IN const BYTE_INPUT_DATA& certificate);

/**
 *
 */
std::string getCHR(
  IN const BYTE_INPUT_DATA& certificate);

#endif // #if !defined(__EPACOMMON_INCLUDED__)