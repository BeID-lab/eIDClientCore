#if !defined(__EPACOMMON_INCLUDED__)
#define __EPACOMMON_INCLUDED__

#include <vector>

#include <AlgorithmIdentifier.h>

#if defined(WIN32)
// CRYPTOPP includes
#include <cryptopp-5.6.0/sha.h>
#include <cryptopp-5.6.0/aes.h>
#include <cryptopp-5.6.0/modes.h>
#include <cryptopp-5.6.0/osrng.h>
#include <cryptopp-5.6.0/integer.h>
#include <cryptopp-5.6.0/ecp.h> // Elliptic curve over GF(p)
#include <cryptopp-5.6.0/cmac.h>
#else
// CRYPTOPP includes
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/integer.h>
#include <cryptopp/ecp.h> // Elliptic curve over GF(p)
#include <cryptopp/cmac.h>
#endif

USING_NAMESPACE(CryptoPP)

/**
 */
std::vector<unsigned char> buildDO87_AES(
  IN const std::vector<unsigned char>& kEnc,
  IN const std::vector<unsigned char>& data,
  IN unsigned long long ssc);

/**
 */
std::vector<unsigned char> buildDO8E_AES(
  IN const std::vector<unsigned char>& kMac,
  IN const std::vector<unsigned char>& data,
  IN const std::vector<unsigned char>& do87,
  IN const std::vector<unsigned char>& do97,
  IN OUT unsigned long long &ssc);

/**
 * Verifies the MAC of an secure messaging RAPDU.
 */
bool verifyResponse_AES( 
  IN const std::vector<unsigned char>& kMac, 
  IN const std::vector<unsigned char>& dataPart,
  IN OUT unsigned long long &ssc);

/**
 */
std::vector<unsigned char> decryptResponse_AES(
  IN std::vector<unsigned char>& kEnc,
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
  IN const std::vector<unsigned char>& certificate);

/**
 *
 */
std::string getCHR(
  IN const std::vector<unsigned char>& certificate);

#endif // #if !defined(__EPACOMMON_INCLUDED__)
