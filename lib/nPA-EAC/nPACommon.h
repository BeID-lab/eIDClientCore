#if !defined(__NPACOMMON_INCLUDED__)
#define __NPACOMMON_INCLUDED__

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
 * Verifies the MAC of an secure messaging RAPDU.
 */
bool verifyResponse_AES( 
  const std::vector<unsigned char>& kMac, 
  const std::vector<unsigned char>& dataPart,
  unsigned long long &ssc);

/**
 */
std::vector<unsigned char> decryptResponse_AES(
  std::vector<unsigned char>& kEnc,
  const std::vector<unsigned char>& returnedData,
  unsigned long long ssc);

/**
 */
std::vector<unsigned char> calculateMAC(
  const std::vector<unsigned char>& toBeMaced,
  const std::vector<unsigned char>& kMac);

/**
 *
 */
std::string getCAR(
  const std::vector<unsigned char>& certificate);

/**
 *
 */
std::string getCHR(
  const std::vector<unsigned char>& certificate);

#endif
