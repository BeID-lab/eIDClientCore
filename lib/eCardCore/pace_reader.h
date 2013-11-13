/*
 * Copyright (C) 2013 Bundesdruckerei GmbH
 */

#if !defined(__PACE_READER_INCLUDED__)
#define __PACE_READER_INCLUDED__

#include "eCardCore/IReader.h"

std::vector<unsigned char> establishPACEChannel_getBuffer(const PaceInput &input);
std::vector<unsigned char> getReadersPACECapabilities_getBuffer(void);

PaceOutput establishPACEChannel_parseBuffer(unsigned char *output, size_t output_length);

bool getReadersPACECapabilities_supportsPACE(unsigned char *output, size_t output_length);
bool getReadersPACECapabilities_supportsEID(unsigned char *output, size_t output_length);
bool getReadersPACECapabilities_supportsSignature(unsigned char *output, size_t output_length);
bool getReadersPACECapabilities_supportsDestroy(unsigned char *output, size_t output_length);


#endif // #if !defined(__PACE_READER_INCLUDED__)
