/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#if !defined(__EIDOID_INCLUDED__)
#define __EIDOID_INCLUDED__

#define bsi_de                              "0.4.0.127.0.7"

#define id_STANDARDIZED_DP					bsi_de ".1.2"

#define id_PACE                             bsi_de ".2.2.4"
#define id_PACE_DH                          id_PACE ".1"
#define id_PACE_DH_3DES_CBC_CBC             id_PACE_DH ".1"
#define id_PACE_DH_AES_CBC_CMAC_128         id_PACE_DH ".2"
#define id_PACE_DH_AES_CBC_CMAC_192         id_PACE_DH ".3"
#define id_PACE_DH_AES_CBC_CMAC_256         id_PACE_DH ".4"
#define id_PACE_ECDH                        id_PACE ".2"
#define id_PACE_ECDH_3DES_CBC_CBC           id_PACE_ECDH ".1"
#define id_PACE_ECDH_AES_CBC_CMAC_128       id_PACE_ECDH ".2"
#define id_PACE_ECDH_AES_CBC_CMAC_192       id_PACE_ECDH ".3"
#define id_PACE_ECDH_AES_CBC_CMAC_256       id_PACE_ECDH ".4"

#define id_TA                               bsi_de ".2.2.2"
#define id_TA_ECDSA                         id_TA ".2"
#define id_TA_ECDSA_SHA_1                   id_TA_ECDSA ".1"
#define id_TA_ECDSA_SHA_224                 id_TA_ECDSA ".2"
#define id_TA_ECDSA_SHA_256                 id_TA_ECDSA ".3"

#define id_CA                               bsi_de ".2.2.3"
#define id_CA_ECDH                          id_CA ".2"
#define id_CA_ECDH_3DES_CBC_CBC             id_CA_ECDH ".1"
#define id_CA_ECDH_AES_CBC_CMAC_128         id_CA_ECDH ".2"
#define id_CA_ECDH_AES_CBC_CMAC_192         id_CA_ECDH ".3"
#define id_CA_ECDH_AES_CBC_CMAC_256         id_CA_ECDH ".4"
#define id_CA_DH                            id_CA ".1"
#define id_CA_DH_3DES_CBC_CBC               id_CA_DH ".1"
#define id_CA_DH_AES_CBC_CMAC_128           id_CA_DH ".2"
#define id_CA_DH_AES_CBC_CMAC_192           id_CA_DH ".3"
#define id_CA_DH_AES_CBC_CMAC_256           id_CA_DH ".4"

#define id_PK                               bsi_de ".2.2.1"
#define id_PK_ECDH                          id_PK ".2"
#define id_PK_DH                            id_PK ".1"

#define id_RI_ECDH                          bsi_de ".2.2.5.2"

#define id_CI                               bsi_de ".2.2.6"

#define id_AUXILIARY_DATA                   bsi_de ".3.1.4"
#define id_AUXILIARY_DATA_DATE_OF_BIRTH     id_AUXILIARY_DATA ".1"
#define id_AUXILIARY_DATA_DATE_OF_EXPIARY   id_AUXILIARY_DATA ".2"
#define id_AUXILIARY_DATA_COMMUNITY_ID      id_AUXILIARY_DATA ".3"

#define id_ROLES                            bsi_de ".3.1.2"
#define id_IS                               id_ROLES ".1"
#define id_AT                               id_ROLES ".2"
#define id_ST                               id_ROLES ".3"

#define id_ECDSA_WITH_SHA224                "1.2.840.10045.4.3.1"
#define id_ECDSA_WITH_SHA256                "1.2.840.10045.4.3.2"

#endif
