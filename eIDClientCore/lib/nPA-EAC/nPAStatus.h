/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#if !defined(__NPASTATUS_INCLUDED__)
#define __NPASTATUS_INCLUDED__

#define EAC_INFO    0x21000000
#define EAC_WARNING 0x22000000
#define EAC_ERROR   0x23000000

#define EAC_SUCCESS								0x00000000
#define EAC_INVALID_EPA                         EAC_ERROR + 0x001

// PACE related errors
#define EAC_EFCARDACCESS_PARSER_ERROR           EAC_ERROR + 0x002
#define EAC_PACE_STEP_B_FAILED                  EAC_ERROR + 0x003
#define EAC_PACE_STEP_C_FAILED                  EAC_ERROR + 0x004
#define EAC_PACE_STEP_C_DECRYPTION_FAILED       EAC_ERROR + 0x005
#define EAC_PACE_STEP_D_FAILED                  EAC_ERROR + 0x006
#define EAC_PACE_STEP_E_FAILED                  EAC_ERROR + 0x007
#define EAC_PACE_STEP_F_FAILED                  EAC_ERROR + 0x008
#define EAC_PACE_STEP_F_VERIFICATION_FAILED     EAC_ERROR + 0x009

// Terminal Authentication related errors
#define EAC_TA_STEP_A_FAILED                    EAC_ERROR + 0x00A
#define EAC_TA_STEP_A_VERIFY_FAILED             EAC_ERROR + 0x00B
#define EAC_TA_STEP_B_FAILED                    EAC_ERROR + 0x00C
#define EAC_TA_STEP_B_INVALID_CERTIFCATE_FORMAT EAC_ERROR + 0x00D
#define EAC_TA_STEP_B_VERIFY_FAILED             EAC_ERROR + 0x00E
#define EAC_TA_STEP_C_FAILED                    EAC_ERROR + 0x00F
#define EAC_TA_STEP_C_VERIFY_FAILED             EAC_ERROR + 0x010
#define EAC_TA_STEP_D_FAILED                    EAC_ERROR + 0x011
#define EAC_TA_STEP_D_VERIFY_FAILED             EAC_ERROR + 0x012
#define EAC_TA_STEP_D_INVALID_CERTIFCATE_FORMAT EAC_ERROR + 0x013
#define EAC_TA_STEP_E_FAILED                    EAC_ERROR + 0x014
#define EAC_TA_STEP_E_VERIFY_FAILED             EAC_ERROR + 0x015
#define EAC_TA_STEP_F_FAILED                    EAC_ERROR + 0x016
#define EAC_TA_STEP_F_VERIFY_FAILED             EAC_ERROR + 0x017
#define EAC_TA_STEP_G_FAILED                    EAC_ERROR + 0x018
#define EAC_TA_STEP_G_VERIFY_FAILED             EAC_ERROR + 0x019

// Chip Authentication related errors
#define EAC_CA_STEP_B_FAILED                    EAC_ERROR + 0x01A
#define EAC_CA_STEP_B_VERIFY_FAILED             EAC_ERROR + 0x01B
#define EAC_EFCARDSECURYITY_PARSER_ERROR        EAC_ERROR + 0x01C
#define EAC_VERIFY_RESPONSE_FAILED              EAC_ERROR + 0x01D

// PIN Management related errors
#define EAC_CHANGE_PIN_FAILED                   EAC_ERROR +  0x020
#define EAC_PIN_DEACTIVATED						EAC_ERROR +  0x021
#define EAC_CAN_REQUIRED						EAC_ERROR +  0x022
#define EAC_PIN_FIRST_FAIL						EAC_ERROR +  0x023
#define EAC_PIN_SECOND_FAIL						EAC_ERROR +  0x024
#endif
