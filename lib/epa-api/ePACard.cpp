// ---------------------------------------------------------------------------
// Copyright (c) 2008 Bundesdruckerei GmbH.
// All rights reserved.
//
// $Id: ePACard.cpp 1310 2011-09-20 11:41:06Z x_schrom $
// ---------------------------------------------------------------------------

#include "ePACard.h"
#include "ePACommon.h"
using namespace Bundesdruckerei::nPA;

/*
 *
 */
ePACard::ePACard(
  IReader* hSubSystem) : ICard(hSubSystem)
{
    if (!selectMF()
            || !readFile(SFID_EF_CARDACCESS, CAPDU::DATA_EXTENDED_MAX, m_ef_cardaccess))
        throw WrongHandle();
}

/*
 *
 */
string ePACard::getCardDescription (
  void )
{
  return "German nPA";
}

bool ePACard::selectMF(
        void)
{
  SelectFile select(SelectFile::P1_SELECT_FID, SelectFile::P2_NO_RESPONSE);

  RAPDU response = sendAPDU (select);

  return response.isOK();
}

/*
 *
 */
bool ePACard::selectEF(
  unsigned short FID)
{
  SelectFile select(SelectFile::P1_SELECT_EF, SelectFile::P2_NO_RESPONSE, FID);

  RAPDU response = sendAPDU (select);

  return response.isOK();
}

bool ePACard::selectEF(
  unsigned short FID,
  vector<unsigned char>& fcp)
{
  SelectFile select(SelectFile::P1_SELECT_EF, SelectFile::P2_FCP_TEMPLATE, FID);
  select.setNe(CAPDU::DATA_SHORT_MAX);

  RAPDU response = sendAPDU (select);

  fcp = response.getData();

  return response.isOK();
}

/*
 *
 */
bool ePACard::selectDF(
  unsigned short FID)
{
  SelectFile select(SelectFile::P1_SELECT_DF, SelectFile::P2_NO_RESPONSE, FID);

  RAPDU response = sendAPDU (select);

  return response.isOK();
}

/*
 *
 */
bool ePACard::readFile(
  size_t size,
  vector<unsigned char>& result)
{
    ReadBinary read;
    if (size < 0xC8)
        read.setNe(size);
    else
        read.setNe(0xC8);

    unsigned short offset = 0;
    bool retValue = false;

    while (offset < size)
    {
        read.setP1(offset >> 8);
        read.setP2(offset & 0xFF);

        if (size - offset > 0xC8)
            read.setNe(0xC8);
        else
            read.setNe(size - offset);

        RAPDU rapdu = sendAPDU (read);

        if (rapdu.isOK())
        {
            for (size_t i = 0; i < rapdu.getData().size(); i++)
                result.push_back(rapdu.getData()[i]);

            offset += (unsigned short) rapdu.getData().size();

        } else {
            return false;
        }
    }

    return true;
}

/*
 *
 */
bool ePACard::readFile(
  unsigned char sfid,
  size_t size,
  vector<unsigned char>& result)
{
    ReadBinary read = ReadBinary(0, sfid);
    read.setNe(size);

    RAPDU response = sendAPDU (read);

    result = response.getData();

    return response.isOK();
}

/*!
 *
 */
unsigned short ePACard::getFileSize(
  IN unsigned short FID)
{
  vector<BYTE> fci;
  selectEF(FID, fci);

  if (fci.size() == 0)
    return 0;

  if (fci[2] == 0x80)
  {
    //Very rarely used, but allowed
    if(fci[3] == 0x01)
      return fci[4];
    else if(fci[3] == 0x02)
      return (fci[4] << 8) + fci[5];
  }

  return 0;
}

CAPDU ePACard::applySM(const CAPDU& capdu)
{
    std::vector<unsigned char> do87_, do8E_, do97_, Le, sm_data;
    CAPDU sm_apdu = CAPDU(capdu.getCLA()|CAPDU::CLA_SM,
            capdu.getINS(), capdu.getP1(), capdu.getP2());

    if (!capdu.getData().empty()) {
        do87_ = buildDO87_AES(m_kEnc, capdu.getData(), m_ssc);
    }

    Le = capdu.encodedLe();
    if (!Le.empty()) {
        do97_.push_back(0x97);
        do97_.push_back(Le.size());
        do97_.insert(do97_.end(), Le.begin(), Le.end());
    }

    /* here, sm_apdu is still a case 1 APDU with header only. */
    do8E_ = buildDO8E_AES(m_kMac, sm_apdu.asBuffer(), do87_, do97_, m_ssc);

    sm_data = do87_;
    sm_data.insert(sm_data.end(), do97_.begin(), do97_.end());
    sm_data.insert(sm_data.end(), do8E_.begin(), do8E_.end());

    sm_apdu.setData(sm_data);
    if (sm_apdu.isExtended() || capdu.isExtended())
        sm_apdu.setNe(CAPDU::DATA_EXTENDED_MAX);
    else
        sm_apdu.setNe(CAPDU::DATA_SHORT_MAX);

    return sm_apdu;
}

RAPDU ePACard::removeSM(const RAPDU& sm_rapdu)
{
    std::vector<unsigned char> response;
    std::vector<unsigned char> sm_rdata;

    // Get returned data.
    sm_rdata = sm_rapdu.getData();

    if (!verifyResponse_AES(m_kMac, sm_rdata, m_ssc))
        throw WrongSM();

    response = decryptResponse_AES(m_kEnc, sm_rdata, m_ssc);

    /* TODO compare DO99 with SW */
    return RAPDU(response, sm_rapdu.getSW());
}

RAPDU ePACard::sendAPDU(const CAPDU& cmd)
{
    if (!m_kEnc.empty() && !m_kMac.empty()
            && !cmd.isSecure()) {
        CAPDU sm_apdu = applySM(cmd);

        RAPDU sm_rapdu = ICard::sendAPDU(sm_apdu);

        return removeSM(sm_rapdu);
    }

    return ICard::sendAPDU(cmd);
}

void ePACard::setKeys(vector<unsigned char>& kEnc, vector<unsigned char>& kMac)
{
    m_kEnc = kEnc;
    m_kMac = kMac;
    m_ssc = 0;
}

ICard* ePACardDetector::getCard(IReader* reader)
{
  try {
      return new ePACard(reader);
  } catch (...) {
  }

  return 0x00;
}

