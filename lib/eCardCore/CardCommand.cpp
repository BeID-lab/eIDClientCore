#include "CardCommand.h"
#include <sstream>

BufferTooLong::BufferTooLong(size_t overrun_by)
: m_overrun_by(overrun_by)
{ }

const char* BufferTooLong::what() const throw()
{
    ostringstream r;
    r << "Overrun by " << m_overrun_by << " Bytes";
    return r.str().c_str();
}

BufferTooSmall::BufferTooSmall(size_t underrun_by)
: m_underrun_by(underrun_by)
{ }
const char* BufferTooSmall::what() const throw()
{
    ostringstream r;
    r << "Underrun by " << m_underrun_by << " Bytes";
    return r.str().c_str();
}

const char* InconsistentData::what() const throw()
{
    return "Inconsistend data";
}

const char* WrongSM::what() const throw()
{
    return "Secure Messaging error";
}

vector<unsigned char> CAPDU::encodeLength(size_t length, bool extendedOnThreeBytes) const
{
    vector<unsigned char> encoded;

    if (length) {
        if (length > DATA_EXTENDED_MAX)
            throw BufferTooLong(length - DATA_EXTENDED_MAX);

        if (isExtended()) {
            if (extendedOnThreeBytes)
                encoded.push_back(0x00);
            if (length == DATA_EXTENDED_MAX) {
                encoded.push_back(0x00);
                encoded.push_back(0x00);
            } else {
                encoded.push_back((length>>8) & 0xFF);
                encoded.push_back( length     & 0xFF);
            }
        } else {
            if (length == DATA_SHORT_MAX) {
                encoded.push_back(0x00);
            } else {
                encoded.push_back( length       & 0xFF);
            }
        }
    } else {
        /* length == 0, no length field should be present */
    }

    return encoded;
}
size_t CAPDU::decodeLength(const unsigned char * const len, bool isExtended, bool extendedOnThreeBytes) const
{
    size_t decoded;
    //printf("%s%d\n", __FILE__, __LINE__);

    if (isExtended) {
        size_t offset = 0;
        if (extendedOnThreeBytes) {
            if (len[offset] != 0x00)
                throw InconsistentData();

            offset++;
        }

        if (len[offset] == 0x00 && len[offset+1] == 0x00)
            decoded = DATA_EXTENDED_MAX;
        else
            decoded = (len[offset]<<8) + len[offset+1];
    } else {
        if (*len == 0x00)
            decoded = DATA_SHORT_MAX;
        else
            decoded = *len;
    }

    return decoded;
}

CAPDU::CAPDU(unsigned char cla, unsigned char ins, unsigned char p1,
        unsigned char p2, vector<unsigned char> data)
: m_CLA(cla), m_INS(ins), m_P1(p1), m_P2(p2), m_data(data),
    m_Ne(0)
{ }

CAPDU::CAPDU(unsigned char cla, unsigned char ins, unsigned char p1,
        unsigned char p2, vector<unsigned char> data, size_t ne)
: m_CLA(cla), m_INS(ins), m_P1(p1), m_P2(p2), m_data(data),
    m_Ne(ne)
{ }

CAPDU::CAPDU(unsigned char cla, unsigned char ins, unsigned char p1,
        unsigned char p2)
: m_CLA(cla), m_INS(ins), m_P1(p1), m_P2(p2), m_Ne(0)
{ }

CAPDU::CAPDU(const vector<unsigned char> capdu)
{
    size_t Nc, lc_len;
    bool isExtended;

    m_CLA = capdu[0];
    m_INS = capdu[1];
    m_P1 = capdu[2];
    m_P2 = capdu[3];

    if (capdu.size() != LENGTH_APDU_HEAD) {
        if (capdu[LENGTH_APDU_HEAD] == 0x00 && capdu.size()
                >= LENGTH_APDU_HEAD + 3) {
            /* Extended Length */
            isExtended = true;
			lc_len = 3;
        } else {
            /* Short Length */
            isExtended = false;
			lc_len = 1;
        }

        if (capdu.size() == LENGTH_APDU_HEAD+lc_len) {
            /* Case 2 */
            m_Ne = decodeLength(&capdu[LENGTH_APDU_HEAD], isExtended, true);
        } else {
            Nc = decodeLength(&capdu[LENGTH_APDU_HEAD], isExtended, true);

            m_data.assign(&capdu[LENGTH_APDU_HEAD + lc_len],
                    &capdu[LENGTH_APDU_HEAD + lc_len + Nc]);

            if (capdu.size() > LENGTH_APDU_HEAD + lc_len +
                    m_data.size()) {
                /* Case 4 */
                m_Ne = decodeLength(&capdu[LENGTH_APDU_HEAD + lc_len +
                        m_data.size()], isExtended, false);
            } else {
                /* Case 3 */
                m_Ne = 0;
            }
        }
    } else {
        /* Case 1 */
        m_Ne = 0;
    }
}

void CAPDU::appendData(unsigned char b)
{
    if (m_data.size() >= DATA_EXTENDED_MAX)
        throw (BufferTooLong(1));

    m_data.push_back(b);
}

void CAPDU::appendData(const vector<unsigned char> data)
{
    if (m_data.size()+data.size() > DATA_EXTENDED_MAX)
        throw (BufferTooLong(m_data.size()+data.size() - DATA_EXTENDED_MAX));

    m_data.insert(m_data.end(), data.begin(), data.end());
}

bool CAPDU::isExtended(void) const
{
    return m_data.size() > DATA_SHORT_MAX
        || m_Ne > DATA_SHORT_MAX;
}
bool CAPDU::isShort(void) const
{
    return !isExtended();
}

bool CAPDU::isSecure(void) const
{
    return (m_CLA & CAPDU::CLA_SM) == CAPDU::CLA_SM;
}

void CAPDU::setData(const vector<unsigned char> data)
{
    m_data = data;
}

void CAPDU::setCLA(unsigned char cla)
{
    m_CLA = cla;
}

void CAPDU::setP1(unsigned char p1)
{
    m_P1 = p1;
}

void CAPDU::setP2(unsigned char p2)
{
    m_P2 = p2;
}

void CAPDU::setNe(size_t Ne)
{
    m_Ne = Ne;
}

unsigned char CAPDU::getCLA(void) const
{
    return m_CLA;
}

unsigned char CAPDU::getINS(void) const
{
    return m_INS;
}

unsigned char CAPDU::getP1(void) const
{
    return m_P1;
}

unsigned char CAPDU::getP2(void) const
{
    return m_P2;
}

size_t CAPDU::getNe(void) const
{
    return m_Ne;
}

const vector<unsigned char> CAPDU::getData(void) const
{
    return m_data;
}

vector<unsigned char> CAPDU::encodedLc(void) const
{
    return encodeLength(m_data.size(), true);
}

vector<unsigned char> CAPDU::encodedLe(void) const
{
    return encodeLength(m_Ne, m_data.empty());
}

vector<unsigned char> CAPDU::asBuffer(void) const
{
    vector<unsigned char> capdu, Lc, Le;

    capdu.push_back(m_CLA);
    capdu.push_back(m_INS);
    capdu.push_back(m_P1);
    capdu.push_back(m_P2);

    Lc = encodedLc();
    capdu.insert(capdu.end(), Lc.begin(), Lc.end());

    capdu.insert(capdu.end(), m_data.begin(), m_data.end());

    Le = encodedLe();
    capdu.insert(capdu.end(), Le.begin(), Le.end());

    return capdu;
}

SelectFile::SelectFile(unsigned char p1, unsigned char p2)
: CAPDU(0x00, INS_SELECT, p1, p2)
{
}

SelectFile::SelectFile(unsigned char p1, unsigned char p2, unsigned short fid)
: CAPDU(0x00, INS_SELECT, p1, p2)
{
    vector<unsigned char> data;
    data.push_back((fid>>8) & 0xff);
    data.push_back( fid     & 0xff);
    setData(data);
}

DataUnitAPDU::DataUnitAPDU(unsigned char ins, size_t offset, unsigned char sfid)
: CAPDU(0x00, ins, sfid|P1_SFID, offset)
{
    /* check if the upper two bits are set to 0 */
    if (sfid & 0xC0)
        throw InconsistentData();

    /* check if offset fits p2 */
    if (offset > 0xff)
        /* TODO don't throw an error. Instead use an offset data object
         * in the command data */
        throw InconsistentData();
}

DataUnitAPDU::DataUnitAPDU(unsigned char ins, size_t offset)
: CAPDU(0x00, ins, (offset>>8) & 0xff, offset & 0xff)
{
    /* check if the upper bit is set to 0 */
    if ((offset>>8) & 0x80)
        /* TODO don't throw an error. Instead use an offset data object
         * in the command data */
        throw InconsistentData();
}

DataUnitAPDU::DataUnitAPDU(unsigned char ins)
: CAPDU(0x00, ins, 0x00, 0x00)
{ }

ReadBinary::ReadBinary(size_t offset, unsigned char sfid)
: DataUnitAPDU(INS_READ_BINARY, offset, sfid)
{ }

ReadBinary::ReadBinary(size_t offset)
: DataUnitAPDU(INS_READ_BINARY, offset)
{ }

ReadBinary::ReadBinary(void)
: DataUnitAPDU(INS_READ_BINARY)
{ }

SecurityCAPDU::SecurityCAPDU(unsigned char ins, unsigned char p1, unsigned char p2)
: CAPDU(0x00, ins, p1, p2)
{ }

MSE::MSE(unsigned char p1, unsigned char p2)
: SecurityCAPDU(INS_MSE, p1, p2)
{ }

PSO::PSO(unsigned char p1, unsigned char p2)
: CAPDU(0x00, INS_PSO, p1, p2)
{ }

GeneralAuthenticate::GeneralAuthenticate(unsigned char p1, unsigned char p2)
: SecurityCAPDU(INS_GENERAL_AUTHENTICATE, p1, p2)
{ }

GetChallenge::GetChallenge(unsigned char p1)
: SecurityCAPDU(INS_GET_CHALLENGE, p1, 0x00)
{ }

ExternalAuthenticate::ExternalAuthenticate(unsigned char p1, unsigned char p2)
: SecurityCAPDU(INS_EXTERNAL_AUTHENTICATE, p1, p2)
{ }

RAPDU::RAPDU(const vector<unsigned char> rapdu)
{
    if (rapdu.size() < 2) {
        throw BufferTooSmall(2 - rapdu.size());
    }

    m_data = rapdu;

    m_sw2 = m_data.back();
    m_data.pop_back();

    m_sw1 = m_data.back();
    m_data.pop_back();
}

RAPDU::RAPDU(const vector<unsigned char> rdata, unsigned short sw)
: m_data(rdata), m_sw1((sw>>8) & 0xff), m_sw2(sw & 0xff)
{ }

RAPDU::RAPDU(const vector<unsigned char> rdata, unsigned char sw1, unsigned char sw2)
: m_data(rdata), m_sw1(sw1), m_sw2(sw2)
{ }

RAPDU::RAPDU(unsigned char sw1, unsigned char sw2)
: m_sw1(sw1), m_sw2(sw2)
{ }

RAPDU::RAPDU(unsigned short sw)
: m_sw1((sw>>8) & 0xff), m_sw2(sw & 0xff)
{ }

unsigned char RAPDU::getSW1(void) const
{
    return m_sw1;
}

unsigned char RAPDU::getSW2(void) const
{
    return m_sw2;
}

unsigned short RAPDU::getSW(void) const
{
    return (m_sw1 << 8) | m_sw2;
}

const vector<unsigned char> RAPDU::getData(void) const
{
    return m_data;
}

vector<unsigned char> RAPDU::asBuffer(void) const
{
    vector <unsigned char> rapdu = m_data;
    rapdu.push_back(getSW1());
    rapdu.push_back(getSW2());

    return rapdu;
}

bool RAPDU::isOK(void) const
{
    if (getSW() == RAPDU::ISO_SW_NORMAL
            || getSW1() == 0x61
            || getSW1() == 0x62
            || getSW1() == 0x63)
        return true;
    else
        return false;
}
