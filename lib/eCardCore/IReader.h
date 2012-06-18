// ---------------------------------------------------------------------------
// Copyright (c) 2007 Bundesruckerei GmbH
// All rights reserved.
//
// $Id: IReader.h 627 2010-01-28 09:19:47Z rfiedler $
// ---------------------------------------------------------------------------

/*!
 * @file IReader.h
 */

#if !defined(__IREADER_INCLUDED__)
#define __IREADER_INCLUDED__

#include "CardCommand.h"
#include "ICardDetector.h"

#include <string>
using namespace std;

class ICard;

class PaceInput
{
    public:
        enum PinID { undef, mrz, can, pin, puk }; 

	protected:
		enum PinID m_pin_id;
		vector<BYTE> m_pin;
		vector<BYTE> m_chat;
		vector<BYTE> m_certificate_description;

    public:
		PaceInput(enum PinID pin_id, vector<BYTE> pin,
                const vector<BYTE> chat,
                const vector<BYTE> certificate_description)
            : m_pin_id(pin_id), m_pin(pin), m_chat(chat), m_certificate_description(certificate_description)
        { };
        const vector<BYTE> get_chat(void)
        { return m_chat; };
        void set_chat(const vector<BYTE> chat)
        { m_chat = chat; };
        enum PinID get_pin_id(void)
        { return m_pin_id; };
        void set_pin_id(enum PinID pin_id)
        { m_pin_id = pin_id; };
        const vector<BYTE> get_pin(void)
        { return m_pin; };
        void set_pin(const vector<BYTE> pin)
        { m_pin = pin; };
        const vector<BYTE> get_certificate_description(void)
        { return m_certificate_description; };
        void set_certificate_description(const vector<BYTE> certificate_description)
        { m_certificate_description = certificate_description; };
};

class PaceOutput
{
	protected:
        unsigned int m_result;
		unsigned short m_status_mse_set_at;
		vector<BYTE> m_ef_cardaccess;
		vector<BYTE> m_car_curr;
		vector<BYTE> m_car_prev;
		vector<BYTE> m_id_icc;

    public:
        unsigned int get_result(void)
        { return m_result; };
        void set_result(unsigned int result)
        { m_result = result; };
        unsigned short get_status_mse_set_at(void)
        { return m_status_mse_set_at; };
        void set_status_mse_set_at(unsigned short status_mse_set_at)
        { m_status_mse_set_at = status_mse_set_at; };
        const vector<BYTE> get_ef_cardaccess(void)
        { return m_ef_cardaccess; };
        void set_ef_cardaccess(const vector<BYTE> ef_cardaccess)
        { m_ef_cardaccess = ef_cardaccess; };
        const vector<BYTE> get_car_curr(void)
        { return m_car_curr; };
        void set_car_curr(const vector<BYTE> car_curr)
        { m_car_curr = car_curr; };
        const vector<BYTE> get_car_prev(void)
        { return m_car_prev; };
        void set_car_prev(const vector<BYTE> car_prev)
        { m_car_prev = car_prev; };
        const vector<BYTE> get_id_icc(void)
        { return m_id_icc; };
        void set_id_icc(const vector<BYTE> id_icc)
        { m_id_icc = id_icc; };
};


/*!
 * @class IReader
 *
 * @brief
 */

class IReader
{
  protected:
    string m_readerName;
    vector<ICardDetector*>& m_cardDetectors;

  private:
    IReader(
      void);

    IReader& operator=(
      const IReader&);

  public:
    /*!
     * @brief
     */
    IReader (
      const string& readerName,
      vector<ICardDetector*>& detector ) : m_readerName ( readerName ),
      m_cardDetectors ( detector ) {};

    /*!
     *
     */
    virtual ~IReader(
      void) {};

    /*!
     * @brief
     */
    string getReaderName (
      void )
    {
      return m_readerName;
    }

    // -------------------------------------------------------------------------
    // Pure virtuals
    // -------------------------------------------------------------------------

    /*!
     * @brief
     */
    virtual bool open (
      void ) = 0;

    /*!
     * @brief
     */
    virtual void close (
      void ) = 0;

    /*!
     * @brief
     */
    virtual ICard* getCard (
      void ) = 0;

    /*!
     * @brief
     */
    virtual bool sendAPDU (
      UINT64 cardID,
      const CardCommand& cmd,
      CardResult& res,
      const string& logMsg = "") = 0;

    /*!
     *
     */
    virtual vector<BYTE> getATRForPresentCard(
      void) = 0;

    virtual bool supportsPACE(
      void) = 0;

	virtual PaceOutput establishPACEChannel(
			PaceInput) = 0;
}; // class IReader

#endif // #if !defined(__IREADER_INCLUDED__)
