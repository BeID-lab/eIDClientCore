/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#if !defined(__IREADER_INCLUDED__)
#define __IREADER_INCLUDED__

#include "CardCommand.h"
#include "ICardDetector.h"
#include "Transceiver.h"

#include <debug.h>

#include <exception>
#include <string>
#include <vector>

class ReaderException : public std::exception
{
		virtual const char *what() const throw() {
			return "Unspecific ReaderException";
		}
};
class NoCard : public ReaderException
{
		const char *what() const throw() {
			return "No Card available";
		}
};
class WrongHandle : public ReaderException
{
		const char *what() const throw() {
			return "Wrong card handle";
		}
};
class TransactionFailed : public ReaderException
{
		const char *what() const throw() {
			return "Transaction failed";
		}
};
class PACEException : public ReaderException
{
private:
	const std::string m_errMsg;

public:
	PACEException(const char * errorMessage) :
	m_errMsg(errorMessage)
	{}
	~PACEException() throw()
	{}
	PACEException() {
		PACEException("PACE failed");
	}
		const char *what() const throw() {
			return m_errMsg.c_str();
		}
};


class PaceInput
{
	public:
		enum PinID { undef, mrz, can, pin, puk };

	protected:
		enum PinID m_pin_id;
		std::vector<unsigned char> m_pin;
		std::vector<unsigned char> m_chat;
		std::vector<unsigned char> m_certificate_description;

	public:
		const std::vector<unsigned char>& get_chat(void) const {
			return m_chat;
		};
		void set_chat(const std::vector<unsigned char>& chat) {
			m_chat = chat;
		};
		enum PinID get_pin_id(void) const {
			return m_pin_id;
		};
		void set_pin_id(enum PinID pin_id) {
			m_pin_id = pin_id;
		};
		const std::vector<unsigned char>& get_pin(void) const {
			return m_pin;
		};
		void set_pin(const std::vector<unsigned char>& pin) {
			m_pin = pin;
		};
		const std::vector<unsigned char>& get_certificate_description(void) const {
			return m_certificate_description;
		};
		void set_certificate_description(const std::vector<unsigned char>& certificate_description) {
			m_certificate_description = certificate_description;
		};
};

class PaceOutput
{
	protected:
		unsigned int m_result;
		unsigned short m_status_mse_set_at;
		std::vector<unsigned char> m_ef_cardaccess;
		std::vector<unsigned char> m_car_curr;
		std::vector<unsigned char> m_car_prev;
		std::vector<unsigned char> m_id_icc;

	public:

		PaceOutput() : m_result(0xFFFFFFFF) {}

		unsigned int get_result(void) const {
			return m_result;
		};
		void set_result(unsigned int result) {
			m_result = result;
		};
		unsigned short get_status_mse_set_at(void) const {
			return m_status_mse_set_at;
		};
		void set_status_mse_set_at(unsigned short status_mse_set_at) {
			m_status_mse_set_at = status_mse_set_at;
		};
		const std::vector<unsigned char>& get_ef_cardaccess(void) const {
			return m_ef_cardaccess;
		};
		void set_ef_cardaccess(const std::vector<unsigned char>& ef_cardaccess) {
			m_ef_cardaccess = ef_cardaccess;
		};
		const std::vector<unsigned char>& get_car_curr(void) const {
			return m_car_curr;
		};
		void set_car_curr(const std::vector<unsigned char>& car_curr) {
			m_car_curr = car_curr;
		};
		const std::vector<unsigned char>& get_car_prev(void) const {
			return m_car_prev;
		};
		void set_car_prev(const std::vector<unsigned char>& car_prev) {
			m_car_prev = car_prev;
		};
		const std::vector<unsigned char>& get_id_icc(void) const {
			return m_id_icc;
		};
		void set_id_icc(const std::vector<unsigned char>& id_icc) {
			m_id_icc = id_icc;
		};
};


/*!
 * @class IReader
 *
 * @brief
 */

class IReader : public Transceiver<std::vector<unsigned char>, std::vector<unsigned char> >
{
	protected:
		std::string m_readerName;
		std::vector<ICardDetector *>& m_cardDetectors;

	private:
		IReader(
			void);

		IReader &operator=(
			const IReader &);

	public:
		/*!
		 * @brief
		 */
		IReader(
			const std::string &readerName,
			std::vector<ICardDetector *>& detector) : m_readerName(readerName),
			m_cardDetectors(detector) {};

		/*!
		 *
		 */
		virtual ~IReader(
			void) {};

		/*!
		 * @brief
		 */
		std::string getReaderName(
			void) const {
			return m_readerName;
		}

		// -------------------------------------------------------------------------
		// Pure virtuals
		// -------------------------------------------------------------------------

		virtual bool open(
			void) = 0;

		virtual void close(
			void) = 0;

		/*!
		 * @brief Use this function to get a pointer to a ICard object.
		 */
		virtual ICard *getCard(
			void)
			{
				ICard *card = 0x0;

				for (std::vector<ICardDetector *>::iterator it = m_cardDetectors.begin();
						it != m_cardDetectors.end(); it++) {
					card = ((ICardDetector *) * it)->getCard(this);

					if (card != 0x0)
						break;
				}

				return card;
			};

		/*!
		 *
		 */
		virtual std::vector<unsigned char> getATRForPresentCard(void) = 0;

		virtual bool supportsPACE(void) = 0;

		virtual PaceOutput establishPACEChannel(const PaceInput &) = 0;
}; // class IReader

class IndividualReader : public IReader, public IndividualTransceiver<std::vector<unsigned char>, std::vector<unsigned char> >
{
	public:
		IndividualReader(const std::string &readerName,
			   	std::vector<ICardDetector *>& detector) : IReader(readerName, detector) {};

        virtual std::vector<std::vector<unsigned char> > transceive(const std::vector<std::vector<unsigned char> > &cmds) {
			return IndividualTransceiver<std::vector <unsigned char>, std::vector<unsigned char> >::transceive(cmds);
		}
};

class BatchReader : public IReader, public BatchTransceiver<std::vector<unsigned char>, std::vector<unsigned char> >
{
	public:
		BatchReader(const std::string &readerName,
			   	std::vector<ICardDetector *>& detector) : IReader(readerName, detector) {};

		virtual std::vector<unsigned char> transceive(const std::vector<unsigned char>& cmd) {
			return BatchTransceiver<std::vector <unsigned char>, std::vector<unsigned char> >::transceive(cmd);
		}
};

#endif // #if !defined(__IREADER_INCLUDED__)
