/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#if !defined(__ICARD_INCLUDED__)
#define __ICARD_INCLUDED__

#include "CardCommand.h"
#include "IReaderManager.h"
#include "eCardTypes.h"

#include <string>

/* ISO 7816 smart card */
class ICard: public Transceiver<CAPDU, RAPDU>
{
	private:
		ICard(
			const ICard &);

		ICard &operator=(
			const ICard &);

		std::vector<std::vector<unsigned char> > get_buffers(
				std::vector<CAPDU> apdus);
		std::vector<RAPDU> get_rapdus(
				std::vector<std::vector<unsigned char> > buffers);

	protected:
		IReader *m_subSystem;
		void debug_CAPDU(const char *label, const CAPDU &cmd) const;
		void debug_RAPDU(const char *label, const RAPDU &cmd) const;

	public:
		static const unsigned short FID_MF = 0x3F00;

		ICard(IReader *subSystem);
		virtual ~ICard(void);

		bool selectMF(void);
		bool selectDF(unsigned short FID);
		bool selectEF(unsigned short FID);
		bool selectEF(unsigned short FID, vector<unsigned char>& fcp);

		bool readFile(vector<unsigned char>& result);
		bool readFile(unsigned char sfid, size_t chunk_size, vector<unsigned char>& result);

		virtual RAPDU transceive(const CAPDU& cmd);
		virtual std::vector<RAPDU> transceive(const std::vector<CAPDU>& cmds);

		const IReader *getSubSystem(void) const;

		// -------------------------------------------------------------------------
		// Pure virtuals
		// -------------------------------------------------------------------------

		virtual string getCardDescription(void) = 0;

}; // class ICard


#endif
