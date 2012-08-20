#if !defined(__ICARD_INCLUDED__)
#define __ICARD_INCLUDED__

#include "CardCommand.h"
#include "IReaderManager.h"
#include "eCardTypes.h"

#include <string>

/*!
 * @class ICard
 */
class ICard
{
  private:
    ICard(
      const ICard&);

    ICard& operator=(
      const ICard&);

  protected:
    IReader *m_subSystem;

  public:
    static const unsigned short FID_MF = 0x3F00;

    /*!
     *
     */
    ICard (
      IReader* subSystem );

    /*!
     *
     */
    virtual ~ICard (
      void );

	bool selectEF(
			unsigned short FID);

	bool selectEF(
			unsigned short FID,
			vector<unsigned char>& fcp);

	bool selectDF(
			unsigned short FID);

    bool selectMF(
            void);

    /*!
     *
     */
    virtual RAPDU sendAPDU(
      const CAPDU& cmd);

    const IReader *getSubSystem(void) const;

    // -------------------------------------------------------------------------
    // Pure virtuals
    // -------------------------------------------------------------------------

    /*!
     *
     */
    virtual string getCardDescription (
      void ) = 0;

}; // class ICard


#endif
