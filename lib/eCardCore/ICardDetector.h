#if !defined(__ICARDDETECTOR_INCLUDED__)
#define __ICARDDETECTOR_INCLUDED__

class ICard;

class IReader;

class ICardDetector
{
  public:
    /*!
     *
     */
    virtual ~ICardDetector(
      void) {};

    /*!
     *
     */
    virtual ICard* getCard (
      IReader* ) = 0;
};


#endif
