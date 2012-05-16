// ---------------------------------------------------------------------------
// Copyright (c) 2007 Bundesruckerei GmbH
// All rights reserved.
//
// $Id: ICardDetector.h 299 2009-05-28 13:45:10Z rfiedler $
// ---------------------------------------------------------------------------

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
