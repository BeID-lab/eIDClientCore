noinst_LTLIBRARIES = libeCardCore.la

noinst_HEADERS = CardCommand.h       eCardStatus.h    ICard.h           PCSCManager.h \
				 eCardCore.h         eCardTypes.h     IReader.h         PCSCReader.h \
				 eCardCore_intern.h  ICardDetector.h  IReaderManager.h

libeCardCore_la_SOURCES = eCardCore.cpp  ICard.cpp  PCSCManager.cpp  PCSCReader.cpp
libeCardCore_la_LIBADD = $(PCSC_LIBS)
libeCardCore_la_CPPFLAGS = $(PCSC_CFLAGS)
