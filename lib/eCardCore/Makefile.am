noinst_LTLIBRARIES = libeCardCore.la

noinst_HEADERS = CardCommand.h eCardStatus.h ICard.h PCSCManager.h eCardTypes.h IReader.h PCSCReader.h ICardDetector.h IReaderManager.h

libeCardCore_la_SOURCES = ICard.cpp  PCSCManager.cpp  PCSCReader.cpp  CardCommand.cpp
libeCardCore_la_LIBADD = $(PCSC_LIBS)
libeCardCore_la_CPPFLAGS = $(PCSC_CFLAGS) \
						   -I$(top_srcdir)/lib
