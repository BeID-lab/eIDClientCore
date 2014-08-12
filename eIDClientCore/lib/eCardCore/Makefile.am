noinst_LTLIBRARIES = libeCardCore.la

noinst_HEADERS = CardCommand.h eCardStatus.h ICard.h PCSCManager.h eCardTypes.h IReader.h PCSCReader.h ICardDetector.h IReaderManager.h ExternalManager.h ExternalReader.h pace_reader.h Transceiver.h eIdClientCardReader.h

libeCardCore_la_SOURCES   = ICard.cpp  CardCommand.cpp IReader.cpp
libeCardCore_la_CPPFLAGS  = -I$(top_srcdir)/lib
libeCardCore_la_LIBADD    =

if DISABLE_EXTERNAL
else
libeCardCore_la_SOURCES  += ExternalReader.cpp
endif

if DISABLE_PCSC
else
libeCardCore_la_SOURCES  += PCSCManager.cpp  PCSCReader.cpp pace_reader.cpp
libeCardCore_la_CPPFLAGS += $(PCSC_CFLAGS)
libeCardCore_la_LIBADD   += $(PCSC_LIBS)
endif
