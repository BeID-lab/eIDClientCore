lib_LTLIBRARIES = libeidui_gui.la

noinst_HEADERS = MainFrame.h

libeidui_gui_la_SOURCES = MainFrame.cpp eidui_gui.cpp

libeidui_gui_la_LDFLAGS = `wx-config --libs std,richtext`

libeidui_gui_la_CPPFLAGS = -I$(top_srcdir)/lib/eIDClientCore -I$(top_srcdir)/lib `wx-config --cxxflags`