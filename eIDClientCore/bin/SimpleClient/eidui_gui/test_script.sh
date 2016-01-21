#!/bin/sh



#g++ main.cpp MainFrame.cpp `../gtk-build/wx-config --cxxflags --libs` -o widgetTest

g++ -g -c -Wall -fPIC -std=gnu++11 MainFrame.cpp eidui_gui.cpp  -I../../../lib/eIDClientCore -I../../../lib `wxWidgets-3.0.2/gtk-build/wx-config --cxxflags --libs`   &&
g++ -shared -o libeidui_gui.so MainFrame.o eidui_gui.o 

#mv libTextFrame.so lib &&

#g++ -std=gnu++11 -L ./lib -L/lib64 main.cpp -leidui_gui  `../gtk-build/wx-config --cxxflags --libs`  -o widgetTest &&

#LD_LIBRARY_PATH=$PWD/lib ./widgetTest          
