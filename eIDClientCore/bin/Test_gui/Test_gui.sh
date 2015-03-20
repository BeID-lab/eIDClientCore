#!/bin/bash -x

cd $(dirname $0)
#LD_LIBRARY_PATH=../../../lib64 ./Test_gui #not working
export LD_LIBRARY_PATH=../../../lib64 
./Test_gui
