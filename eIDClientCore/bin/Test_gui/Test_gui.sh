#!/bin/bash -x

cd $(dirname $0)
LD_LIBRARY_PATH=../../../lib:../../../lib64 ./Test_gui 
