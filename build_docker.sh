#!/bin/bash -xv
mkdir -p bin
mkdir -p logs
make veryrelease
cp bin/server docker/server
pushd .
cd docker && docker build -t "higload-irqlevel$1" .
popd
