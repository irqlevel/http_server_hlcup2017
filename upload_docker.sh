#!/bin/bash -xv
docker tag $1 stor.highloadcup.ru/travels/first_octopus
docker push stor.highloadcup.ru/travels/first_octopus
