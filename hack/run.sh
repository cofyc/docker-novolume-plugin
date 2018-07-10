#!/bin/bash

ROOT=$(unset CDPATH && cd $(dirname "${BASH_SOURCE[0]}")/.. && pwd)

cd $ROOT/hack
docker build -t docker-volume-plugin-debian-packger-packager .
docker run -v $ROOT:/src/docker-volume-plugin --rm -it docker-volume-plugin-debian-packger-packager --work-dir /src/docker-volume-plugin --binary-url-base file:///src/docker-volume-plugin $@
