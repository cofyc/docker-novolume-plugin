#!/bin/bash

docker run --entrypoint sh quay.io/prometheus/prometheus:v2.3.2 -c 'echo ok'
docker run -v /tmp:/prometheus --entrypoint sh quay.io/prometheus/prometheus:v2.3.2 -c 'echo ok'
