#!/bin/bash -xv
docker run -it --rm -p 80:80 -v /root/epoll/data:/tmp/data:ro $1
