#!/bin/bash
echo "Hello world!!!"
#ls -al /tmp
#ls -al /tmp/data
/usr/bin/unzip -qq /tmp/data/data.zip -d /app/data
cp /tmp/data/options.txt /app/data/options.txt
#ls -al /app/data
#ls -al /app/bin
/app/bin/server -v
/app/bin/server 0.0.0.0 80 4 /app/data
