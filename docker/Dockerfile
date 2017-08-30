FROM centos:centos7.3.1611

RUN yum -y install unzip
RUN mkdir -p /app/bin
RUN mkdir -p /app/data
COPY server /app/bin/server
COPY boot.sh /app/bin/boot.sh
EXPOSE 80
ENTRYPOINT /bin/bash /app/bin/boot.sh
