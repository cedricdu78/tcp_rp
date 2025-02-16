FROM ubuntu:jammy

RUN apt update && apt install -y python3 python3-pip build-essential wget curl build-essential autoconf libtool pkg-config python3-yaml

#RUN pip3 install yaml
