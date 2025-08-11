FROM debian:stable-slim

RUN apt-get update && \
    apt-get install -y curl gnupg cmake make gcc g++ flex bison libpcap-dev libssl-dev python3 python3-pip git && \
    git clone --recursive https://github.com/zeek/zeek && \
    cd zeek && ./configure && make && make install

WORKDIR /zeek
CMD ["zeek", "-r", "sample.pcap"]
