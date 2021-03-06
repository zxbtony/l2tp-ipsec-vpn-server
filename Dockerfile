FROM debian:jessie
MAINTAINER Tony Zhang <tony.zxb@outlook.com>

ENV REFRESHED_AT 2017-05-20

ENV SWAN_VER 3.20
ENV DEBIAN_FRONTEND noninteractive

RUN apt-get -yqq update \
    && apt-get -yqq --no-install-recommends install \
         wget dnsutils openssl ca-certificates kmod \
         iproute gawk grep sed net-tools iptables \
         bsdmainutils libunbound2 libcurl3-nss \
         libnss3-tools libevent-dev libcap-ng0 xl2tpd \
         libnss3-dev libnspr4-dev pkg-config libpam0g-dev \
         libcap-ng-dev libcap-ng-utils libselinux1-dev \
         libcurl4-nss-dev libsystemd-dev flex bison gcc make \
         libunbound-dev xmlto \
         jq \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/src
RUN wget -t 3 -T 30 -nv -O "libreswan-${SWAN_VER}.tar.gz" "https://download.libreswan.org/libreswan-${SWAN_VER}.tar.gz" \
    && tar xzf "libreswan-${SWAN_VER}.tar.gz" \
    && rm -f "libreswan-${SWAN_VER}.tar.gz" \
    && cd "libreswan-${SWAN_VER}" \
    && echo "WERROR_CFLAGS =" > Makefile.inc.local \
    && make -s programs \
    && make -s install \
    && rm -rf "/opt/src/libreswan-${SWAN_VER}"

COPY ./run.sh /run.sh
RUN chmod 755 /run.sh

EXPOSE 500/udp 4500/udp

VOLUME ["/lib/modules"]

CMD ["/run.sh"]
