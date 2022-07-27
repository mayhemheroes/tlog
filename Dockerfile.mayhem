FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential automake libtool pkg-config libjson-c-dev libsystemd-dev libcurl3-dev

COPY . /repo
WORKDIR /repo
RUN autoreconf -if
RUN ./configure --prefix=/install
RUN make -j8
RUN make install
ENV LD_LIBRARY_PATH=/repo/lib/tlog/.libs
RUN ldconfig

FROM ubuntu:20.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libjson-c-dev libcurl3-dev
COPY --from=builder /install /install
