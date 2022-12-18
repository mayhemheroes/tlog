FROM --platform=linux/amd64 ubuntu:20.04 as builder

RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential automake libtool pkg-config libjson-c-dev libsystemd-dev libcurl3-dev clang

COPY . /repo
WORKDIR /repo
RUN autoreconf -if
RUN ./configure --prefix=/install
RUN make -j8
RUN make install
ENV LD_LIBRARY_PATH=/repo/lib/tlog/.libs
RUN clang++ /repo/mayhem/fuzz_tlog_utf8_buf_is_valid.cpp -fsanitize=fuzzer,address /install/lib/libtlog.a -o /fuzz

FROM ubuntu:20.04 as package
RUN apt-get update
RUN DEBIAN_FRONTEND=noninteractive apt-get install -y libjson-c-dev libcurl3-dev
COPY --from=builder /install /install
COPY --from=builder /fuzz /fuzz_tlog_utf8_buf_is_valid
