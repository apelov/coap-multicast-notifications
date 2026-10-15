# docker build -t coap-observe-multicast .   builds the patched libcoap and runs the unit tests.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      build-essential clang cmake pkg-config git ca-certificates patch \
      libssl-dev libcbor-dev python3 python3-cryptography \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN make deps && make test && python3 tools/test_gosc_verify.py
CMD ["make", "test"]
