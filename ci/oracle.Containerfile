FROM docker.io/library/ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55
ARG BUILD_CPUS=0
ENV DEBIAN_FRONTEND=noninteractive
COPY ci/packages.txt /pins/packages.txt
RUN taskset -c "$BUILD_CPUS" sh -ec 'apt-get update; sed "/^#/d; /^$/d" /pins/packages.txt | xargs apt-get install -y --no-install-recommends; dpkg-query -W | tr "\t" "=" | sort > /opt/oracle-packages.txt; for tool in gdb llvm-dwarfdump-18 readelf gcc clang; do command -v "$tool"; "$tool" --version | head -n 1; sha256sum "$(readlink -f "$(command -v "$tool")")"; done > /opt/oracle-binaries.txt; rm -rf /var/lib/apt/lists/*'
WORKDIR /work
