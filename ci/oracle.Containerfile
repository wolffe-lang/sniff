FROM docker.io/library/ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55
ARG BUILD_CPUS=0
ENV DEBIAN_FRONTEND=noninteractive
COPY ci/packages.txt ci/apt-snapshot ci/snapshot-update.sh ci/snapshot-install.sh /pins/
ADD --checksum=sha256:f9fbacd417b515450b831032cc39d18059e9874e67525679a43c16071dabf9a0 https://snapshot.ubuntu.com/ubuntu/20261106T000000Z/pool/main/c/ca-certificates/ca-certificates_20260816ubuntu0.24.04.2_all.deb /pins/bootstrap-ca.deb
RUN taskset -c "$BUILD_CPUS" sh -ec ' \
  for read in 1 2; do printf "%s  %s\n" f9fbacd417b515450b831032cc39d18059e9874e67525679a43c16071dabf9a0 /pins/bootstrap-ca.deb | sha256sum -c -; done; \
  dpkg-deb -x /pins/bootstrap-ca.deb /pins/bootstrap-ca; \
  mkdir -p /etc/ssl/certs; \
  find /pins/bootstrap-ca/usr/share/ca-certificates -name "*.crt" -type f -exec cat {} + > /etc/ssl/certs/ca-certificates.crt; \
  test -s /etc/ssl/certs/ca-certificates.crt; \
  sh /pins/snapshot-update.sh "$(cat /pins/apt-snapshot)"; \
  sed "/^#/d; /^$/d" /pins/packages.txt | xargs sh /pins/snapshot-install.sh "$(cat /pins/apt-snapshot)"; \
  dpkg-query -W | tr "\t" "=" | sort > /opt/oracle-packages.txt; \
  for tool in gdb llvm-dwarfdump-18 readelf gcc clang; do command -v "$tool"; "$tool" --version | head -n 1; sha256sum "$(readlink -f "$(command -v "$tool")")"; done > /opt/oracle-binaries.txt; \
  rm -rf /var/lib/apt/lists/*'
WORKDIR /work
