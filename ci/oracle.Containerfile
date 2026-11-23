FROM docker.io/library/ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55
ARG BUILD_CPUS=0
ENV DEBIAN_FRONTEND=noninteractive
COPY ci/packages.txt ci/apt-snapshot ci/snapshot-update.sh ci/snapshot-install.sh /pins/
# TLS trust for the snapshot: its own ca-certificates package, kept in the tree
# by digest (sniff-oracle.toml names the source). Nothing is fetched before apt.
COPY ci/bootstrap/ca-certificates_20260816ubuntu0.24.04.2_all.deb /pins/bootstrap-ca.deb
RUN taskset -c "$BUILD_CPUS" sh -ec ' \
  for read in 1 2; do printf "%s  %s\n" f9fbacd417b515450b831032cc39d18059e9874e67525679a43c16071dabf9a0 /pins/bootstrap-ca.deb | sha256sum -c -; done; \
  dpkg-deb -x /pins/bootstrap-ca.deb /pins/bootstrap-ca; \
  mkdir -p /etc/ssl/certs; \
  find /pins/bootstrap-ca/usr/share/ca-certificates -name "*.crt" -type f -exec cat {} + > /etc/ssl/certs/ca-certificates.crt; \
  test -s /etc/ssl/certs/ca-certificates.crt; \
  sh /pins/snapshot-update.sh "$(cat /pins/apt-snapshot)"; \
  sed "/^#/d; /^$/d" /pins/packages.txt | xargs sh /pins/snapshot-install.sh "$(cat /pins/apt-snapshot)"; \
  dpkg-query -W | tr "\t" "=" | sort > /opt/oracle-packages.txt; \
  for tool in gdb llvm-dwarfdump-18 readelf gcc clang gdbserver; do command -v "$tool"; "$tool" --version | head -n 1; sha256sum "$(readlink -f "$(command -v "$tool")")"; done > /opt/oracle-binaries.txt; \
  rm -rf /var/lib/apt/lists/*'
# QEMU for the remote rows: the release tarball fetched after apt (its trust is the snapshot's), held to the digest
# sniff-oracle.toml names, read twice, and built with the configure line it names; only --prefix and --python are the
# image's own.
RUN taskset -c "$BUILD_CPUS" sh -ec ' \
  curl -fsSL --proto =https -o /tmp/qemu.tar.xz https://download.qemu.org/qemu-11.1.2.tar.xz; \
  for read in 1 2; do printf "%s  %s\n" 731b5681e4bb18be313231579b8efd0296c5b015fa36dc533874b639ba838016 /tmp/qemu.tar.xz | sha256sum -c -; done; \
  mkdir -p /tmp/qemu; tar -xJf /tmp/qemu.tar.xz -C /tmp/qemu --strip-components=1; \
  cd /tmp/qemu; ./configure --prefix=/opt/qemu-11.1.2 --python=/usr/bin/python3 --target-list=x86_64-softmmu --enable-slirp --disable-docs --disable-werror --disable-download; \
  ninja -C build -j"$(nproc)"; ninja -C build install; \
  cd /; rm -rf /tmp/qemu /tmp/qemu.tar.xz; \
  ln -s /opt/qemu-11.1.2/bin/qemu-system-x86_64 /usr/local/bin/qemu-system-x86_64; \
  for tool in qemu-system-x86_64; do command -v "$tool"; "$tool" --version | head -n 1; sha256sum "$(readlink -f "$(command -v "$tool")")"; done >> /opt/oracle-binaries.txt'
WORKDIR /work
