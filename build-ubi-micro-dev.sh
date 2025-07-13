#!/bin/sh

set -x

set -euo pipefail

dnf --installroot /mnt/rootfs clean all

groupadd -R /mnt/rootfs/ ubi-micro-dev -g 1001

useradd -R /mnt/rootfs/ \
        -u 1001 -g ubi-micro-dev -G ubi-micro-dev \
        -m -d /home/ubi-micro-dev -s /sbin/nologin \
        -c "ubi-micro-dev user" ubi-micro-dev

rm -rf /mnt/rootfs/var/cache/* /mnt/rootfs/var/log/dnf* /mnt/rootfs/var/log/yum.*

pkgs=( coreutils-single alsa-lib copy-jdk-configs lua cups-libs gawk \
       python3 python3-libs python3-pip-wheel python3-setuptools-wheel \
       platform-python-setuptools \
       p11-kit ncurses-base sqlite-libs \
       nspr nss nss-softokn nss-softokn-freebl nss-sysinit nss-util )

remove=()

dnf install --installroot /mnt/rootfs \
    redhat-release \
    --releasever $UBI_VERSION --setopt install_weak_deps=false --nodocs --nogpgcheck -y
rpm --root=/mnt/rootfs --import /mnt/rootfs/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release

for p in "${pkgs[@]}"; do
  rpm --root /mnt/rootfs -q "$p" &>/dev/null && remove+=( "$p" ) ;
done

if [ ${#remove[@]} -gt 0 ]; then
  echo "==> Erasing: ${remove[*]}" ;
  rpm --root /mnt/rootfs -e --nodeps --noscripts --allmatches "${remove[@]}" ;
else
  echo "==> Nothing to erase" ;
fi
