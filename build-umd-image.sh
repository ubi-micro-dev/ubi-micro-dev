#!/usr/bin/env bash
set -euo pipefail

# Install build-time tools
dnf install -y diffutils

rootfs=/mnt/rootfs

modules=()          # list of module streams to enable, e.g.  nodejs:18
packages=()         # list of packages to install / keep

while (( $# )); do
  case "$1" in
    --module)
      # expect the stream in the next arg
      shift || { echo "ERROR: --module needs an argument"; exit 1; }
      modules+=( "$1" )
      ;;
    --module=*)
      modules+=( "${1#--module=}" )
      ;;
    *)
      packages+=( "$1" )
      ;;
  esac
  shift
done

# Prepare base list of packages to keep, which include those passed on
# the command line, as well as a few fixed ones (at least `bash`).
printf '%s\n' "${packages[@]}" > keep
cat >> keep <<'EOF'
bash
EOF

# Prepare a list of package we will never allow in the container image.
cat > disallow <<'EOF'
alsa-lib
chkconfig
copy-jdk-configs
coreutils-single
cups-libs
gawk
info
lua
ncurses-base
ncurses-libs
nspr
nss
nss-softokn
nss-softokn-freebl
nss-sysinit
nss-util
p11-kit
platform-python
platform-python-setuptools
python3
python3-libs
python3-pip-wheel
python3-setuptools-wheel
sqlite-libs
EOF

# Sort the keep file
sort -u keep -o keep

# Enable all modules identified on the cli on both the host, for
# dependency resolution, and the target root.
for m in "${modules[@]}"; do
  dnf -y module enable "$m"
  dnf -y --installroot "$rootfs" module enable "$m"
done

rpm --root="$rootfs" --import "$rootfs"/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release

# Install all of the `keep` packages, without weak dependencies or
# documentation, and then clean up a little.
cp -a /etc/yum.repos.d "$rootfs"/etc
ls -l "$rootfs"
<keep xargs dnf install -y --installroot "$rootfs" \
      --setopt install_weak_deps=false --nodocs
dnf --installroot "$rootfs" clean all
rm -rf "$rootfs"/var/cache/{bpf,dnf,ldconfig} \
       "$rootfs"/var/log/dnf* \
       "$rootfs"/var/log/yum.*

# Starting from `keep` figure out what the real package
# dependencies, excluding dependencies pulled in by the `disallow`
# list.
touch old
while ! cmp -s keep old; do
  <keep xargs rpm -r "$rootfs" -q --requires | sort -Vu | cut -d' ' -f1 \
    | grep -v '^rpmlib(' \
    | xargs -d $'\n' rpm -r "$rootfs" -q --whatprovides \
    | grep -v '^no package provides' \
    | sed -r 's/^(.*)-.*-.*$/\1/' \
    | grep -vxF -f disallow \
    > new || true
  mv keep old
  cat old new > keep
  sort -u keep -o keep
done

rpm -r "$rootfs" -qa | sed -r 's/^(.*)-.*-.*$/\1/' | sort -u > all
grep -vxF -f keep all > remove

echo "==> $(wc -l < remove) packages to erase:"
cat remove
echo "==> $(wc -l < keep) packages to keep:"
cat keep
echo

# Delete the `remove` packages
<remove xargs rpm -v -r "$rootfs" --erase --nodeps --allmatches

groupadd -R "$rootfs"/ ubi-micro-dev -g 1001

useradd -R "$rootfs"/ \
        -u 1001 -g ubi-micro-dev -G ubi-micro-dev \
        -m -d /home/ubi-micro-dev -s /sbin/nologin \
        -c "ubi-micro-dev user" ubi-micro-dev
