#!/usr/bin/env bash
#
# ─────────────────────────────────────────────────────────────────────────────
#  WHY THIS SCRIPT EXISTS
#  ----------------------

#  Red Hat’s Universal Base Images (UBI) provide signed,
#  redistributable RPMs, but the official UBI Micro image comes
#  without DNF/YUM or any convenient way to add or remove packages.
#  This script builds alternatives to the UBI Micro image by starting
#  with a minimal set of packages and layering on language runtimes,
#  or other package specified on the command line.  It specifically
#  **excludes** `coreutils-single`, which is part of Red Hat's UBI
#  Micro image.
#
#  This script builds such an image FROM "scratch":
#
#    • It creates a fresh root filesystem under `/mnt/rootfs`, populated
#      exclusively by the RPMs you name on the command line (plus their true
#      dependencies) and nothing more.
#    • It guarantees that certain heavyweight or security-sensitive libraries
#      (listed in `disallow`, e.g. `nss`, `python3`, `lua`) can never sneak in,
#      even indirectly via dependencies.
#    • It lets you enable individual UBI module streams (e.g. `nodejs:18`)
#      during the build so that you get the right runtime ABI without pulling
#      the entire development tool-chain into the final image.
#    • It finishes by stripping docs, weak deps, cache files, and then creates
#      a non-root user (UID/GID 1001) so the resulting container runs safely
#      by default.
#
#  The outcome is a tiny, auditable, reproducible rootfs comprising only
#  the RPMs you asked for.
#
#  WHAT THE SCRIPT DOES
#  --------------------
#  1.  Parses CLI arguments:
#        – `--module[=<stream>]`  ➜ enable a DNF module stream on host & rootfs
#        – `<package>`            ➜ add an RPM to the “keep” list
#  2.  Seeds `keep` with those packages plus mandatory `bash`; seeds `disallow`
#      with RPM names that must never appear.
#  3.  Enables every requested module stream both on the build host (for
#      dependency solving) and inside the target root.
#  4.  Installs the current `keep` set into `/mnt/rootfs`, skipping weak deps
#      and docs, then cleans all caches.
#  5.  Iteratively calculates the *minimal* dependency closure of `keep`,
#      subtracts anything on the `disallow` list, updates `keep`, and repeats
#      until no new deps appear.
#  6.  Computes `remove = all_installed – keep` and erases every package in
#      that list with `--nodeps --allmatches`.
#  7.  Adds group `ubi-micro-dev` (GID 1001) and user `ubi-micro-dev`
#      (UID 1001, no-login shell) inside the rootfs.
#
#  Invoke this script in a `RUN` layer of your Containerfile/ Dockerfile; copy
#  or mount `/mnt/rootfs` into a final scratch layer; and you have a bespoke
#  micro-UBI runtime built entirely from signed Red Hat RPMs—but containing
#  only what you truly need.
# ─────────────────────────────────────────────────────────────────────────────

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
