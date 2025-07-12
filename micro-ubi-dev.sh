#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# 1. Parse arguments
###############################################################################
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

###############################################################################
# 2. Prepare working dirs
###############################################################################
dir="/tmp/micro-ubi-dev"
rootfs="$dir/rootfs"
rm -rf "$dir"
mkdir -p "$rootfs"
cd "$dir"

###############################################################################
# 3. Write keep & disallow lists
###############################################################################
printf '%s\n' "${packages[@]}" > keep
cat >> keep <<'EOF'
bash
EOF

# keep used to include coreutils-single

cat > disallow <<'EOF'
alsa-lib
copy-jdk-configs
lua
cups-libs
chkconfig
info
gawk
platform-python
platform-python-setuptools
python3
python3-libs
python3-pip-wheel
python3-setuptools-wheel
p11-kit
ncurses-base
ncurses-libs
sqlite-libs
nspr nss nss-softokn nss-softokn-freebl nss-sysinit nss-util
EOF

sort -u keep -o keep

###############################################################################
# 4. Enable requested modules on the host (for dependency resolution)
###############################################################################
for m in "${modules[@]}"; do
  dnf -y module enable "$m"
done

###############################################################################
# 5. Install into chroot
###############################################################################
echo "==> Installing packages into chroot" >&2
set -x
dnf install -y findutils diffutils   # tools the script itself needs

# Enable modules inside the chroot before installing packages there
for m in "${modules[@]}"; do
#  dnf -y --installroot "$rootfs" --releasever 9 module enable "$m"
    dnf -y --installroot "$rootfs" module enable "$m"
done

#<keep xargs dnf install -y --installroot "$rootfs" --releasever 9 \
<keep xargs dnf install -y --installroot "$rootfs" \    
      --setopt install_weak_deps=false --nodocs

dnf --installroot "$rootfs" clean all
rm -rf "$rootfs"/var/cache/{bpf,dnf,ldconfig} "$rootfs"/var/log/dnf* \
       "$rootfs"/var/log/yum.*

{ set +x; } 2>/dev/null

###############################################################################
# 6. Trim unneeded packages (unchanged logic)
###############################################################################
echo "==> Building dependency tree" >&2
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

echo "==> $(wc -l < remove) packages to erase:" >&2
cat remove
echo "==> $(wc -l < keep) packages to keep:" >&2
cat keep
echo >&2

echo "==> Erasing packages" >&2
set -x
<remove xargs rpm -r "$rootfs" --erase --nodeps --allmatches
rpm -r "$rootfs" -qa
<remove xargs rpm -r "$rootfs" --erase --nodeps --noscripts --allmatches
echo "================"
rpm -r "$rootfs" -qa
echo "================"
rpm -r "$rootfs"  -e nss --nodeps
echo "================"
rpm -r "$rootfs" -qa
{ set +x; } 2>/dev/null

echo "==> Packages erased ok!" >&2
