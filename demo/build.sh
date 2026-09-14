#!/bin/bash
# Builds demo/initramfs.cpio.gz — a minimal busybox initramfs with real
# networking (virtio-net + httpd), used for interactive/manual play with
# hyperbug (see docs/dev-guide.md's "Playing with it interactively"
# section). Not a project deliverable — this whole demo/ directory is
# gitignored, same as the throwaway images `tests/boot.rs` builds on the
# fly for automated tests. Re-run this script any time to rebuild it
# (e.g. after `pacman -Syu` changes the running kernel's module paths).
#
# Needs: busybox, zstd, cpio, gzip, find — and a kernel whose real
# release string (not its /boot/vmlinuz-<name> filename — see
# tests/boot.rs's own `kernel_release()` for why those differ) has
# virtio_net/net_failover/failover as loadable modules. If your kernel
# builds virtio-net in instead (CONFIG_VIRTIO_NET=y), delete the
# insmod lines from the init script below — eth0 will just appear.

set -euo pipefail
cd "$(dirname "$0")"

KERNEL="${1:-$(ls /boot/vmlinuz-* | head -1)}"
RELEASE="$(file "$KERNEL" | grep -oP 'version \K[^ ]+')"
echo "building demo initramfs for kernel: $KERNEL (release $RELEASE)"

rm -rf initramfs initramfs.cpio.gz
mkdir -p initramfs/{bin,proc,sys,dev,mnt,lib/modules,www}

BUSYBOX=/usr/bin/busybox
[ -x "$BUSYBOX" ] || BUSYBOX=/bin/busybox
cp "$BUSYBOX" initramfs/bin/busybox
for applet in sh mount echo cat dd sleep poweroff mkdir insmod ip httpd wget ping ifconfig; do
    ln -sf busybox "initramfs/bin/$applet"
done

MODDIR="/lib/modules/$RELEASE"
zstd -d -f -q "$MODDIR/kernel/net/core/failover.ko.zst" -o initramfs/lib/modules/failover.ko
zstd -d -f -q "$MODDIR/kernel/drivers/net/net_failover.ko.zst" -o initramfs/lib/modules/net_failover.ko
zstd -d -f -q "$MODDIR/kernel/drivers/net/virtio_net.ko.zst" -o initramfs/lib/modules/virtio_net.ko

cat > initramfs/www/index.html << 'HTML'
<html><body><h1>Hello from a hyperbug guest</h1></body></html>
HTML

cat > initramfs/init << 'INIT'
#!/bin/busybox sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
echo ""
echo "=== hyperbug demo guest ==="
insmod /lib/modules/failover.ko 2>/dev/null
insmod /lib/modules/net_failover.ko 2>/dev/null
insmod /lib/modules/virtio_net.ko 2>/dev/null
if ip link show eth0 >/dev/null 2>&1; then
    ip link set lo up
    ip link set eth0 up
    ip addr add 10.250.0.2/24 dev eth0
    httpd -p 0.0.0.0:8080 -h /www
    echo "network: eth0 up @ 10.250.0.2, httpd on :8080"
else
    echo "network: no eth0 (booted without --net)"
fi
echo "type 'poweroff -f' to shut down cleanly"
echo "==========================="
exec /bin/sh
INIT
chmod +x initramfs/init

( cd initramfs && find . | cpio -o -H newc 2>/dev/null | gzip -9 > ../initramfs.cpio.gz )
echo "built: $(pwd)/initramfs.cpio.gz"
