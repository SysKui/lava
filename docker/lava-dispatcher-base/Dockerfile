FROM debian:bookworm-slim

LABEL maintainer="Rémi Duraffort <remi.duraffort@linaro.org>"

ENV DEBIAN_FRONTEND noninteractive

# 设置代理
ENV http_proxy "http://10.161.28.28:7890"
ENV HTTP_PROXY "http://10.161.28.28:7890"
ENV https_proxy "http://10.161.28.28:7890"
ENV HTTPS_PROXY "http://10.161.28.28:7890"



RUN echo 'deb http://deb.debian.org/debian bookworm-backports main' > /etc/apt/sources.list.d/backports.list && \
    mkdir -p /usr/share/man/man1 /usr/share/man/man7 && \
    apt-get update -q && \
    apt-get install --no-install-recommends --yes python3-sentry-sdk python3-voluptuous python3-yaml && \
    apt-get install --no-install-recommends --yes bmap-tools python3-aiohttp python3-configobj python3-guestfs python3-jinja2 python3-magic python3-netifaces python3-pexpect python3-pyudev python3-requests python3-setproctitle python3-yaml && \
    apt-get install --no-install-recommends --yes android-sdk-libsparse-utils docker.io dfu-util git libguestfs-tools ser2net telnet tftpd-hpa u-boot-tools unzip xz-utils zstd rpcbind nfs-common fastboot && \
    apt-get install --no-install-recommends --yes -t bookworm-backports qemu-system-arm qemu-system-mips qemu-system-misc qemu-system-ppc qemu-system-sparc qemu-system-x86 && \
    apt-get install --no-install-recommends --yes python3-pip && \
    python3 -m pip install --break-system-packages avh-api==1.0.5 && \
    find /usr/lib/python3/dist-packages/ -name '__pycache__' -type d -exec rm -r "{}" + && \
    rm -rf /var/lib/apt/lists/*


# 下载完取消
# 取消代理设置
ENV http_proxy ""
ENV HTTP_PROXY ""
ENV https_proxy ""
ENV HTTPS_PROXY ""