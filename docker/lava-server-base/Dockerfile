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
    groupadd --system --gid 200 lavaserver && \
    useradd --system --home /var/lib/lava-server/home/ --uid 200 --gid 200 --shell /bin/sh lavaserver && \
    apt-get update -q && \
    apt-get install --no-install-recommends --yes apache2 gunicorn3 postgresql postgresql-client postgresql-common python3-setuptools && \
    apt-get install --no-install-recommends --yes libldap-common libsasl2-modules && \
    apt-get install --no-install-recommends --yes python3-boto3 python3-pycurl && \
    apt-get install --no-install-recommends --yes python3-sentry-sdk python3-voluptuous python3-yaml && \
    apt-get install --no-install-recommends --yes python3-aiohttp python3-asgiref python3-celery python3-defusedxml python3-django python3-django-allauth python3-django-auth-ldap python3-django-environ python3-django-filters python3-django-tables2 python3-djangorestframework python3-djangorestframework-extensions python3-djangorestframework-filters python3-jinja2 python3-junit.xml python3-psycopg2 python3-requests python3-tap python3-voluptuous python3-whitenoise python3-yaml python3-zmq && \
    apt-get install --no-install-recommends --yes python3-pip && \
    python3 -m pip install --break-system-packages django-matomo==0.1.6 django-sync-github-teams==0.1.1 && \
    find /usr/lib/python3/dist-packages/ -name '__pycache__' -type d -exec rm -r "{}" + && \
    rm -rf /var/lib/apt/lists/*


    # 下载完取消
# 取消代理设置
ENV http_proxy ""
ENV HTTP_PROXY ""
ENV https_proxy ""
ENV HTTPS_PROXY ""
