FROM python:3.11.0b1-buster

# set work directory
WORKDIR /app


# Debian 10 (buster) is end-of-life: deb.debian.org returns 404 for it, so this
# layer - and therefore the whole image - stopped building. The packages moved to
# archive.debian.org, which is a frozen snapshot with no Release date validity,
# hence Check-Valid-Until. buster-updates does not exist in the archive at all.
#
# The EOL base image is retained deliberately: its unpatched OS packages are the
# vulnerability surface the image-scanning stage exists to demonstrate. Moving to
# a supported base would leave the two image scanners with nothing to find. The
# accepted CVEs are fingerprinted in .security/baseline/.
#
# Versions re-pinned to what the archive actually serves (the previous pins point
# at packages the archive superseded).
# dependencies for psycopg2
RUN sed -i -e 's|deb.debian.org/debian|archive.debian.org/debian|g' \
           -e 's|security.debian.org/debian-security|archive.debian.org/debian-security|g' \
           -e '/buster-updates/d' /etc/apt/sources.list \
 && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99no-check-valid-until \
 && apt-get update && apt-get install --no-install-recommends -y \
      dnsutils=1:9.11.5.P4+dfsg-5.1+deb10u11 \
      libpq-dev=11.22-0+deb10u2 \
      python3-dev=3.7.3-1 \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/*


# Set environment variables
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1


# Install dependencies
RUN python -m pip install --no-cache-dir pip==22.0.4
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt


# copy project
COPY . /app/


# install pygoat
EXPOSE 8000


RUN python3 /app/manage.py migrate

# Run as a non-root, high-UID account. This hardens the *platform*, not the
# application: every PyGoat vulnerability above remains exploitable, but a
# successful exploit no longer lands as root.
#
# It is also a hard prerequisite for deploy/k8s, where the securityContext sets
# runAsNonRoot and a read-only root filesystem - the kubelet refuses to start a
# container whose image declares USER root under that policy.
#
# UID 10001 is outside the host's system-account range, so a container escape
# does not map onto a privileged host user.
RUN groupadd --gid 10001 pygoat \
 && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin pygoat \
 && chown -R pygoat:pygoat /app
USER 10001

# WORKDIR must stay /app: the Django settings package is /app/pygoat, so the
# module path `pygoat.wsgi` only resolves from its parent. The upstream
# `WORKDIR /app/pygoat/` made every gunicorn worker die with
# "ModuleNotFoundError: No module named 'pygoat'" - the image built but could
# never serve a request.
WORKDIR /app
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers","6", "pygoat.wsgi"]
