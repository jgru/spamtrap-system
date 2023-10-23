FROM debian:bookworm-20221219

USER root
ENV DEBIAN_FRONTEND=noninteractive
RUN echo 'APT::Get::Assume-Yes "true";' >> /etc/apt/apt.conf

# Install general dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      software-properties-common \
      build-essential \
      sudo \
      python3 \
      python3-dev \
      python3-setuptools \
      python3-wheel \
      python-is-python3 \
      python3-pip \
      python3-magic \
      python3-venv

# Packages from universe
#
# Install sflock2 dependencies
RUN apt-add-repository non-free
RUN apt-get update && apt-get install -y \
    rar \
    unace-nonfree \
    cabextract \
    lzip \
    p7zip-full && \
    rm -rf /var/lib/apt/lists/*


RUN mkdir -p /usr/local/src/backend
WORKDIR /usr/local/src/backend
COPY ./ ./

RUN mkdir -p /opt/venv  && python3 -m venv /opt/venv/spamtrap

# Prep dep installation
RUN /opt/venv/spamtrap/bin/python -m pip install --upgrade pip
RUN /opt/venv/spamtrap/bin/python -m pip install --upgrade setuptools

# Install deps of backend
RUN /opt/venv/spamtrap/bin/python -m pip install .

CMD ["/opt/venv/spamtrap/bin/python", "-m", "spamtrap_backend"]