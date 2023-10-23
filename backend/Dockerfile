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
      python3-magic

# Packages from universe
#
# Install sflock2 dependencies
RUN sed -i 's/ main/ main non-free/' /etc/apt/sources.list.d/debian.sources \
    && apt-get update && apt-get install -y \
    apt-get update && \
    apt-get install rar \
    unace-nonfree \
    cabextract \
    lzip \
    p7zip-full && \
    rm -rf /var/lib/apt/lists/*

# Install thug dependencies
RUN pip3 install --upgrade pip
RUN pip3 install --upgrade setuptools
RUN mkdir -p /usr/local/src/backend
WORKDIR /usr/local/src/backend
COPY ./ ./

RUN pip3 install .

CMD ["python3", "-m", "spamtrap_backend"]