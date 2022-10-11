FROM ubuntu:22.04

USER root
ENV DEBIAN_FRONTEND=noninteractive
RUN echo 'APT::Get::Assume-Yes "true";' >> /etc/apt/apt.conf

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
      libboost-dev \
      libboost-iostreams-dev \
      libboost-python-dev \
      libboost-system-dev \
      python3-pip \
      libxml2-dev \
      libxslt-dev \
      tesseract-ocr \
      git \
      wget \
      unzip \
      libtool \
      graphviz-dev \
      automake \
      libffi-dev \
      graphviz \
      libfuzzy-dev \
      libfuzzy2 \
      libjpeg-dev \
      libffi-dev \
      libssl-dev \
      zlib1g-dev \
      pkg-config \
      clang \
      autoconf

# Packages from universe
RUN add-apt-repository universe && \
    apt-get update && \
    apt-get install rar \
    unrar \
    unace-nonfree \
    cabextract \
    lzip \
    p7zip-full && \
    rm -rf /var/lib/apt/lists/*

RUN pip3 install --upgrade pip
RUN pip3 install --upgrade setuptools
RUN pip3 install --upgrade pytesseract
RUN pip3 install --upgrade pygraphviz

WORKDIR /opt/
RUN wget https://github.com/cloudflare/stpyv8/releases/download/v10.3.174.20/stpyv8-ubuntu-22.04-python-3.10.zip
RUN unzip stpyv8-ubuntu-22.04-python-3.10.zip
RUN pip3 install stpyv8-ubuntu-22.04-3.10/stpyv8-10.3.174.20-cp310-cp310-linux_x86_64.whl
RUN mkdir -p /usr/share/stpyv8
RUN sudo mv stpyv8-ubuntu-22.04-3.10/icudtl.dat /usr/share/stpyv8
RUN git clone https://github.com/buffer/libemu.git && \
  cd libemu && \
  autoreconf -v -i && \
  ./configure && \
  make install && \
  cd .. && \
  rm -rf libemu
RUN ldconfig
RUN pip3 install thug

RUN mkdir /usr/local/src/backend
WORKDIR /usr/local/src/backend
COPY ./ ./
RUN pip3 install -r requirements.txt

CMD python3 run_backend.py