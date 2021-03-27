FROM python:3.8-slim-buster

RUN apt-get update -q --fix-missing && \
    apt-get -y upgrade

WORKDIR /usr/local/bin/

COPY requirements.txt .
RUN pip3 install -r requirements.txt

COPY catchall_lmtp/__init__.py ./catchall_lmtp/__init__.py
COPY catchall_lmtp/lmtp_server.py ./catchall_lmtp/lmtp_server.py
COPY catchall_lmtp/feed_distributor.py ./catchall_lmtp/feed_distributor.py
COPY catchall_lmtp.py .

COPY entrypoint.sh .
RUN chmod a+x entrypoint.sh

# Copy default hpfeeds config
COPY ./feed_config.yml /usr/local/etc/feed_config.yml

VOLUME ["/data"]
WORKDIR /data

EXPOSE 8587/tcp

#HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD printf "EHLO healthcheck\n" | nc localhost 8587 | grep -qE "^220.*"

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
