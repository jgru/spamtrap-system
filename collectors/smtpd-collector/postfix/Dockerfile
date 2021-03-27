FROM debian:buster-slim
MAINTAINER: 6ru

ENV DEBIAN_FRONTEND noninteractive

ARG MYHOSTNAME=localhost
ARG MYDOMAIN=local

RUN apt-get update -q --fix-missing && \
  apt-get -y upgrade && \
  apt-get -y install postfix && \
  apt-get -y install --no-install-recommends \
  apt-transport-https \
  postfix-ldap \
  postfix-pcre \
  postfix-policyd-spf-python \
  postsrsd

RUN apt-get autoclean && \
  rm -rf /var/lib/apt/lists/* && \
  rm -rf /usr/share/locale/* && \
  rm -rf /usr/share/man/* && \
  rm -rf /usr/share/doc/* && \
  touch /var/log/auth.log && \
  rm /etc/postsrsd.secret

# Set Postfix main.cf and master.cf
COPY config/relay-domains_main.cf /etc/postfix/main.cf
COPY config/master.cf /etc/postfix/master.cf


RUN postconf -e myhostname=$HOSTNAME && \
	postconf -e mydomain=$MYDOMAIN

# Configuring where to relay
COPY config/smtp_transport /etc/postfix/smtp_transport
RUN postmap /etc/postfix/smtp_transport

# Configuring which domains to relay
COPY config/relay_domains /etc/postfix/relay_domains
RUN postmap /etc/postfix/relay_domains


HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD printf "EHLO healthcheck\n" | nc localhost 587 | grep -qE "^220.*ESMTP Postfix"
STOPSIGNAL SIGINT

EXPOSE 25
EXPOSE 587

CMD ["postfix", "start-fg"]
