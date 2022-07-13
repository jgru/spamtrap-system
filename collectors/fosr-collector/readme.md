<a id="org6c8988c"></a>

# fosr-collector

This is a fork of [FakeOpenSMTPRelay](https://github.com/waaeh/FakeOpenSmtpRelay) created by [Waaeh](https://github.com/waaeh/FakeOpenSmtpRelay) <sup><a id="fnr.1" class="footref" href="#fn.1" role="doc-backlink">1</a></sup> to extend it to transport incoming mail to a [hpfeeds-broker](https://hpfeeds.org/brokers).

## Table of Contents

- [fosr-collector](#org6c8988c)
  - [Description](#org4327b5e)
    - [Overview](#org657c9b8)
    - [Added functionality](#orgc7e2cd6)
  - [Dependencies](#org08e8e4e)
  - [Installation](#org6358e8f)
  - [Usage](#org2ee434b)
    - [Commandline parameters](#org1eac1f4)
    - [TLS configuration for SMTP services](#orgce9db2c)
    - [Configuration for hpfeeds](#orgdd6da3e)


<a id="org4327b5e"></a>

## Description

For a reference on the original tool see: <https://github.com/waaeh/FakeOpenSmtpRelay/blob/master/README.md>


<a id="org657c9b8"></a>

### Overview

FakeOpenSmtpRelay.py is a Python simulation of a working open SMTP relay. Waeeh's solution is based on the three building blocks:

-   By utilizing the Python library [aiosmtpd](https://github.com/aio-libs/aiosmtpd) a fake open SMTP relay server is created, which will run on the SMTP ports: 25, 465 and587. It will accept any email from any sender.
-   A dynamic rule engine is implemented, which tries to identify email probes from spammers and selectively relays them to their author. This script can be run in an automated way or with user-interaction. Safeguards are implemented to avoid turning into a true open relay in case of a logic flaw - such as the number of maximum emails relayed per day.
-   The transport layer was extended by a [hpfeeds distributor](https://hpfeeds.org/brokers), so that spam message can be relayed to a [hpfeeds-broker](https://hpfeeds.org/brokers).


<a id="orgc7e2cd6"></a>

### Added functionality

The threading model of the code was optimized, so that the SMTP servers listening on the different ports and offering different flavours of service (unencrypted, implicit and explicit TLS,&#x2026;) run in the same event loop. Before every server instance run in its own thread using its on event loop, which counteracted the async concurrency model. Those server instance now add received emails to an async queue for further distribution. A commandline argument was added, so that a `feed_config.yml`-file could be specified, which holds information about the message broker to use. The class `HpfeedsDistributor` was added and uses the a/m queue to retrieve incoming mails and send them to the backend in an authenticated and integrity protected manner in the form of a JSON-object, like so:

```JSON
{
"sha256": "sha256_hexdigest",
"msg": "rfc5322_data_in_utf8"
}
```


<a id="org08e8e4e"></a>

## Dependencies

`fosr_collector.py` requires in addition to the original dependencies the Python library [hpfeeds](https://github.com/hpfeeds/hpfeeds) in version 3.0.0. Therefore it depends on the following libs:

-   aiosmtpd==1.2.2
-   atpublic==2.1.1
-   dnspython==2.0.0
-   hpfeeds==3.0.0


<a id="org6358e8f"></a>

## Installation

Use Python package installer [pip](https://github.com/pypa/pip) to install the a/m requirements:

```bash
pip3 install -r ./requirements.txt
```

Consider installing tho dependencies in a virtualenv like this

```bash
# Install virtualenv package
sudo pip3 install virtualenv

# Create virtualenv by specifying a specific interpreter
virtualenv -p /usr/bin/python3.8 fosr_collector_venv

# Activate newly created venv
source fosr_collector_venv/bin/activate

# Install imap-collector's requirements
pip3 install -r ./requirements.txt

# Run it
python3.8 fosr_collector.py -h

# Deactivate venv
deactivate
```


<a id="org2ee434b"></a>

## Usage


<a id="org1eac1f4"></a>

### Commandline parameters

```
usage: fosr_collector.py [-h] [-i] [-t] [-d] [-f FEED_CONFIG]

Simulates a Fake Open SMTP relay to collect spam mails.

optional arguments:
  -h, --help            show this help message and exit
  -i, --interactive
  -t, --testMode
  -d, --debug
  -f FEED_CONFIG, --feed-config FEED_CONFIG
                        Config file in JSON-syntax specifying hpfeeds broker
                        and credentials to use
```


<a id="orgce9db2c"></a>

### TLS configuration for SMTP services

Create or reference certificate files to handle command STARTTLS and explicit TLS SMTP. The expected file names are hardcoded inside the code as `INSTALL_CERTIFICATE_CERT_FILE` & `INSTALL_CERTIFICATE_KEY_FILE`. You can kust run `openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem` inside this directory.


<a id="orgdd6da3e"></a>

### Configuration for hpfeeds

`feed_config.yml` stores the needed configuration for submitting mails to the [hpfeeds-broker](https://hpfeeds.org/brokers)

```yaml
---  # Broker config
  broker: "127.0.0.1"
  port: 10_000
  identity: "writer"
  secret: "secret"
  channels:
    - "spam.mails"
```

## Footnotes

<sup><a id="fn.1" class="footnum" href="#fnr.1">1</a></sup> Released under the MIT license, which is compatible with GPL
