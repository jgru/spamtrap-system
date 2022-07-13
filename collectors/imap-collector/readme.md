<a id="orgff02eb4"></a>

# imap-collector

A tool to concurrently collect spam mails from spamtrap mailboxes via the [IMAP-protocol](https://tools.ietf.org/html/rfc3501) and transfer the retrieved messages via the transport protocol [hpfeeds](https://hpfeeds.org/) to a central processing backend in an asynchronous manner by using [aioimaplib](https://github.com/bamthomas/aioimaplib).

## Table of Contents

- [imap-collector](#orgff02eb4)
- [Motivation](#orgc1e3c7e)
- [Dependencies](#org45dc02a)
- [Installation](#org4abeb58)
- [Usage](#org7f72ad9)
  - [Config files](#org77d1136)
  - [Commandline arguments](#org2e7d5ce)

<a id="orgc1e3c7e"></a>

## Motivation

As the name suggests `imap-collector` functions as a collection component within the distributed spamtrap-system. It enables concurrent retrieval malspam from several mailboxes via IMAP and sends it to the backend in an authenticated and integrity protected manner in the form of a JSON-object in the form of

```JSON
{
"sha256": "sha256_hexdigest",
"msg": "rfc5322_data_in_utf8"
}
```

Those spamtrap mailboxes can be either hosted at freemail services or single spamtraps on production mail servers. By utilizing the IDLE command specified in RFC 2177 real time access to multiple mailboxes is possible without wasting CPU cycles.


<a id="org45dc02a"></a>

## Dependencies

imap-collector requires the following Python packages, which are specified in [requirements.txt](https://github.com/jgru/spamtrap-system/blob/main/collectors/imap-collector/requirements.txt):

-   aioimaplib==0.7.18
-   hpfeeds==3.0.0
-   PyYAML==5.3.1


<a id="org4abeb58"></a>

## Installation

Use Python package installer [pip](https://github.com/pypa/pip) to install the a/m requirements:

```
pip3 install -r ./requirements.txt
```

Consider installing tho dependencies in a virtualenv like this

```
# Install virtualenv package
sudo pip3 install virtualenv

# Create virtualenv by specifying a specific interpreter
virtualenv -p /usr/bin/python3.8 imap_collector_venv

# Activate newly created venv
source imap_collector_venv/bin/activate

# Install imap-collector's requirements
pip3 install -r ./requirements.txt

# Run it
python3.8 aioimap_collector.py -h

# Deactivate venv
deactivate
```


<a id="org7f72ad9"></a>

## Usage


<a id="org77d1136"></a>

### Config files

Two config files are used: `feed_config.yml` and `mailbox_credentials_template.yaml`

1.  Configuration for hpfeeds

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

2.  Configuration of mailboxes

    Each entry in the `mailbox_credentials_template.yaml` defines a spamtrap mailbox to query during the retrieval process. The following snippet illustrates how to setup the spamtrap mailboxes:
    
    ```yaml
    --- # Mailbox configs
    - username:  "user@domain"
      password:  "secret"
      protocol: "imap"
      host: "mail.mailserver.com"
      port:  993
    - username:  "user@domain"
      password:  "secret"
      protocol: "imap"
      host: "mail.mailserver.com"
      port:  143
    ```


<a id="org2e7d5ce"></a>

### Commandline arguments

Specifying the path to the `--feed-config`-YAML-file is neccessary, as well as specifying the `--mailbox-config`-file containing the IMAP mailboxes to query. `aioimap_collector.py` can be used to fetch new mails/all mails (`-a`) a single time or continuosly (`-c`). See the help page for a full reference.

```
aioimap_collector.py -h
usage: aioimap_collector.py [-h] [-f FEED_CONFIG] [-m MAILBOX_CONFIG] [-a] [-d] [-c]

Retrieves emails from an IMAP server in an async manner. Tested with gmail and dovecot.

optional arguments:
  -h, --help            show this help message and exit
  -f FEED_CONFIG, --feed-config FEED_CONFIG
                        Config file in yaml syntax specifying broker to use
  -m MAILBOX_CONFIG, --mailbox-config MAILBOX_CONFIG
                        Config file in yaml syntax specifying mailboxes to query
  -a, --fetch-all       Fetch all messages in INBOX, otherwise fetch only, unseen msgs
  -d, --delete          Delete messages after fetch (doublecheck, that broker is available!)
  -c, --continuous-fetch
                        Perform single fetch only, otherwise fetcher runs continuosly

```
