
<a id="orgea7a9f7"></a>

# hpfeeds-broker-tls

## Table of Contents 

- [hpfeeds-broker-tls](#orgea7a9f7)
  - [Motivation](#orgad15c3e)
  - [Usage](#orgb584f96)
    - [Preparations](#orga35c188)
    - [Run it](#org62e6d27)
    - [Test](#orgbf6616f)

<a id="orgad15c3e"></a>

## Motivation

There are three implementations of [hpfeeds-brokers](https://hpfeeds.org/brokers) ranging from Python, Go and C++. The most easy one to use is the Python broker, which brings TLS support out of the box <sup><a id="fnr.1" class="footref" href="#fn.1" role="doc-backlink">1</a></sup>. Unfortunately this broker is not as performant as the other implementations, furtheron it does only support a message size of 1024<sup>2</sup> bytes <sup><a id="fnr.2" class="footref" href="#fn.2" role="doc-backlink">2</a></sup>, although the hpfeeds-protocol supports payloads up to 2<sup>32</sup> bytes.

Neither the Go implementation called [HPFBroker](https://github.com/d1str0/HPFBroker) nor the C++-implementation called [tentacool](https://github.com/tentacool/tentacool) support TLS out of the box. Therefore a dockerized setup was created, which places [tentacool](https://github.com/tentacool/tentacool) behind a [haproxy](https://github.com/haproxy/haproxy) instance, which functions as a reverse proxy to provide TLS encryption.


<a id="orgb584f96"></a>

## Usage

The environment variables for docker-compose are stored in the file [.env](.env), here you can adapt port numbers, filenames for the certificate to use and the IP-addresses of the containers in their private networks. The `.env`-file contains the following variables:

-   `SUBNET`: IP-Range of the internal Docker network (i.e. 172.28.1.0/24)
-   `HAPROXY_IP`: Internal IP-Address of the haproxy-container (i.e. 172.28.1.2)
-   `HAPROXY_PORT`: Exposed port of the haproxy-container, which is used for receiving connections. This will be made accessible on the Docker host.
-   `CERT`: Name of the certificate-file (of type .pem), which is expected to exist inside the directory `./certs`
-   `TENTACOOL_IP`: Internal IP-address of the container running the hpfeeds-broker named tentacool (i.e. 172.28.1.3)
-   `TENTACOOL_PORT`: Port of the hpfeeds-broker. This will only accessible internally, not exposed.
-   `AUTH_FILE`: Name of the comma-separated values file (i.e. `auth_keys.dat`)


<a id="orga35c188"></a>

### Preparations

The following modifications are necessary in order to use the setup:

1.  Modify tentacool's credential-file

    Usage is very easy, you have to adjust a .csv-file called [auth<sub>keys.dat</sub>](tentacool/data/auth_keys.dat), which contains the hpfeeds credentials for the subscribers and publishers, who want to connect to the broker <sup><a id="fnr.3" class="footref" href="#fn.3" role="doc-backlink">3</a></sup>.
    
    ```bash
    # Add credentials to the auth_keys.dat-file
    nano ./tentacool/data/auth_keys.dat
    ```

2.  Create your certificates

    The certificates are expected to be placed in [./certs](certs/). `haproxy` expects that the private key is named exactly like the public key but with a `.key` suffix. If you choose another name than `certificate`, than modify the variable `$CERT`, which is specified inside the environment variable file [.env](.env).
    
    I.e.:
    
    ```
    cp *.pem ./certs
    mv fullchain.pem certificate
    mv privkey.pem certificate.key
    ```
    
    Note, that if you use a CA like Let's Encrypt you have to place the `fullchain.pem`-file, which contains the whole CA trail, in the a/m directory <sup><a id="fnr.4" class="footref" href="#fn.4" role="doc-backlink">4</a></sup>. Theoretically you could use a self-signed cert as well <sup><a id="fnr.5" class="footref" href="#fn.5" role="doc-backlink">5</a></sup>.


<a id="org62e6d27"></a>

### Run it

After following the a/m steps run the setup with the following command:

```bash
docker-compose build && docker-compose up --force-recreate
```


<a id="orgbf6616f"></a>

### Test

Test the functionality with valid certificate (e.g. from Let's Encrypt) like so:

```bash
hpfeeds subscribe --tls --host hostname.tld -p 10000 -i "reader" -s "secret" -c "ch1"
```

Test the functionality with a self-signed certificate <sup><a id="fnr.6" class="footref" href="#fn.6" role="doc-backlink">6</a></sup> like so:

```bash
hpfeeds subscribe --tls --host hostname -p 10000 -i "reader" -s "secret" -c "ch1" --tlscert=path/to/self-signed-cert.crt
```

## Footnotes

<sup><a id="fn.1" class="footnum" href="#fnr.1">1</a></sup> See <https://python.hpfeeds.org/en/latest/broker.html>

<sup><a id="fn.2" class="footnum" href="#fnr.2">2</a></sup> See <https://github.com/hpfeeds/hpfeeds/blob/2ca4b7a9271b3b9f46a8210050e0500d0b0bbef4/hpfeeds/protocol.py#L20>

<sup><a id="fn.3" class="footnum" href="#fnr.3">3</a></sup> In the future MongoDB support could be added, which tentacool supports by using libpoco.

<sup><a id="fn.4" class="footnum" href="#fnr.4">4</a></sup> Its import to use Lets Encrypts fullchain.pem in Docker file -> Error: otherwise certificate verify failed: unable to get local issuer certificate (<sub>ssl.c</sub>:1108)

<sup><a id="fn.5" class="footnum" href="#fnr.5">5</a></sup> Create it with this command i.e.: `openssl req -x509 -newkey rsa:2048 -keyout broker.key -nodes -out broker.crt -sha256 -days 1000`

<sup><a id="fn.6" class="footnum" href="#fnr.6">6</a></sup> Check hostname via `cat cert | openssl x509 -text | less`
