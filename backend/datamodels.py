import json
import logging
import re
import socket
from dataclasses import InitVar
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from hashlib import md5, sha1, sha256, sha512
from typing import ClassVar
from typing import List

import geoip2.database
import geoip2.errors
import netaddr
from bson import ObjectId
from netaddr import IPAddress
from pyfaup.faup import Faup

logger = logging.getLogger(__name__)


def asdict(o, skip_empty=True):
    """
    Inspired by https://stackoverflow.com/a/56839195
    """
    return {key: value
            for key, value in o.__dict__.items()
            if not (skip_empty and value is None)}


class CollectionEnum(str, Enum):
    """
    Enum of strings, specifying collection names of MongoDB
    """
    raw = "raw"
    url = "urls"
    email = "emails"
    file = "files"
    events = "events"
    network_entity = "network_entities"


class EntityEnum(str, Enum):
    """
    Enum of strings, specifying certain roles of network infrastructure
    """
    smtp_server = "smtp_server"
    website = "website"
    victim = "victim"
    honeypot = "honeypot"
    malware_infrastructure = "malware_infrastructure"
    malware_distribution_site = "malware_distribution_site"
    c2_server = "c2_server"
    exploit_landing_page = "exploit_landing_page"
    dns_query = "dns_query"
    unspecified = "unspecified"


class NetworkTypeEnum(str, Enum):
    ipv4 = "ipv4"
    ipv6 = "ipv6"


class NetworkTransportEnum(str, Enum):
    tcp = "tcp"
    udp = "udp"


@dataclass
class Parent:
    parent_id: str
    parent_type: CollectionEnum


@dataclass
class FeedMsg:
    identifier: str
    channel: str
    timestamp: datetime = field(init=False)
    payload: dict = field(init=False)
    raw_payload: InitVar[str] = None
    # GridFS file_id, will be used as parent reference
    _id: ObjectId = None

    def __post_init__(self, raw_payload: str):
        self.timestamp = datetime.utcnow()
        self.payload = self.parse_payload(raw_payload)

    @staticmethod
    def parse_payload(payload):
        try:
            payload_dict = json.loads(payload)
            return payload_dict
        except ValueError:
            logger.warning('Payload was not parseable JSON, storing it as a string')
            return {"raw": payload}


@dataclass
class Hash:
    # Inspired by: https://www.elastic.co/guide/en/ecs/master/ecs-hash.html
    md5: str
    sha1: str
    sha256: str
    sha512: str


class HashFactory:
    @classmethod
    def get_hashstruct_from_bytes(cls, buffer):
        return Hash(
            md5=md5(buffer).hexdigest(),
            sha1=sha1(buffer).hexdigest(),
            sha256=sha256(buffer).hexdigest(),
            sha512=sha512(buffer).hexdigest()
        )


@dataclass
class Extraction:
    description: str
    hash: Hash
    content_guess: str
    extension: str


@dataclass
class Geo:
    # Inspired by https://www.elastic.co/guide/en/ecs/master/ecs-geo.html
    city_name: str
    continent_name: str
    country_iso_code: str
    country_name: str
    location: dict  # e.g. { "lon": -73.614830, "lat": 45.505918 }


@dataclass
class NetworkEntity:
    ip: str
    port: int
    category: EntityEnum = EntityEnum.unspecified
    geo: Geo = None
    is_enriched: bool = False
    timestamp: datetime = datetime.utcnow()
    parent: Parent = None
    hostname: str = None
    _id: str = None

    def __eq__(self, other):
        return self.ip == other.ip and self.port and other.port


class NetworkEntityFactory:
    GEO_DB = "./GeoLite2-City.mmdb"
    geoip_reader = geoip2.database.Reader(GEO_DB)
    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

    @classmethod
    def get_from_ip(cls, ip, port, type, hostname=None, timestamp=datetime.utcnow()):
        try:
            ip_addr = IPAddress(ip)
        except netaddr.core.AddrFormatError:
            logger.debug(f"Failed to parse {ip}")
            return None

        geo = None

        if not ip_addr.is_private() and not ip_addr.is_reserved():
            geo = cls.get_geo(ip)

            if not hostname:
                hostname = cls.get_rdns(ip)

        return NetworkEntity(ip, port, type, geo, hostname=hostname, timestamp=timestamp, is_enriched=True)

    @classmethod
    def get_from_hostname(cls, hostname, type, timestamp=datetime.utcnow()):
        ip = cls.get_ip(hostname)
        geo = None

        try:
            ip_addr = IPAddress(ip)

            if ip_addr and not ip_addr.is_private() \
                    and not ip_addr.is_reserved():
                geo = cls.get_geo(ip)

        except netaddr.core.AddrFormatError:
            logger.debug(f"Failed to parse {ip}")

        return NetworkEntity(ip, 0, type, geo, hostname=hostname, timestamp=timestamp, is_enriched=True)

    @classmethod
    def get_geo(cls, ip_addr):
        geo = None

        try:
            res = cls.geoip_reader.city(str(ip_addr))
            geo = Geo(
                continent_name=res.continent.name,
                country_name=res.country.name,
                country_iso_code=res.country.iso_code,
                city_name=res.city.name,
                location={"lat": res.location.latitude, "lon": res.location.longitude}
            )

        except geoip2.errors.AddressNotFoundError:
            logger.info(f"Could not find loc for {str(ip_addr)}")
            pass

        return geo

    @classmethod
    def get_ip(cls, hostname):
        ip = ""
        try:
            ip = str(socket.gethostbyname(hostname))
        except socket.gaierror:
            pass

        if re.match(cls.ip_pattern, ip):
            return ip

        return None

    @classmethod
    def get_rdns(cls, ip):
        try:
            rdns = socket.gethostbyaddr(ip)[0]
        except:
            rdns = None
        return rdns


@dataclass
class Network:
    protocol: str
    type: NetworkTypeEnum = "ipv4"  # e.g. "ipv4",
    transport: NetworkTransportEnum = "tcp"  # "udp"


@dataclass
class Observer:
    name: str
    type: str = "spamtrap"


@dataclass
class Session:
    timestamp: datetime
    source_ip: str
    honeypot: str
    protocol: str
    parent: ObjectId
    attachments: List[Hash] = field(default_factory=list)
    source_port: int = 0
    destination_port: int = 0
    source_country: str = ""


@dataclass
class NetworkEvent:
    # Inspired by https://www.elastic.co/guide/en/ecs/master/ecs-mapping-network-events.html
    timestamp: datetime
    source: NetworkEntity
    destination: NetworkEntity
    related: List[IPAddress]  # list of the addresses of above
    observer: Observer
    category: Network
    urls: List[str] = field(default_factory=list)
    kind: str = "event"
    type: str = "creation"


@dataclass
class Address:
    address: str
    domain: str = None
    top_level_domain: str = None
    subdomain: str = None

    def __post_init__(self):
        if self.domain is None:
            f = Faup()  # Example code at https://programtalk.com/python-examples-amp/pyfaup.faup.Faup/
            f.decode(self.address.split("@")[-1])
            self.top_level_domain = f.get_tld()
            self.domain = f.get_domain()
            self.subdomain = f.get_subdomain()


@dataclass
class File:
    ARCHIVE_EXTS: ClassVar[list] = ["zip", "rar", "tar"]

    # Inspired by https://www.elastic.co/guide/en/ecs/master/ecs-file.html
    content_guess: str
    extension: str
    filename: str
    hash: Hash  # reference for data container in GridFS
    blob: bytes  # will be stored in GridFS
    timestamp: datetime
    is_enriched: bool = False
    parent: Parent = None
    file_id: ObjectId = None  # will be stored in GridFS
    encoding: str = 'application/octet-stream'
    analysis_id: ObjectId = None
    mal_score: float = 0.0
    analysis_timestamp: datetime = None
    extractions: List[Hash] = field(default_factory=list)
    family: str = "Unkown"
    password: str = None
    _id: str = None


@dataclass
class Url:
    # Inspired by https://www.elastic.co/guide/en/ecs/master/ecs-url.html
    url: str  # analysis is referenced by full url
    timestamp: datetime
    parent: Parent = None
    is_enriched: bool = False
    scheme: str = None  # https...
    domain: str = None
    top_level_domain: str = None
    subdomain: str = None
    path: str = None
    extractions: List[Extraction] = field(default_factory=list)
    exploits: List[dict] = field(default_factory=list)
    analysis_timestamp: datetime = None
    geo: Geo = None
    category: str = EntityEnum.website
    _id: str = None

    def __post_init__(self):
        f = Faup() # Example code at https://programtalk.com/python-examples-amp/pyfaup.faup.Faup/
        f.decode(self.url)

        self.scheme = f.get_scheme()
        self.top_level_domain = f.get_tld()
        self.domain = f.get_domain()
        self.subdomain = f.get_subdomain()
        self.path = f.get_resource_path()

    # For creation of network entity
    def get_port(self):
        f = Faup()
        f.decode(self.url)
        return f.get_port()


@dataclass
class Email:
    # Follows RFC for ECS https://github.com/elastic/ecs/pull/999
    # See https://github.com/jamiehynds/ecs/blob/jamiehynds-patch-2/rfcs/text/0008-email.md
    file_id: ObjectId
    attachment_count: int
    attachments: List[Extraction]  # referral to file
    cc: List[Address]
    destination: NetworkEntity
    domains: List[str]
    message: str
    message_id: str
    observer: Observer
    recipients: List[Address]
    related: List[IPAddress]  # list of the addresses of above
    reply_to: Address
    return_path: Address
    sender: Address
    sha256: str  # for referral to original blob
    size: int
    source: NetworkEntity
    subject: str
    to: List[Address]
    timestamp: datetime
    urls: List[str]
    is_enriched: bool = True
    # bcc: List[Address]  # use it to be ECS compliant; [] here
    # direction: str = "inbound"  # use it  to be ECS compliant; everytime inbound
    _id: str = None
