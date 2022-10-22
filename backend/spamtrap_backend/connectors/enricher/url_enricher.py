import logging
import re

import async_dns.core.types
import async_dns.resolver

from ...datamodels import EntityEnum, NetworkEntityFactory, Url

from .. import utils
from ..clients.thug_client import ThugdClient
from .base_enricher import BaseEnricher

logger = logging.getLogger(__name__)


class UrlEnricher(BaseEnricher):
    applicable_types = (Url,)
    resolver = "8.8.8.8"

    def __init__(self, whitelist_urls=None, **kwargs):

        self.loop = None
        self.thugd_client = ThugdClient(**kwargs)
        self.whitelist_urls = utils.read_whitelist(whitelist_urls)

        logger.info(f"Start URL enricher using Thug")

    async def enrich(self, u):

        if u.url in self.whitelist_urls:
            return None, None  # Caller expects a tuple

        # Initiates analysis with thug
        report = await self.thugd_client.submit(u)

        # Process Thug's report
        enriched_url, extracted_files = self.thugd_client.process_report(u, report)

        srv_ips = set(await self.retrieve_hosting_server(u))
        srv_port = self.get_port_from_url(enriched_url)

        # If category was not set before, check report for categorization hints
        if u.category == EntityEnum.website:
            if len(extracted_files) > 0:
                cat = EntityEnum.malware_distribution_site
            elif len(enriched_url.exploits) > 0:
                cat = EntityEnum.exploit_landing_page
            else:
                cat = EntityEnum.website
        else:
            cat = u.category

        enriched_url.category = cat
        hn = self.form_hostname(enriched_url)

        hosts = [
            NetworkEntityFactory.get_from_ip(
                i, srv_port, cat, hostname=hn, timestamp=enriched_url.timestamp
            )
            for i in srv_ips
        ]

        enriched_url.is_enriched = True
        logger.info(f"Enriched url {u.url}")

        # Returns hosts separately
        return enriched_url, [*hosts, *extracted_files]

    ip_pattern = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

    @staticmethod
    def form_hostname(url):
        if url.subdomain:
            hn = f"{url.subdomain}.{url.domain}"
        else:
            hn = f"{url.domain}"

        return hn

    @classmethod
    async def retrieve_hosting_server(cls, url):
        # Handle URLs with IPs
        if re.match(cls.ip_pattern, url.domain):
            return [url.domain]
        else:  # Resolve FQDN to IP
            query_domain = cls.form_hostname(url)

            try:
                resolver = async_dns.resolver.DNSClient(timeout=3)
                res = await resolver.query(
                    query_domain,
                    qtype=async_dns.core.types.A,
                    addr=async_dns.core.address.Address.parse(cls.resolver),
                )

                a_records = []
                # Parses response, which is in the following form:
                # res -> [<Record type=response qtype=A name=domain.tld ttl=97 data=<a: 1.1.1.1>>]
                for an in res.an:
                    if an.qtype == async_dns.core.types.A:
                        a_records.append(an.data.data)

                return a_records

            except Exception:  # resolver.query() throws generic exception
                logger.info(f"Could not resolve A record to {query_domain}")
                return []

    proto_to_port = {
        "ftp": 21,
        "ssh": 22,
        "http": 80,
        "dcom-scm": 130,
        "smb": 445,
        "https": 443,
        None: 0,
    }

    @classmethod
    def get_port_from_url(cls, enriched_url):
        p = enriched_url.port

        # Returns explicitly mentioned port
        if p:
            return p
        # Infers from protocol otherwise
        else:
            return cls.proto_to_port.get(enriched_url.scheme, 0)
