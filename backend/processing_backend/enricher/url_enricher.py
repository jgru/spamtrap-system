import asyncio
import base64
import datetime
import json
import logging
import os
import re
from hashlib import sha512

import async_dns.core.types
import async_dns.resolver.query

from datamodels import Url, File, Hash, Extraction, NetworkEntityFactory, EntityEnum
from processing_backend.enricher.base_enricher import BaseEnricher
from . import thug_service

logger = logging.getLogger(__name__)


class UrlEnricher(BaseEnricher):
    applicable_types = (Url,)
    thug_service = thug_service.__file__

    def __init__(self, database, thug_config_dir="./config/thug/", thug_timeout=30, thug_interpreter="python3.8",
                 whitelist_urls=None):
        self.database = database
        self.thug_config_dir = os.path.abspath(thug_config_dir)
        self.thug_timeout = str(thug_timeout)
        self.thug_interpreter = os.path.abspath(thug_interpreter)
        self.whitelist_urls = self.read_whitelist(whitelist_urls)
        self.loop = asyncio.get_event_loop()

        logger.info(f"Start URL enricher using Thug {self.thug_service} with a timeout of {self.thug_timeout} secs, \
                      using config in {self.thug_config_dir} and {self.thug_interpreter}")

    async def enrich(self, u):

        if u.url in self.whitelist_urls:
            logger.debug(f"Url {u.url} is whitelisted")
            return None, None  # Caller expects a tuple

        # Initiates analysis with thug
        report = await self.initiate_thug_analysis(u)

        # Process Thug's report
        enriched_url, extracted_files = self.process_report(u, report)
        logger.debug("Thug analysis and reporting completed")

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
            ) for i in srv_ips
        ]

        for h in hosts:
            if h.geo is not None:
                enriched_url.geo = h.geo

        enriched_url.is_enriched = True
        logger.info(f"Enriched url {u.url}")

        # Returns hosts separately to
        return enriched_url, [*hosts, *extracted_files]

    async def initiate_thug_analysis(self, url):
        logger.debug("Initiating Thug analysis")
        result_dict = None
        try:
            # Calls Python wrapped Thug
            result = await self.run_command(
                self.thug_interpreter,
                self.thug_service,
                "-u", url.url,
                "-t", self.thug_timeout,
                "-c", self.thug_config_dir
            )

            result_dict = json.loads(result)

        except BaseException as e:
            logger.debug(e)
            logger.debug(f"Thug analysis of {url.url} failed")

        return result_dict

    @staticmethod
    async def run_command(*args):
        """
        See https://asyncio.readthedocs.io/en/latest/subprocess.html for background info
        :param args: varargs
        :return:
        """
        # Create subprocess, stdout must a pipe to be accessible as process.stdout
        process = await asyncio.create_subprocess_exec(*args, stdout=asyncio.subprocess.PIPE)

        # Await the subprocess to finish
        stdout, stderr = await process.communicate()

        # Return stdout
        return stdout.decode().strip()

    @classmethod
    def process_report(cls, url, result_dict):
        files = []

        if result_dict:
            logger.info(f"Processing Thug result to {url}")

            # Retrieve analysis timestamp and make it timezone aware
            d = datetime.datetime.strptime(result_dict['timestamp'], "%Y-%m-%d %H:%M:%S.%f")
            url.analysis_timestamp = d.astimezone(datetime.timezone.utc)

            # Record exploits
            exploits = result_dict.get('exploits', [])
            if len(exploits):
                logger.info(f"Processing exploits")
                for e in exploits:
                    url.exploits.append(e)

            if len(result_dict['files']):
                logger.info(f"{len(result_dict['files'])} extracted")

                for entry in result_dict['files']:
                    blob, hash = cls.extract_data(entry)

                    file = File(
                        content_guess=entry['type'].lower(),
                        encoding='application/octet-stream',
                        filename=cls.get_filename(entry),
                        hash=hash,
                        blob=blob,
                        timestamp=url.analysis_timestamp
                    )

                    files.append(file)

                    # Add extraction, which references actual file
                    url.extractions.append(
                        Extraction(
                            description=file.filename,
                            hash=file.hash,
                            content_guess=file.content_guess
                        )
                    )
                    logger.info(f"Appended URL extraction {url.extractions}")

            logger.info(f"Processed report to {url.url}")

        return url, files

    @staticmethod
    def get_filename(file_entry):
        try:
            filename = file_entry['url'].split("/")[-1]
        except BaseException:
            filename = file_entry['sha256']

        return filename

    @classmethod
    def extract_data(cls, entry):
        blob = base64.b64decode(entry['data'])
        hash = cls.build_hash(entry, blob)

        return blob, hash

    @staticmethod
    def build_hash(file_entry, blob):
        sha512_digest = sha512(blob).hexdigest()

        return Hash(
            md5=file_entry['md5'],
            sha1=file_entry['sha1'],
            sha256=file_entry['sha256'],
            sha512=sha512_digest
        )

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
            q = cls.form_hostname(url)

            logger.info(f"Performing querying A record for {q}")

            try:
                resolver = async_dns.resolver.ProxyResolver()
                res = await resolver.query(q, qtype=async_dns.core.types.A, timeout=3, tick=5)
                a_records = []

                # Parses response, which is in the following form:
                # res -> [<Record type=response qtype=A name=example.com ttl=299 data=1.1.1.1>]
                for a in res.an:
                    if a.qtype == async_dns.core.types.A:
                        a_records.append(a.data)

                return a_records

            except Exception:  # resolver.query() throws generic exception
                logger.debug(f"Could not resolve A record to {url.subdomain}.{url.domain}")
                return []

    proto_to_port = {'ftp': 21, 'ssh': 22, 'http': 80, 'dcom-scm': 130, 'smb': 445, 'https': 443, None: 0}

    @classmethod
    def get_port_from_url(cls, enriched_url):
        p = enriched_url.get_port()

        # Returns explicitly mentioned port
        if p:
            return p
        # Infers from protocol otherwise
        else:
            return cls.proto_to_port.get(enriched_url.scheme, 0)
