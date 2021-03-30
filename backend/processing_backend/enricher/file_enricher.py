import asyncio
import datetime
import json
import logging
import sys

import aiohttp

try:
    from sflock.main import unpack
    from sflock.unpack import ZipFile, Zip7File, RarFile, TarFile
    from sflock.abstracts import File as SflockFile
except ImportError:
    print("Missing dependencies:")
    print("sudo apt-get install p7zip-full rar unrar rar unace-nonfree; sudo pip install -U sflock")
    sys.exit(1)

from datamodels import File, Url, NetworkEntityFactory, EntityEnum, HashFactory, Extraction
from processing_backend.enricher.base_enricher import BaseEnricher

logger = logging.getLogger(__name__)


class FileEnricher(BaseEnricher):
    ignore_list = ["jpg", "png", "ico", "bmp", "gif"]
    applicable_types = (File,)
    cuckoo_report_endpoint = "/tasks/create/file"
    reported = "reported"

    def __init__(self, database, cuckoo_host="localhost", cuckoo_port="8090", cuckoo_timeout=30, whitelist_ips=None,
                 whitelist_domains=None):
        self.database = database
        self.cuckoo_host = cuckoo_host
        self.cuckoo_port = cuckoo_port
        self.cuckoo_url = f"http://{self.cuckoo_host}:{self.cuckoo_port}"
        self.cuckoo_timeout = cuckoo_timeout
        self.cuckoo_retry = 1

        # For filtering OS noise
        self.whitelist_ips = self.read_whitelist(whitelist_ips)
        self.whitelist_domains = self.read_whitelist(whitelist_domains)

        logger.info(f"Start file enricher using cuckoo on {self.cuckoo_url} \
                      with a timeout of {self.cuckoo_timeout} secs.")

    async def enrich(self, f):

        if f.extension in File.ARCHIVE_EXTS:
            return self.extract_archive(f)

        # Checks, if sample is already known
        doc = await self.database.find_file_by_sha512(f.hash.sha512)

        if not doc or not doc["analysis_id"]:
            report = await self.analyze_file(f)
        else:
            logger.debug(f"Hash of file '{f.filename}' already known. No need to analyze again.")
            report = await self.retrieve_report(doc["analysis_id"])

        file, children = self.process_report(f, report)
        file.is_enriched = True

        logger.info(f"Enriched '{f.filename}'")

        return file, children

    @classmethod
    def extract_archive(cls, f):
        logger.debug(f"Extracting {f.filename}")
        content = f.blob

        if f.password:
            # Sflock expects byte string
            pw = f.password.encode("utf-8")
        else:
            pw = None

        if f.extension == "zip":
            if "v5.1" in f.content_guess:
                # Unzip is not capable to process this version, 7z is required (Zip7File)
                archive_file = Zip7File(SflockFile(contents=content, password=pw))
            else:
                archive_file = ZipFile(SflockFile(contents=content, password=pw))
        elif f.extension == "rar":
            archive_file = RarFile(SflockFile(contents=content, password=pw))
        elif f.extension == "tar":
            archive_file = TarFile(SflockFile(contents=content, password=pw))
        else:  # Fallback to zip
            archive_file = Zip7File(SflockFile(contents=content, password=pw))

        files_in_zip = list(archive_file.unpack(password=pw, duplicates=[]))
        extracted_files = []

        for zf in files_in_zip:
            h = HashFactory.get_hashstruct_from_bytes(zf.contents)
            cg = zf.magic
            fn = zf.filename.decode("utf-8")
            ext = fn.rsplit(".", 1)[-1] if "." in fn else ""

            f.extractions.append(Extraction(
                content_guess=cg,
                extension=ext,
                description=fn,
                hash=h
            )
            )

            file_struct = File(
                content_guess=cg,
                extension=ext,
                encoding='application/octet-stream',  # alternative: "hex"
                filename=fn,
                hash=h,
                blob=zf.contents,
                timestamp=f.timestamp
            )
            extracted_files.append(file_struct)
            logger.info(f"Extracted {zf.filename}")

            f.is_enriched = True

        return f, extracted_files

    async def analyze_file(self, file: File) -> dict:
        report = None

        if file.content_guess not in self.ignore_list:
            raw_data = file.blob
            task_id = await self.submit_file_for_analysis(raw_data)

            if not task_id:  # "message": "This file has already been submitted"
                task_id = await self.get_taskid_to_hash(file.hash.sha256)

                # Handles rare edge case, when exe was submitted inside archive.
                # This leads to, that neither task_id is retrievable nor unique submission is possible
                if not task_id:
                    task_id = await self.submit_file_for_analysis(raw_data, unique=False)

            logger.debug(f"Waiting for {task_id}")

            view_url = f"{self.cuckoo_url}/tasks/view/{task_id}"
            is_reported = False

            while not is_reported:
                async with aiohttp.ClientSession() as session:
                    logger.debug(f"Checking, if task {task_id} is done")
                    async with session.get(view_url) as resp:
                        status = resp.status
                        if status == 200:
                            resp = await resp.text()
                            report = json.loads(resp)
                            is_reported = True if report['task']['status'] == self.reported else False

                        await asyncio.sleep(self.cuckoo_retry)

            report = await self.retrieve_report(task_id)
            logger.debug(f"Task '{task_id}' is done.")

        return report

    async def get_taskid_to_hash(self, sha256):
        url = f"{self.cuckoo_url}/files/view/sha256/{sha256}"

        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                resp = await resp.text()
                response_dict = json.loads(resp)
                sample_dict = response_dict.get("sample")
                if not sample_dict:
                    logger.debug(f"Could not find task ID to {sha256}, submit file first")
                    return None
                tasks = sample_dict.get("tasks")

                if len(tasks) > 0:
                    logger.debug(f"Task ID to {sha256} -> {tasks[0]}")
                    return tasks[0]

        return None

    async def retrieve_report(self, task_id):
        url = f"{self.cuckoo_url}/tasks/report/{task_id}"

        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                resp = await resp.text()
                report = json.loads(resp)
                logger.info(f"Task {task_id} is done")

        return report

    cuckoo_submit_endpoint = "/tasks/create/file"

    async def submit_file_for_analysis(self, data, unique=True):
        async with aiohttp.ClientSession() as session:
            url = f"{self.cuckoo_url}{self.cuckoo_submit_endpoint}"
            files = {'file': data, 'unique': str(unique)}

            async with session.post(url, data=files, ssl=None) as response:
                response = await response.text()
                response_dict = json.loads(response)
                task_id = response_dict.get("task_id")

                if task_id:
                    logger.info(f"Submitted task {task_id}")
                else:
                    logger.info(f"This file has already been submitted")

        return task_id

    def process_report(self, file, report):
        logger.debug(f"Processing report to {file.filename}")
        file.mal_score = report['info']['score']
        file.analysis_id = report['info']['id']
        ts = datetime.datetime.fromtimestamp(int(report['info']['started']))
        file.analysis_timestamp = ts

        # Process logged network connections
        hosts = self.extract_hosts_from_traffic(report, file.timestamp)

        # Extract separate DNS queries
        dns_hosts = self.extract_domains(report, file.timestamp)
        hosts.extend(dns_hosts)

        # Extract malconfscan result
        hosts_conf, urls, malware_name = self.extract_config(report, file.timestamp)
        file.family = malware_name if malware_name else "Unkown"

        for hc in hosts_conf:
            if hc not in hosts:
                hosts.append(hc)

        return file, [*hosts, *urls]

    def extract_domains(self, report, ts):
        dns_hosts = []

        for d in report['network']['domains']:
            hostname = d['domain']
            if hostname not in self.whitelist_domains:
                dns_hosts.append(
                    NetworkEntityFactory.get_from_hostname(hostname, EntityEnum.dns_query)
                )

        return dns_hosts

    def extract_hosts_from_traffic(self, report, timestamp):
        hosts = []
        host_entries = report['network'].get("hosts", [])

        for h in host_entries:
            if h not in self.whitelist_ips:

                tcps_conns = report['network'].get("tcp", [])
                for conn in tcps_conns:
                    if h == conn['dst']:
                        port = conn['dport']
                        hostname = self.search_hostname(report, h)
                        network_entity = NetworkEntityFactory.get_from_ip(
                            h, port, EntityEnum.malware_infrastructure, hostname, timestamp
                        )

                        if network_entity not in hosts:
                            hosts.append(network_entity)

                udp_conns = report['network'].get("udp", [])
                for conn in udp_conns:
                    if h == conn['dst']:
                        port = conn['dport']
                        hostname = self.search_hostname(report, h)
                        network_entity = NetworkEntityFactory.get_from_ip(
                            h, port, EntityEnum.malware_infrastructure, hostname, timestamp
                        )
                        if network_entity not in hosts:
                            hosts.append(network_entity)

        return hosts

    @staticmethod
    def search_hostname(report, ip):
        for d in report['network']['domains']:
            if d['ip'] == ip:
                return d['domain']

        for d in report['network']['https_ex']:
            if d['dst'] == ip and d['dst'] != d['host']:
                return d['host']

        for d in report['network']['http_ex']:
            if d['dst'] == ip and d['dst'] != d['host']:
                return d['host']

        return None

    @staticmethod
    def extract_config(report, timestamp):
        hosts = []
        urls = []
        memrep = report.get("memory", None)
        malware_name = None

        if memrep:
            malconfrep = memrep.get("malconfscan", None)
            if malconfrep:
                for data_elem in malconfrep['data']:
                    malconf_data = data_elem.get('malconf', dict())
                    for mc_elem in malconf_data:
                        for entry in mc_elem:
                            for k in entry.keys():
                                # Distincts between keys, malconfscan uses different names for different malware families

                                # C&C-IP-address
                                if "IP" in k:
                                    ip, port = entry[k].split(":")
                                    h = NetworkEntityFactory.get_from_ip(
                                        ip, int(port), EntityEnum.c2_server, timestamp
                                    )
                                    hosts.append(h)
                                # C&C-URL
                                elif "Server" in k:  # some C2 URL specified
                                    urls.append(Url(entry[k], category=EntityEnum.c2_server, timestamp=timestamp))
                                elif "Original URL" in k:
                                    urls.append(Url(entry[k], category=EntityEnum.c2_server, timestamp=timestamp))
                                elif "Setting URL" in k:
                                    urls.append(Url(entry[k], category=EntityEnum.c2_server, timestamp=timestamp))

                    malware_name = data_elem.get('malware_name', None)

        return hosts, urls, malware_name
