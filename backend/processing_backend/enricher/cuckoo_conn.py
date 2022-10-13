import asyncio
import datetime
import json
import logging
from typing import List, Tuple, Union

import aiohttp
from datamodels import (EntityEnum, File, Hash, NetworkEntity,
                        NetworkEntityFactory, Url)

from . import utils
from .sandbox_conn import SandboxConnector

logger = logging.getLogger(__name__)


class Cuckoo(SandboxConnector):
    _type = "cuckoo"
    reported = "reported"
    cuckoo_report_endpoint = "/tasks/create/file"

    def __init__(
        self,
        host="localhost",
        port=None,
        timeout=15,
        whitelist_ips=None,
        whitelist_domains=None,
    ):
        "Create a Cuckoo connector"
        self.cuckoo_host = host
        self.cuckoo_port = port
        self.url = (
            f"http://{self.cuckoo_host}"
            if not self.cuckoo_port or self.cuckoo_port == ""
            else f"http://{self.cuckoo_host}:{self.cuckoo_port}"
        )

        self.timeout = timeout
        self.retry = 1

        logger.info(f"Using {self.url} with a timeout of " f"{self.timeout} secs.")

        # For filtering OS noise
        self.whitelist_ips = utils.read_whitelist(whitelist_ips)
        self.whitelist_domains = utils.read_whitelist(whitelist_domains)

    async def analyze_file(self, file: File):
        report = None
        raw_data = file.blob
        task_id = await self.submit_file_for_analysis(raw_data)

        if not task_id:  # "message": "This file has already been submitted"
            task_id = await self.get_taskid_to_hash(file.hash.sha256)

            # Handles rare edge case, when exe was submitted inside
            # archive. This leads to that neither task_id is
            # retrievable nor unique submission is possible
            if not task_id:
                task_id = await self.submit_file_for_analysis(raw_data, unique=False)

        logger.debug(f"Waiting for {task_id}")

        view_url = f"{self.url}/tasks/view/{task_id}"
        is_reported = False

        while not is_reported:
            async with aiohttp.ClientSession() as session:
                logger.debug(f"Checking, if task {task_id} is done")
                async with session.get(view_url) as resp:
                    status = resp.status
                    if status == 200:
                        resp = await resp.text()
                        report = json.loads(resp)
                        is_reported = (
                            True if report["task"]["status"] == self.reported else False
                        )

                    await asyncio.sleep(self.retry)

            report = await self.retrieve_report(task_id)
            logger.debug(f"Task '{task_id}' is done.")

        return report

    async def get_taskid_to_hash(self, sha256):
        url = f"{self.url}/files/view/sha256/{sha256}"

        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                resp = await resp.text()
                response_dict = json.loads(resp)
                sample_dict = response_dict.get("sample")
                if not sample_dict:
                    logger.debug(
                        f"Could not find task ID to {sha256}, submit file first"
                    )
                    return None
                tasks = sample_dict.get("tasks")

                if len(tasks) > 0:
                    logger.debug(f"Task ID to {sha256} -> {tasks[-1]}")
                    return tasks[-1]

        return None

    async def retrieve_report(self, task_id: int):
        url = f"{self.url}/tasks/report/{task_id}"

        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                resp = await resp.text()
                report = json.loads(resp)
                logger.info(f"Task {task_id} is done")

        return report

    cuckoo_submit_endpoint = "/tasks/create/file"

    async def submit_file_for_analysis(self, data, unique=True):
        async with aiohttp.ClientSession() as session:
            url = f"{self.url}{self.cuckoo_submit_endpoint}"
            files = {"file": data, "unique": str(unique)}

            async with session.post(url, data=files, ssl=None) as response:
                response = await response.text()
                response_dict = json.loads(response)
                task_id = response_dict.get("task_id")

                if task_id:
                    logger.info(f"Submitted task {task_id}")
                else:
                    logger.info(f"This file has already been submitted")

        return task_id

    def process_report(self, _file, report):
        logger.debug(f"Processing report to {_file.filename}")
        _file.mal_score = report["info"]["score"]
        _file.analysis_id = report["info"]["id"]
        ts = datetime.datetime.fromtimestamp(int(report["info"]["started"]))
        _file.analysis_timestamp = ts

        # Process logged network connections
        hosts = self.extract_hosts_from_traffic(report, _file.timestamp)

        # Extract separate DNS queries
        dns_hosts = self.extract_domains(report, _file.timestamp)
        hosts.extend(dns_hosts)

        # Extract malconfscan result
        hosts_conf, urls, malware_name = self.extract_config(report, _file.timestamp)
        _file.family = malware_name if malware_name else "Unkown"

        for hc in hosts_conf:
            if hc not in hosts:
                hosts.append(hc)

        return _file, [*hosts, *urls]

    def extract_domains(self, report, ts):
        dns_hosts = []

        for d in report["network"]["domains"]:
            hostname = d["domain"]
            if hostname not in self.whitelist_domains:
                dns_hosts.append(
                    NetworkEntityFactory.get_from_hostname(
                        hostname, EntityEnum.dns_query
                    )
                )

        return dns_hosts

    def extract_hosts_from_traffic(self, report, timestamp):
        hosts = []
        host_entries = report["network"].get("hosts", [])

        for h in host_entries:
            if h not in self.whitelist_ips:

                tcps_conns = report["network"].get("tcp", [])
                for conn in tcps_conns:
                    if h == conn["dst"]:
                        port = conn["dport"]
                        hostname = self.search_hostname(report, h)
                        network_entity = NetworkEntityFactory.get_from_ip(
                            h,
                            port,
                            EntityEnum.malware_infrastructure,
                            hostname,
                            timestamp,
                        )

                        if network_entity not in hosts:
                            hosts.append(network_entity)

                udp_conns = report["network"].get("udp", [])
                for conn in udp_conns:
                    if h == conn["dst"]:
                        port = conn["dport"]
                        hostname = self.search_hostname(report, h)
                        network_entity = NetworkEntityFactory.get_from_ip(
                            h,
                            port,
                            EntityEnum.malware_infrastructure,
                            hostname,
                            timestamp,
                        )
                        if network_entity not in hosts:
                            hosts.append(network_entity)

        return hosts

    @staticmethod
    def search_hostname(report, ip):
        for d in report["network"]["domains"]:
            if d["ip"] == ip:
                return d["domain"]

        for d in report["network"]["https_ex"]:
            if d["dst"] == ip and d["dst"] != d["host"]:
                return d["host"]

        for d in report["network"]["http_ex"]:
            if d["dst"] == ip and d["dst"] != d["host"]:
                return d["host"]

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
                for data_elem in malconfrep["data"]:
                    malconf_data = data_elem.get("malconf", dict())
                    for mc_elem in malconf_data:
                        for entry in mc_elem:
                            for k in entry.keys():
                                # Distincts between keys, malconfscan
                                # uses different names for different
                                # malware families

                                # C&C-IP-address
                                if "IP" in k:
                                    ip, port = entry[k].split(":")
                                    h = NetworkEntityFactory.get_from_ip(
                                        ip, int(port), EntityEnum.c2_server, timestamp
                                    )
                                    hosts.append(h)
                                # C&C-URL
                                elif "Server" in k:  # some C2 URL specified
                                    urls.append(
                                        Url(
                                            entry[k],
                                            category=EntityEnum.c2_server,
                                            timestamp=timestamp,
                                        )
                                    )
                                elif "Original URL" in k:
                                    urls.append(
                                        Url(
                                            entry[k],
                                            category=EntityEnum.c2_server,
                                            timestamp=timestamp,
                                        )
                                    )
                                elif "Setting URL" in k:
                                    urls.append(
                                        Url(
                                            entry[k],
                                            category=EntityEnum.c2_server,
                                            timestamp=timestamp,
                                        )
                                    )

                    malware_name = data_elem.get("malware_name", None)

        return hosts, urls, malware_name
