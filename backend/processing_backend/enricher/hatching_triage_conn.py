import asyncio
import datetime
import json
import logging
from typing import List, Tuple, Union

import aiohttp
import validators
from datamodels import EntityEnum, File, Hash, NetworkEntity, NetworkEntityFactory, Url

from . import utils
from .sandbox_conn import SandboxConnector

logger = logging.getLogger(__name__)


class HatchingTriage(SandboxConnector):
    _type = "hatching"

    def __init__(self, token, host="api.tria.ge", timeout=15):

        self.token = token
        self.url = f"https://{host.rstrip('/')}"

        self.timeout = timeout
        self.retry = 1

        print(f"Using {self.url} with a timeout of " f"{self.timeout} secs.")

        self.headers = {"Authorization": "Bearer {:s}".format(token)}

    async def get_sample_id_to_hash(self, sha256):
        url = f"{self.url}/v0/search?query=sha256:{sha256}"

        async with aiohttp.ClientSession(headers=self.headers) as session:
            async with session.get(url) as resp:
                resp = await resp.text()
                response_dict = json.loads(resp)

                sample_dict = response_dict.get("data")
                if not sample_dict:
                    logger.debug(
                        f"Could not find sample ID to {sha256}, submit file first"
                    )
                    return None
                tasks = [entry.get("id") for entry in sample_dict]

                if len(tasks) > 0:
                    logger.debug(f"Task ID to {sha256} -> {tasks[-1]}")
                    return tasks[-1]

        return None

    async def analyze_file(self, file: File):
        report = None
        raw_data = file.blob

        # Check if file has already been submitted
        sample_id = await self.get_sample_id_to_hash(file.hash.sha256)

        if not sample_id:
            sample_id = await self.submit_file_for_analysis(file.filename, raw_data)
            found = self.wait_for_report(sample_id)

        report = await self.retrieve_report(sample_id)
        logger.debug(f"Task '{sample_id}' is done.")

        return report

    async def wait_for_report(self, sample_id, max_tries=50):
        logger.debug(f"Waiting for {sample_id}")

        url = f"{self.url}/v0/samples/{sample_id}"
        is_reported = False
        tries = 0
        while not is_reported:
            async with aiohttp.ClientSession(headers=self.headers) as session:
                logger.debug(f"Checking, if task {sample_id} is done")
                tries += 1
                async with session.get(url) as resp:
                    status = resp.status
                    if status == 200:
                        resp = await resp.json()
                        if "status" in resp.keys():
                            is_reported = (
                                True if resp["status"] == "reported" else False
                            )
                        if tries > max_tries:
                            return False
                    await asyncio.sleep(self.retry)
        return True

    async def retrieve_report(self, _id: int):
        url = self.url + f"/v1/samples/{_id}/overview.json"

        async with aiohttp.ClientSession(headers=self.headers) as session:
            async with session.get(url) as resp:
                resp = await resp.text()
                report = json.loads(resp)
                print(f"Task {_id} is done")

        return report

    def process_report(self, file, report):
        logger.debug(f"Processing report to {file.filename}")
        file.mal_score = report["sample"]["score"]
        file.analysis_id = report["sample"]["id"]
        ts = datetime.datetime.strptime(
            report["sample"]["completed"], "%Y-%m-%dT%H:%M:%SZ"
        )
        file.analysis_timestamp = ts

        hosts = []
        malware_names = []

        # Read malware name from config
        extractions = report.get("extracted")
        if extractions:
            for e in extractions:
                conf = e.get("config")
                if conf:
                    malware_names.append(conf.get("family"))

        # Read hosts from config and network traffic
        hosts = self.extract_hosts_from_config(report, ts)

        file.family = " ".join(malware_names) if len(malware_names) else "Unkown"

        return file, hosts

    def extract_hosts_from_config(self, report, timestamp):
        # Process logged network connections
        hosts = []
        for t in report["targets"]:
            iocs = t.get("iocs")
            if not iocs:
                continue
            else:
                if iocs.get("ips"):
                    for ip in iocs["ips"]:
                        h = NetworkEntityFactory.get_from_ip(
                            ip,
                            None,
                            EntityEnum.malware_infrastructure,
                            timestamp=timestamp,
                        )

                        hosts.append(h)

        extracted = report.get("extracted")

        for elem in extracted:
            config = elem.get("config")

            # All done
            if not config:
                continue

            # Process config
            c2s = config["c2"] if config.get("c2") else []

            for c2 in c2s:
                logger.debug(c2)
                if validators.url(c2):
                    u = Url(
                        c2,
                        category=EntityEnum.c2_server,
                        timestamp=timestamp,
                    )
                    hosts.append(u)
                else:
                    ip, port = c2.rsplit(":", 1)
                    h = NetworkEntityFactory.get_from_ip(
                        ip, int(port), EntityEnum.c2_server, timestamp=timestamp
                    )

                    hosts.append(h)

        return hosts

    async def submit_file_for_analysis(self, filename, data):

        url = f"{self.url}/v0/samples"
        _json = {
            "_json": json.dumps({"kind": "file", "interactive": False, "profiles": []})
        }
        files = {"file": data, "filename": filename}
        async with aiohttp.ClientSession(headers=self.headers) as session:
            async with session.post(url, data=files, params=_json) as response:
                response = await response.json()
                return response["id"]
