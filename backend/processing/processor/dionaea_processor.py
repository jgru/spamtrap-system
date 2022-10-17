from datamodels import (
    FeedMsg,
    NetworkEvent,
    NetworkEntityFactory,
    Observer,
    EntityEnum,
    Network,
)
from .baseprocessor import BaseProcessor
import logging
import re

logger = logging.getLogger(__name__)
import base64


class DionaeaProcessor(BaseProcessor):
    channels = (
        "mwbinary.dionaea.sensorunique",
        "dionaea.shellcodeprofiles",
        "dionaea.connections",
        "dionaea.capture",
    )

    def process(self, entry: FeedMsg):

        logging.info(f"Processing {entry.channel}")
        print(entry.payload)
        if entry.channel == "dionaea.connections":
            return self.process_connection(entry)

        elif entry.channel == "dionaea.capture":
            return self.process_capture(entry)

    def process_connection(self, entry: FeedMsg):
        parsed = entry.payload
        src_ip = self.normalize_ip(parsed["remote_host"])
        dst_ip = "127.0.0.1"
        src = NetworkEntityFactory.get_from_ip(
            src_ip, parsed["remote_port"], EntityEnum.unspecified
        )
        dst = NetworkEntityFactory.get_from_ip(
            dst_ip, parsed["local_port"], EntityEnum.honeypot
        )
        proto = ""  # self.port_to_service(parsed['local_port'])

        n = NetworkEvent(
            timestamp=entry.timestamp,
            source=src,
            destination=dst,
            related=[src_ip, dst_ip],
            category=Network(proto),
            observer=Observer(name=entry.identifier, type="dionaea"),
        )

        return n, None

    def process_capture(self, entry: FeedMsg):
        logger.info("Capture")
        print(entry)
        d = entry.payload["binary_payload"]
        print(type(d))
        decoded = base64.b64decode(d.encode("utf-8"))
        print(decoded[:25])
        return self.process_connection(entry)

    def normalize_ip(self, ip):
        mat = re.match(r"[a-f0-9A-F:]+:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$", ip)
        if mat:
            return mat.group(1)
        else:
            return ip
