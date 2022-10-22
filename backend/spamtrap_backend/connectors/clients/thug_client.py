import asyncio
import base64
import datetime
import json
import logging
from hashlib import sha512
from uuid import uuid4

import aio_pika
from aio_pika.message import IncomingMessage, Message

from ...datamodels import Extraction, File, Hash, Url

logger = logging.getLogger(__name__)

# Silence really verbose RabbitMQ connection logging
aio_pika.logger.setLevel(logging.WARNING)
logging.getLogger("aiormq").setLevel(logging.ERROR)


class ThugdClient:
    def __init__(
        self,
        host,
        port,
        vhost,
        user,
        secret,
        job_queue="rpc.server.queue",
        timeout=30,
        referrer="https://google.com",
        tls=False,
        check_cert=False,
    ):
        "docstring"
        self.thugd_rmq_host = host
        self.thugd_rmq_port = port
        self.thugd_job_queue = job_queue
        self.thugd_rmq_user = user
        self.thugd_rmq_pass = secret
        self.thugd_rmq_vhost = vhost
        self.thugd_timeout = str(timeout)
        self.thugd_referrer = referrer

        self.tls = False
        self.check_cert = False

        self.connection = None
        self.done = False
        self.reply_queue = str(uuid4())
        self.wait_interval = 0.5
        self.cur_report = {}

        logger.info("Intitialized Thugd Client")

    async def prepare(self):
        self.loop = asyncio.get_running_loop()

        ssl_options = None

        if self.tls:
            if self.check_cert:
                ssl_options = aio_pika.abc.SSLOptions(verify_ssl=ssl.CERT_REQUIRED)
            else:
                ssl_options = aio_pika.abc.SSLOptions(no_verify_ssl=ssl.CERT_REQUIRED)

        try:
            return await aio_pika.connect_robust(
                host=self.thugd_rmq_host,
                port=self.thugd_rmq_port,
                login=self.thugd_rmq_user,
                password=self.thugd_rmq_pass,
                vhost=self.thugd_rmq_vhost,
                ssl=self.tls,
                ssl_options=ssl_options,
            )

        except aio_pika.exceptions.AMQPConnectionError as e:
            logger.error("Could not connect to Thugd")

        return None

    async def on_message(self, message: IncomingMessage):
        if message.body != b"":
            self.cur_report = json.loads(message.body.decode())

        self.done = True

    async def submit(self, url):
        self.done = False

        if not self.connection:
            self.connection = await self.prepare()

        channel = await self.connection.channel()
        queue = await channel.declare_queue(self.reply_queue)
        await queue.consume(
            self.on_message,
            no_ack=True,
        )
        job = {
            "url": url.url,
            "timeout": self.thugd_timeout,
            "referrer": self.thugd_referrer,
        }

        req = json.dumps(job).encode()

        await channel.default_exchange.publish(
            Message(body=req, reply_to=self.reply_queue),
            routing_key=self.thugd_job_queue,
        )

        while not self.done:
            await asyncio.sleep(self.wait_interval)

        return self.cur_report

    @classmethod
    def process_report(cls, url, result_dict):
        files = []

        if result_dict:
            logger.info(f"Processing Thug result to {url}")

            # Retrieve analysis timestamp and make it timezone aware
            d = datetime.datetime.strptime(
                result_dict["timestamp"], "%Y-%m-%d %H:%M:%S.%f"
            )
            url.analysis_timestamp = d.astimezone(datetime.timezone.utc)

            # Record exploits
            exploits = result_dict.get("exploits", [])
            if len(exploits):
                for e in exploits:
                    url.exploits.append(e)

            if len(result_dict["files"]):

                for entry in result_dict["files"]:
                    blob, hash = cls.extract_data(entry)

                    file = File(
                        content_guess=entry["type"].lower(),
                        encoding="application/octet-stream",
                        filename=cls.get_filename(entry),
                        hash=hash,
                        data=blob,
                        timestamp=url.analysis_timestamp,
                    )

                    files.append(file)

                    # Add extraction, which references actual file
                    url.extractions.append(
                        Extraction(
                            description=file.filename,
                            hash=file.hash,
                            content_guess=file.content_guess,
                        )
                    )

        return url, files

    @staticmethod
    def get_filename(file_entry):
        try:
            filename = file_entry["url"].split("/")[-1]
        except BaseException:
            filename = file_entry["sha256"]

        return filename

    @classmethod
    def extract_data(cls, entry):
        blob = base64.b64decode(entry["data"])
        hash = cls.build_hash(entry, blob)

        return blob, hash

    @staticmethod
    def build_hash(file_entry, blob):
        sha512_digest = sha512(blob).hexdigest()

        return Hash(
            md5=file_entry["md5"],
            sha1=file_entry["sha1"],
            sha256=file_entry["sha256"],
            sha512=sha512_digest,
        )
