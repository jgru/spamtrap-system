import asyncio
import email
import json
import logging
from email import policy
from hashlib import sha256

from hpfeeds.asyncio import ClientSession

logger = logging.getLogger()


class HpfeedsDistributor:

    def __init__(self, broker="localhost", port=20000, tls=True, identity="writer", secret="secret",
                 channels=["spam.mails"]):
        logger.info("Created distributor")
        self.identity = identity
        self.broker = broker
        self.port = port
        self.secret = secret
        self.channels = channels
        self.enabled = False
        self.tls_enabled = tls

    @staticmethod
    def construct_hpfeeds_msg(msg):
        # logger.info(f'Construction msg')
        msg_digest = sha256(msg).hexdigest()

        msg_dict = {
            "msg": msg.decode("utf-8"),
            'sha256': msg_digest
        }

        return json.dumps(msg_dict)

    async def distribute_queued(self, queue):
        logging.info(f"Starting to distribute to {self.broker}:{self.port}...")
        self.enabled = True

        if self.tls_enabled:
            # create default SSL context, which requires valid cert chain
            client = ClientSession(self.broker, self.port, self.identity, self.secret, ssl=self.tls_enabled)
        else:
            client = ClientSession(self.broker, self.port, self.identity, self.secret)

        while self.enabled or queue.qsize() > 0:
            # logging.info(f"Created distributor {self.broker}...")
            try:
                msg = await queue.get()
                msg_as_json = self.construct_hpfeeds_msg(msg)
                for c in self.channels:
                    client.publish(c, msg_as_json)

            except asyncio.CancelledError:
                self.enabled = False
                logging.debug(f"Distribution to {self.broker} cancelled")

        logging.debug(f"Stopped to distribute to {self.broker}...")
