import asyncio
import logging
import ssl
from abc import ABC, abstractmethod

import aio_pika
from hpfeeds.asyncio import ClientSession

logger = logging.getLogger(__name__)

aio_pika.logger.setLevel(logging.WARNING)
logging.getLogger("aiormq").setLevel(logging.ERROR)


class MessageDistributor(ABC):
    @abstractmethod
    def distribute_queued(self, queue):
        pass


class AMQPDistributor(MessageDistributor):
    def __init__(
        self,
        broker="localhost",
        port=5671,
        vhost="/",
        identity="writer",
        secret="secret",
        exchange=["spam"],
        routing_key="spam.mails",
    ):
        logger.info("Created AMQP distributor")
        self.identity = identity
        self.broker = broker
        self.port = port
        self.vhost = vhost
        self.secret = secret
        self.exchange = exchange
        self.routing_key = routing_key
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self.enabled = False

    async def distribute_queued(self, queue):
        logging.info(f"Starting to distribute to {self.broker}...")
        self.enabled = True
        connection = await aio_pika.connect_robust("amqp://guest:guest@localhost/")
        channel = await connection.channel()
        msg_exchange = await channel.declare_exchange(
            self.exchange,
            aio_pika.ExchangeType.TOPIC,
        )

        while self.enabled or queue.qsize() > 0:
            try:
                msg_data = await queue.get()
                message = aio_pika.Message(
                    body=msg_data,
                    delivery_mode=aio_pika.DeliveryMode.PERSISTENT,
                )
                await msg_exchange.publish(message, routing_key=self.routing_key)

            except asyncio.CancelledError:
                self.enabled = False
                connection.close()
                logging.info(f"Distribution to {self.broker} cancelled")

        logging.info(f"Stopped to distribute to {self.broker}...")


class HpfeedsDistributor(MessageDistributor):
    def __init__(
        self,
        broker="localhost",
        port=10000,
        identity="writer",
        secret="secret",
        channels=["spam.mails"],
    ):
        logger.info("Created Hpfeeds distributor")
        self.identity = identity
        self.broker = broker
        self.port = port
        self.secret = secret
        self.channels = channels
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self.enabled = False

    async def distribute_queued(self, queue):
        logging.info(f"Starting to distribute to {self.broker}...")
        self.enabled = True
        client = ClientSession(self.broker, self.port, self.identity, self.secret)

        while self.enabled or queue.qsize() > 0:

            try:
                msg = await queue.get()
                for c in self.channels:
                    client.publish(c, msg)

            except asyncio.CancelledError:
                self.enabled = False
                logging.info(f"Distribution to {self.broker} cancelled")

        logging.info(f"Stopped to distribute to {self.broker}...")
