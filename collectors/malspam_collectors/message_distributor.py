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
    MAX_RETRIES = 10
    RETRY_INTERVAL = 1

    @abstractmethod
    def distribute_queued(self, queue):
        pass

    @staticmethod
    def get_distributor(_type, **kwargs):
        distributors = MessageDistributor.populate_distributors()

        return distributors[_type](**kwargs[_type])

    @staticmethod
    def populate_distributors():
        distributors = {}
        for md in MessageDistributor.__subclasses__():

            distributors |= {md._type: md}
        return distributors


class AMQPDistributor(MessageDistributor):
    _type = "amqp"

    def __init__(
        self,
        host="localhost",
        port=5671,
        vhost="/",
        ident="writer",
        secret="secret",
        exchange=["spam"],
        routing_key="spam.mails",
        tls=True,
        check_cert=True,
    ):
        logger.info("Created AMQP distributor")
        self.identity = ident
        self.host = host
        self.port = port
        self.vhost = vhost
        self.ident = ident
        self.secret = secret
        self.exchange = exchange
        self.routing_key = routing_key
        self.tls = tls
        self.check_cert = check_cert
        self.enabled = False

    async def establish_connection(self):
        ssl_options = None

        if self.tls:
            if self.check_cert:
                ssl_options = aio_pika.abc.SSLOptions(verify_ssl=ssl.CERT_REQUIRED)
            else:
                ssl_options = aio_pika.abc.SSLOptions(no_verify_ssl=ssl.CERT_REQUIRED)

        connection = None

        retries = 0

        while not connection and retries < self.MAX_RETRIES:
            retries += 1

            try:
                connection = await aio_pika.connect_robust(
                    host=self.host,
                    port=self.port,
                    login=self.ident,
                    password=self.secret,
                    vhost=self.vhost,
                    ssl=self.tls,
                    ssl_options=ssl_options,
                )
            except ConnectionError as e:
                logger.info(
                    f"Could not connect to {self.host}:{self.port}. "
                    f"Retrying {self.MAX_RETRIES-retries} times..."
                )
                logger.debug(e)
                await asyncio.sleep(self.RETRY_INTERVAL)

        assert (
            connection
        ), "Could connect to broker. Check its availability and certificate."

        return connection

    async def distribute_queued(self, queue):
        logging.info(f"Starting to distribute to {self.host}...")

        self.enabled = True
        connection = await self.establish_connection()
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
                logging.info(f"Distribution to {self.host} cancelled")

        logging.info(f"Stopped to distribute to {self.host}...")


class HpfeedsDistributor(MessageDistributor):
    _type = "hpfeeds"

    def __init__(
        self,
        host="0.0.0.0",
        port=10000,
        ident="writer",
        secret="secret",
        channels=["spam.mails"],
        tls=True,
    ):
        logger.info("Created Hpfeeds distributor")
        self.identity = ident
        self.broker = host
        self.port = port
        self.secret = secret
        self.channels = channels
        self.tls = tls
        self.enabled = False

    async def distribute_queued(self, queue):
        logging.info(f"Starting to distribute to {self.broker}...")
        self.enabled = True

        try:
            client = ClientSession(
                self.broker, self.port, self.identity, self.secret  # , ssl=self.tls
            )

            while self.enabled or queue.qsize() > 0:
                msg = await queue.get()
                for c in self.channels:
                    client.publish(c, msg)
                queue.task_done()

        except (asyncio.CancelledError, asyncio.exceptions.InvalidStateError) as e:
            logging.info(f"Cancelled distribution to {self.broker}")
            self.enabled = False

            # Note: `async with ... as client:' leads to dirty shutdown
            # if await client.when_connected():
            await client.close()

        logging.info(f"Stopped to distribute to {self.broker}...")
