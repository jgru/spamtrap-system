import asyncio
import logging
import ssl
from abc import ABC, abstractmethod

import aio_pika
import hpfeeds.asyncio

from ..datamodels import FeedMsg

logger = logging.getLogger(__name__)

# Silence really verbose RabbitMQ connection logging
aio_pika.logger.setLevel(logging.WARNING)
logging.getLogger("aiormq").setLevel(logging.ERROR)


class MessageIngestor(ABC):
    MAX_RETRIES = 10
    RETRY_INTERVAL = 1

    @abstractmethod
    async def ingest(self, queue):
        pass

    @staticmethod
    def get_message_ingestor(**kwargs):
        _type = kwargs.pop("type", "rabbitmq")
        ingestors = MessageIngestor.populate_ingestors()
        return ingestors[_type](**kwargs[_type])

    @staticmethod
    def populate_ingestors():
        ingestors = {}
        for md in MessageIngestor.__subclasses__():
            ingestors |= {md._type: md}
        return ingestors


class AMQPIngestor(MessageIngestor):
    _type = "amqp"

    def __init__(
        self, ident, secret, host, port, vhost, exchange, routing_key, tls, check_cert
    ):

        self.ident = ident
        self.secret = secret
        self.host = host
        self.port = port
        self.vhost = vhost
        self.exchange = exchange
        self.routing_key = routing_key
        self.tls = tls
        self.check_cert = check_cert
        self.last_received = None

        self.enabled = False

    async def ingest(self, queue):
        self.enabled = True

        ssl_options = None

        if self.tls:
            if self.check_cert:
                ssl_options = aio_pika.abc.SSLOptions(verify_ssl=ssl.CERT_REQUIRED)
            else:
                ssl_options = aio_pika.abc.SSLOptions(no_verify_ssl=ssl.CERT_REQUIRED)

        connection = None

        try:
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
                except ConnectionError:
                    await asyncio.sleep(self.RETRY_INTERVAL)
                    pass

            channel = await connection.channel()
            topic_exchange = await channel.declare_exchange(
                self.exchange,
                aio_pika.ExchangeType.TOPIC,
            )
            rmq_queue = await channel.declare_queue(durable=True, auto_delete=True)

            await rmq_queue.bind(topic_exchange, routing_key=self.routing_key)
            await channel.set_qos(prefetch_count=1)

            async with rmq_queue.iterator() as queue_iter:
                async for message in queue_iter:
                    async with message.process():
                        feed_msg = FeedMsg(
                            self.ident, message.routing_key, message.body
                        )

                        logger.debug(f"Received feed msg {channel}")

                        if queue:
                            await queue.put(feed_msg)

        except asyncio.exceptions.CancelledError as e:
            self.enabled = False
            # aio_pika's async ctx manager does not call close()
            if connection:
                connection.close()
            logger.error("Cancelled ingestion")


class HpFeedIngestor(MessageIngestor):
    _type = "hpfeeds"

    def __init__(self, ident, secret, host, port, channels, tls):
        self.ident = ident
        self.secret = secret
        self.port = port
        self.host = host
        self.channels = channels
        self.tls = tls
        self.last_received = None

        self.enabled = False

    async def ingest(self, queue):
        self.enabled = True
        client = None

        try:
            client = hpfeeds.asyncio.ClientSession(
                self.host, self.port, self.ident, self.secret, ssl=self.tls
            )
            logger.info(f"Connected to {self.host} on port {self.port}")

            for f in self.channels:
                logger.info(f"Subcribing for {f}")
                client.subscribe(f)

            async for ident, channel, payload in client:
                if not any(x in channel for x in (";", '"', "{", "}")):
                    feed_msg = FeedMsg(ident, channel, payload)
                    logger.debug(f"Received feed msg {channel}")
                    if queue:
                        await queue.put(feed_msg)

        except asyncio.exceptions.CancelledError as e:
            logger.error(f"Cancelled hpfeeds ingestion from {self.host}")
            self.enabled = False

            # Note: `async with ... as client:' leads to dirty shutdown
            if await client.when_connected():
                await client.close()
