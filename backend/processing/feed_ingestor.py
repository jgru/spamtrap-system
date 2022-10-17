import asyncio
import logging
from abc import ABC, abstractmethod
import ssl

import hpfeeds.asyncio
import aio_pika

from datamodels import FeedMsg

logger = logging.getLogger(__name__)


class FeedIngestor(ABC):
    @abstractmethod
    async def ingest(self, queue):
        pass

    @staticmethod
    def get_feed_ingestor(**kwargs):
        _type = kwargs.pop("type", "rabbitmq")
        if _type == "rabbitmq":
            return RabbitMQFeedIngestor(**kwargs[_type])
        elif _type == "hpfeeds":
            return HpFeedIngestor(**kwargs[_type])


class RabbitMQFeedIngestor(FeedIngestor):
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

            async with connection:
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
            logger.error("Cancelled ingestion")
            self.enabled = False


class HpFeedIngestor(FeedIngestor):
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

        try:
            async with hpfeeds.asyncio.ClientSession(
                self.host, self.port, self.ident, self.secret, ssl=self.tls
            ) as client:
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
            logger.error("Cancelled ingestion")
            self.enabled = False
