import asyncio
import logging
from abc import ABC, abstractmethod

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
            async with ClientSession(
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
