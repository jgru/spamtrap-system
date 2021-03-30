import asyncio
import logging
import sys

from hpfeeds.asyncio import ClientSession

from datamodels import FeedMsg

logger = logging.getLogger(__name__)


class HpFeedIngestor(object):

    def __init__(self, ident, secret, host, port, channels, tls):
        self.ident = ident
        self.secret = secret
        self.port = port
        self.host = host
        self.channels = channels
        self.tls = tls
        self.last_received = None
        self.hpc = None
        self.is_stopped = True
        self.enabled = False

    async def start_ingesting(self, queue):

        client = ClientSession(self.host, self.port, self.ident, self.secret, ssl=self.tls)

        logger.info(f"Connecting to {self.host} on port {self.port}")

        for f in self.channels:
            logger.info(f"subcribing for {f}")
            client.subscribe(f)

        try:
            async for ident, channel, payload in client:
                if not any(x in channel for x in (';', '"', '{', '}')):
                    feed_msg = FeedMsg(ident, channel, payload)
                    logger.debug(f"Received feed msg {channel}")
                    if queue:
                        await queue.put(feed_msg)

        except asyncio.exceptions.CancelledError as e:
            logger.error(e)
            logger.error("Cancelled ingestion")
            sys.exit(1)

