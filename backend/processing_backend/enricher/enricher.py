import asyncio
import logging
import sys

from datamodels import File, Url
from processing_backend.enricher.file_enricher import FileEnricher
from processing_backend.enricher.url_enricher import UrlEnricher

logger = logging.getLogger(__name__)


class Enricher:

    def __init__(self, database, **kwargs):
        logger.info("Creating Enricher")
        self.database = database
        self.file_enricher = FileEnricher(database, **kwargs['cuckoo'])
        self.url_enricher = UrlEnricher(database, **kwargs['thug'])

        # Defines, which dataclass types will be enriched
        self.enrichers = {File: self.file_enricher, Url: self.url_enricher}

        self.enabled = False
        self.is_stopped = True

    async def enrich_from_stream(self, read_queue, out_q):
        logger.info("Start enriching stream entries")
        self.enabled = True

        try:
            while self.enabled or read_queue.qsize() > 0:
                elem = await read_queue.get()
                logger.info(f"Enriching {type(elem)}")

                enriched_elem, children = await self.enrichers[type(elem)].enrich(elem)

                if enriched_elem:
                    await out_q.put((enriched_elem, children))

            read_queue.task_done()

        except asyncio.CancelledError as e:
            logger.debug(e)
            self.enabled = False
            self.is_stopped = True
            logger.info("Cancelled enriching")
            sys.exit(0)
