import asyncio
import logging

from datamodels import File, Url
from .file_enricher import FileEnricher
from .url_enricher import UrlEnricher

logger = logging.getLogger(__name__)


class Enricher:
    def __init__(self, **kwargs):
        logger.info("Creating Enricher")
        self.file_enricher = FileEnricher(**kwargs["sandbox"])
        kwargs["thug"].pop("enabled")
        kwargs["thug"].pop("enrich")
        self.url_enricher = UrlEnricher(**kwargs["thug"])

        # Defines, which dataclass types will be enriched
        self.enrichers = {File: self.file_enricher, Url: self.url_enricher}
        self.enabled = False

    async def enrich_from_stream(self, read_queue, out_q):
        logger.info("Start enriching stream entries")
        self.enabled = True

        try:
            while self.enabled or read_queue.qsize() > 0:
                elem = await read_queue.get()
                cur_enricher = self.enrichers.get(type(elem))

                if cur_enricher:
                    enriched_elem, children = await cur_enricher.enrich(elem)

                    if enriched_elem:
                        await out_q.put((enriched_elem, children))

            read_queue.task_done()

        except asyncio.CancelledError as e:
            logger.info("Cancelled enriching")
