import asyncio
import logging

from ...datamodels import File, Url
from ..clients.sandbox_client import populate_sandboxes
from .file_enricher import FileEnricher
from .url_enricher import UrlEnricher

logger = logging.getLogger(__name__)


class Enricher:
    MAX_TASKS = 2500
    INTERVAL = 1
    IS_THROTTLE = True

    def __init__(self, **kwargs):
        logger.info("Creating Enricher")

        # Defines, which dataclass types will be enriched
        self.enrichers = {}

        # Take the first available sandbox definition
        for t in populate_sandboxes():
            if kwargs.get(t) and kwargs[t].pop("enrich") and kwargs[t].pop("enabled"):
                for f in kwargs[t].get("relevant_documents"):
                    logger.info(f"Using {t} sandbox for enriching for {f}")
                    self.enrichers |= {f: FileEnricher(t, **kwargs[t])}
                break

        if kwargs.get("thug"):
            kwargs["thug"].pop("enabled")
            kwargs["thug"].pop("enrich")
            for f in kwargs["thug"].get("relevant_documents"):
                self.enrichers |= {f: UrlEnricher(**kwargs["thug"])}

        self.enabled = False
        self.tasks = set()
        self.results = asyncio.Queue()

    def task_done_callback(self, fut):
        """Callback that is run after enriching finished.

        Note this has to be synchronous which is why we need
        `forward_results' to place the results on the output queue in
        an async manner.

        """
        if not fut.cancelled() and fut.done():
            self.results.put_nowait(fut.result())
        else:
            logger.debug(f"Task {fut.get_name()} did not bring up results")

        self.tasks.discard(fut)

    async def enrich_from_stream(self, read_queue, out_q):
        logger.info("Start enriching stream entries")
        self.enabled = True

        self.results = out_q
        try:
            while self.enabled or read_queue.qsize() > 0:
                elem = await read_queue.get()
                cur_enricher = self.enrichers.get(type(elem).__name__)

                if cur_enricher:
                    logger.info(
                        f"Spawning background task for "
                        f"{elem.url if isinstance(elem, Url) else elem.hash.sha256} "
                    )

                    # Do not flood the event loop many tasks
                    while self.IS_THROTTLE and len(self.tasks) > self.MAX_TASKS:
                        await asyncio.sleep(self.INTERVAL)

                    t = asyncio.create_task(
                        cur_enricher.enrich(elem),
                        name=f"{elem.url if isinstance(elem, Url) else elem.hash.sha256}",
                    )
                    self.tasks.add(t)
                    t.add_done_callback(self.task_done_callback)

                read_queue.task_done()

        except asyncio.CancelledError as e:
            logger.info("Cancelled enriching")
