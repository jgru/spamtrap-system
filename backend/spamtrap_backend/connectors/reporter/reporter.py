import asyncio
import logging

from ...datamodels import File, Url

# Needed for population via BaseReporter.__subclasses__()
from ..clients.cuckoo_client import Cuckoo
from ..clients.elastic_client import ElasticReporter
from ..clients.hatching_triage_client import HatchingTriage
from ..clients.karton_client import KartonReporter
from ..clients.misp_client import MISPReporter
from ..clients.thug_client import ThugdClient
from .base_reporter import BaseReporter

# from ..clients.sandbox_client import SandboxConnector


logger = logging.getLogger(__name__)


class Reporter:
    def __init__(self, **kwargs):
        logger.info("Creating Reporter")

        self.reporters = self.populate_reporters(**kwargs)
        self.enabled = False
        logger.debug(BaseReporter.all_subclasses())

    def populate_reporters(self, **kwargs):
        active_reporters = [
            r(**kwargs[r._type])
            for r in BaseReporter.all_subclasses()
            # for k in kwargs.keys()
            if kwargs.get(r._type) and kwargs[r._type].pop("enabled")
        ]

        logger.info(f"Active reporters {active_reporters}")

        return active_reporters

    async def spawn_reporting_tasks(self):
        # Create respective queues and spawn a background task for
        # each reporter
        queues = {}
        loop = asyncio.get_running_loop()

        for reporter in self.reporters:
            await reporter.prepare()
            q = asyncio.Queue()
            queues[reporter] = q
            loop.create_task(reporter.run_reporting(q))

        return queues

    async def report_from_stream(self, read_queue):
        self.enabled = True

        if len(self.reporters) == 0:
            logger.info("There are no configured reporters. Exiting reporting.")
            return

        queues = await self.spawn_reporting_tasks()

        try:
            logger.info("Start to report stream entries")

            while self.enabled or read_queue.qsize() > 0:
                result = False
                elem = await read_queue.get()

                for r, q in queues.items():
                    if type(elem).__name__ in r.relevant_documents:
                        await q.put(elem)

                read_queue.task_done()

        except asyncio.CancelledError as e:
            logger.info("Cancelled enriching")
