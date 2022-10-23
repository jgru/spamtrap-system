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

    async def report_from_stream(self, read_queue):
        self.enabled = True
        if len(self.reporters) == 0:
            logger.info("There are no configured reporters. Exiting reporting.")
            return

        try:
            logger.info("Start to report stream entries")

            # Establish async connections
            for reporter in self.reporters:
                await reporter.prepare_reporting()

            while self.enabled or read_queue.qsize() > 0:
                result = False
                elem = await read_queue.get()

                # FIXME: Parallelize this potentially to service
                # multiple reporting systems concurrently; either
                # spawn tasks and/or introduce respective queues
                for reporter in self.reporters:
                    result = await reporter.report(elem)

                # Enqueue again (parent objects have not been been reported yet
                if not result:
                    logger.info(
                        f"Enqueuing {elem._id} again, because parent object "
                        "has not been reported yet"
                    )
                    await read_queue.put(elem)
                else:
                    logger.debug(f"Reported {type(elem)}")

                read_queue.task_done()

        except asyncio.CancelledError as e:
            logger.info("Cancelled enriching")
