import asyncio
import logging
from threading import activeCount

from datamodels import File, Url
from processing_backend.reporter.base_reporter import BaseReporter
from processing_backend.reporter.elastic_reporter import ElasticReporter
from processing_backend.reporter.misp_reporter import MISPReporter

logger = logging.getLogger(__name__)

# Needed for population via BaseReporter.__subclasses__()
from .elastic_reporter import ElasticReporter
from .misp_reporter import MISPReporter


class Reporter:
    def __init__(self, **kwargs):
        logger.info("Creating Reporter")
        self.reporters = self.populate_reporters(**kwargs)
        self.enabled = False

    def populate_reporters(self, **kwargs):
        logger.info("Populating reporters")

        active_reporters = [
            r(**kwargs[r._type])
            for r in BaseReporter.__subclasses__()
            # for k in kwargs.keys()
            if kwargs.get(r._type) and kwargs[r._type].pop("enabled")
        ]

        logger.info(active_reporters)

        return active_reporters

    async def report_from_stream(self, read_queue):
        logger.info("Start to report stream entries")
        self.enabled = True

        try:
            # Establish async connections
            for reporter in self.reporters:
                await reporter.prepare_reporting()

            while self.enabled or read_queue.qsize() > 0:
                result = False
                elem = await read_queue.get()

                for reporter in self.reporters:
                    result = await reporter.report(elem)

                # Enqueue again (parent objects have not been been reported yet
                if not result:
                    logger.info(
                        f"Enqueuing {elem._id} again, because parent objects "
                        "has not been been reported yet"
                    )
                    read_queue.put(elem)


                read_queue.task_done()

        except asyncio.CancelledError as e:
            logger.info("Cancelled enriching")
