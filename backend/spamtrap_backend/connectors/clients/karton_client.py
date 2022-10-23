import asyncio
import concurrent.futures
import logging
from functools import partial

from karton.core import Config, Producer, Resource, Task

from ...datamodels import Email, File, asdict
from ..reporter.base_reporter import BaseReporter

logger = logging.getLogger(__name__)


class KartonReporter(BaseReporter):
    """Reporter component that receives extracted objects and checks
    if they should be pushed into Karton.
    """

    _type = "karton"

    def __init__(
        self,
        ini_file="./karton.ini",
        relevant_documents=[Email.__name__],
    ):
        self.ini_file = ini_file
        self.relevant_types = relevant_documents

        self.enabled = True
        self.loop = None
        self.karton = None

        logger.debug(f"Reporting {self.relevant_types} to Karton")

    async def prepare(self):
        self.loop = asyncio.get_running_loop()
        self.karton = Producer(
            config=Config(self.ini_file), identity="spamtrap-producer"
        )
        logger.info(f"Initialized reporting to Karton using {self.ini_file}")

    def submit(self, elem):
        assert type(elem).__name__ in [
            Email.__name__,
            File.__name__,
        ], f"Cannot handle {type(elem)}"

        payload = elem.data
        sha256 = elem.hash.sha256

        task = Task(
            headers={"type": "sample", "kind": "raw"},
            payload={"sample": Resource(sha256, payload)},
        )

        self.karton.send_task(task)
        logger.debug(f"Send task to Karton for {elem._id}")

    async def report(self, elem):
        """ """
        # Checks if the actual element should be sent to ES
        if type(elem).__name__ in self.relevant_types:
            with concurrent.futures.ThreadPoolExecutor() as pool:
                upload = partial(self.submit, elem)
                await self.loop.run_in_executor(pool, upload)
                logger.debug(f"Reported {type(elem)} to Karton")

        return True
