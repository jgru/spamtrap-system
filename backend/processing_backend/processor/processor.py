import asyncio
import concurrent.futures
import logging

from .baseprocessor import BaseProcessor

# Needed for population via BaseProcessor.__subclasses__()
from .dionaea_processor import DionaeaProcessor
from .mail_processor import MailProcessor

logger = logging.getLogger(__name__)


class Processor(object):
    THRESHOLD = 20
    TIMEOUT = 2

    def __init__(self, database):
        self.database = database
        self.decomposers = {}
        self.populate_decomposers()

        self.enabled = True

    def populate_decomposers(self):
        # Inspired by https://github.com/johnnykv/mnemosyne/blob/master/normalizer/normalizer.py
        # Gets all BaseProcessor subclasses, instantiates it and maps it to specified channel(s)
        for proc_subclass in BaseProcessor.__subclasses__():
            proc = proc_subclass()
            for channel in proc.channels:
                if channel in self.decomposers:
                    raise Exception(
                        f"Only one processor for each channel allowed. Conflicting on {channel}"
                    )
                else:
                    self.decomposers[channel] = proc
                    logger.info(f"Added processor for {channel}")

    async def decompose_from_stream(self, in_q, out_q):
        logger.info("Start processing stream entries")

        loop = asyncio.get_running_loop()

        try:
            while self.enabled:
                e = await in_q.get()
                logger.info(f"Processing {type(e)}")

                # Run slow, CPU-bound parsing on separate core
                with concurrent.futures.ProcessPoolExecutor() as executor:
                    print(e.channel)
                    proc = self.decomposers[e.channel]
                    parent, children = await loop.run_in_executor(
                        executor, proc.process, e
                    )

                    await out_q.put((parent, children))

                in_q.task_done()

        except asyncio.CancelledError as e:
            self.enabled = False

        logging.info("Cancelled processing")
