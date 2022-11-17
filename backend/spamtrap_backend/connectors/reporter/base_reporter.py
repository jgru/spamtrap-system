import asyncio
import logging
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class BaseReporter(ABC):
    """
    Interface specifying methods, which every reporter component has to provide
    """

    _type = "abstract"

    MAX_TASKS = 15
    INTERVAL = 1e-3  # 5 ms sleep
    IS_THROTTLE = True

    def __init__(self):
        "docstring"
        self.tasks = set()
        self.read_queue = None

    @abstractmethod
    async def prepare(self):
        pass

    @abstractmethod
    async def report(self, obj):
        pass

    def task_done_callback(self, fut):
        """Callback that is run after enriching finished.

        Note this has to be synchronous which is why we need
        `forward_results' to place the results on the output queue in
        an async manner.

        """
        if not fut.cancelled() and fut.done():
            res = fut.result()

            if res:
                self.read_queue.put_nowait(res)
                logger.info(
                    f"Enqueuing {res._id} again, because parent object "
                    "has not been reported yet"
                )
        else:
            logger.debug(f"Task {fut.get_name()} could not be reported")

        self.tasks.discard(fut)

    async def run_reporting(self, read_queue):
        self.enabled = True
        self.read_queue = read_queue

        try:
            logger.info(f"Start to report stream entries for {self._type}")

            while self.enabled or read_queue.qsize() > 0:

                # Do not flood the event loop with too many tasks from one reporter
                while self.IS_THROTTLE and len(self.tasks) > self.MAX_TASKS:
                    await asyncio.sleep(self.INTERVAL)

                elem = await read_queue.get()

                t = asyncio.create_task(
                    self.report(elem),
                    name=f"{elem}",
                )
                self.tasks.add(t)
                t.add_done_callback(self.task_done_callback)

                read_queue.task_done()

        except asyncio.CancelledError as e:
            logger.info("Cancelled enriching")

    @classmethod
    def all_subclasses(cls):
        """Finds all subclasses recursively. Ensure they are imported
        _before_ calling this classmethod.

        """
        return _all_subclasses(cls)


def _all_subclasses(cls):
    return set(cls.__subclasses__()).union(
        [s for c in cls.__subclasses__() for s in _all_subclasses(c)]
    )
