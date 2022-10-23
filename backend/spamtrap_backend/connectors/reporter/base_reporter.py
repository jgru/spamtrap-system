import asyncio
import logging
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class BaseReporter(ABC):
    """
    Interface specifying methods, which every reporter component has to provide
    """

    _type = "abstract"

    @abstractmethod
    async def prepare(self):
        pass

    @abstractmethod
    async def report(self, obj):
        pass

    async def run_reporting(self, read_queue):
        self.enabled = True
        try:
            logger.info(f"Start to report stream entries for {self._type}")

            while self.enabled or read_queue.qsize() > 0:
                result = False
                elem = await read_queue.get()

                result = await self.report(elem)

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
