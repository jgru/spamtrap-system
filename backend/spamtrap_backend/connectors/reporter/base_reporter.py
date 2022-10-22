from abc import ABC, abstractmethod


class BaseReporter(ABC):
    """
    Interface specifying methods, which every reporter component has to provide
    """

    _type = "abstract"

    @abstractmethod
    async def prepare_reporting(self):
        pass

    @abstractmethod
    async def report(self, obj):
        pass
