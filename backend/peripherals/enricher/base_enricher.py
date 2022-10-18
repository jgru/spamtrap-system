from abc import ABC, abstractmethod


class BaseEnricher(ABC):
    """
    Interface specifying methods, which every enricher component has to provide
    """

    @abstractmethod
    async def enrich(self, obj):
        pass
