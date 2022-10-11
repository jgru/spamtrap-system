from abc import ABC, abstractmethod


class BaseEnricher(ABC):
    """
    Interface specifying methods, which every enricher component has to provide
    """

    @abstractmethod
    def enrich(self, obj):
        pass

    @staticmethod
    def read_whitelist(fp):
        wl = []
        if fp:
            with open(fp, "r") as f:
                for line in f.readlines():
                    wl.append(line.strip())
        return wl
