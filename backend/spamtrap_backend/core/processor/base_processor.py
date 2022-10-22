from abc import ABC, abstractmethod

from ...datamodels import FeedMsg


class BaseProcessor(ABC):
    """
    Interface specifying methods, which every processor component has to provide.
    """

    @abstractmethod
    def process(self, feed_msg: FeedMsg):
        pass
