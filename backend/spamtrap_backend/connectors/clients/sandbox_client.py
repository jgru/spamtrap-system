import logging
from abc import ABC, abstractmethod
from typing import List, Tuple, Union

from ...datamodels import File, NetworkEntity, Url
from ..enricher.base_enricher import BaseEnricher
from ..reporter.base_reporter import BaseReporter

logger = logging.getLogger(__name__)


class SandboxConnector(BaseEnricher):
    _type = "abstract"

    @abstractmethod
    async def analyze_file(self, file: File) -> dict:
        pass

    @abstractmethod
    async def process_report(
        self, file: File, report
    ) -> Tuple[File, List[Union[File, NetworkEntity, Url]]]:
        pass

    @abstractmethod
    async def retrieve_report(self, task_id: int) -> dict:
        pass

    async def enrich(self, f):
        report = await self.analyze_file(f)
        _file, children = await self.process_report(f, report)
        _file.is_enriched = True

        logger.info(f"Enriched '{f.filename}'")

        return _file, children

    @staticmethod
    def get_sandbox(_type, **kwargs):
        sandboxes = populate_sandboxes()
        # assert _type in sandboxes.keys(), f"{_type} is not supported"
        return sandboxes[_type](**kwargs)


# Needed for population via SandboxConnector.__subclasses__()
from .cuckoo_client import Cuckoo
from .hatching_triage_client import HatchingTriage


def populate_sandboxes():
    sandboxes = {}
    for sbc in SandboxConnector.__subclasses__():
        sandboxes |= {sbc._type: sbc}

    return sandboxes
