import logging
from abc import ABC, abstractmethod
from typing import List, Tuple, Union

from ...datamodels import File, NetworkEntity, Url
from ..enricher.base_enricher import BaseEnricher
from ..reporter.base_reporter import BaseReporter

logger = logging.getLogger(__name__)


class SandboxConnector(BaseEnricher, BaseReporter):
    _type = "sandbox"

    relevant_documents = [
        File.__name__,
    ]

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
        """Submits file to sandbox, awaits and processes report to
        return the enriched result and the retrieved children.

        """
        logger.info(f"Started enriching '{f.filename}'")
        report = await self.analyze_file(f)
        _file, children = await self.process_report(f, report)
        _file.is_enriched = True

        logger.info(f"Enriched '{f.filename}'")

        return _file, children

    async def prepare(self):
        """Prepares reporting. For sandboxes there is nothing to do."""
        return await super().prepare()

    async def report(self, f):
        """Reports file to sandbox by submitting it for analysis
        without any enriching"""
        if type(f).__name__ in self.relevant_documents:
            # Fire and forget
            await self.analyze_file(f)

        return True

    @staticmethod
    def get_sandbox(_type, **kwargs):
        sandboxes = populate_sandboxes()
        # assert _type in sandboxes.keys(), f"{_type} is not supported"
        return sandboxes[_type](**kwargs)


# Imports are needed to populate via SandboxConnector.__subclasses__()
from .cuckoo_client import Cuckoo
from .hatching_triage_client import HatchingTriage


def populate_sandboxes():
    sandboxes = {}
    for sbc in SandboxConnector.__subclasses__():
        sandboxes |= {sbc._type: sbc}

    return sandboxes
