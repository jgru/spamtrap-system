import asyncio
import logging
import os
import sys

from aiofile import async_open
from motor.core import docstrings

from ..datamodels import Email, FeedMsg, File, Parent, Url
from .database import DatabaseHandler, ObjectId

logger = logging.getLogger(__name__)


class Mediator(object):
    def __init__(self, docs_to_enrich, docs_to_report, **config):

        self.database = None
        self.docs_to_enrich = docs_to_enrich
        self.docs_to_report = docs_to_report
        logger.debug(f"Enriching {self.docs_to_enrich}")
        logger.debug(f"Reporting {self.docs_to_report}")

        if config["mongodb"].pop("enabled"):
            logger.info(f"Checking DB availability at")
            self.database = DatabaseHandler(**config["mongodb"])
            if not self.database.is_database_up():
                logger.info(
                    "MongoDB connection was requested but it is not available. "
                    "Exiting..."
                )
                sys.exit(1)

        self.is_persist = True if self.database else False

        self.is_dump = config["dumping"].get("enabled")

        if self.is_dump:
            self.dump_path = self.check_dir(config["dumping"].get("path"))

        self.enabled = True
        self.is_stopped = True

    async def mediate(self, in_q, process_q=None, enrich_q=None, report_q=None):

        try:
            logger.info("Running mediator coroutine")

            if self.database:
                await self.database.connect_db(asyncio.get_running_loop())

            self.is_stopped = False

            while self.enabled or in_q.qsize() > 0:
                elem = await in_q.get()

                if not elem:
                    continue

                # Persists feed msg and passes it to processor
                if isinstance(elem, FeedMsg):
                    await process_q.put(elem)
                    continue

                # Handles parent-child-relationship of dataclasses
                else:
                    parent = elem[0]
                    children = elem[1]

                    if parent:
                        # Inserts result to db
                        _id = (
                            await self.database.insert_dm(parent)
                            if self.is_persist
                            else ObjectId()
                        )

                        if self.is_dump and isinstance(parent, Email):
                            await self.dump_to_file(parent.hash.sha256, parent.data)

                        parent._id = _id

                        if report_q and type(parent).__name__ in self.docs_to_report:
                            await report_q.put(parent)

                        if children:
                            p = Parent(
                                _id, DatabaseHandler.collection_map[type(parent)]
                            )
                            logger.debug(f"Processing {len(children)} children")

                            # For each child, reference the parent
                            for c in children:
                                logger.debug(f"Processing child")
                                c.parent = p

                                # Put on queue for enriching
                                if (
                                    enrich_q
                                    and type(c).__name__ in self.docs_to_enrich
                                    and not c.is_enriched
                                ):
                                    logger.debug(f"Enqueuing {type(c)} for enriching")
                                    await enrich_q.put(c)

                                else:  # Store elem and put it on report queue otherwise
                                    _id = (
                                        await self.database.insert_dm(c)
                                        if self.is_persist
                                        else ObjectId()
                                    )
                                    c._id = _id
                                    logger.debug(f"Inserted {type(c)} ")

                                    if (
                                        report_q
                                        and type(c).__name__ in self.docs_to_report
                                    ):
                                        logger.debug(
                                            f"Enqueuing {type(c)} for reporting"
                                        )
                                        await report_q.put(c)

                in_q.task_done()

            logger.info("Stopped mediator task")

        except asyncio.CancelledError as e:
            self.enabled = False
            logger.info("Cancelled writer task")

    async def dump_to_file(self, filename, data):
        filepath = os.path.join(self.dump_path, filename)
        async with async_open(filepath, "wb") as af:
            await af.write(data)

    @staticmethod
    def check_dir(dump_path):
        abs_path = os.path.abspath(dump_path)
        if not os.path.exists(abs_path):
            os.makedirs(abs_path)
            logger.info(f"Creating {abs_path}")
        return abs_path
