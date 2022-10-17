import asyncio
import logging
import os
import sys
from aiofile import async_open

from datamodels import Email, FeedMsg, Parent

logger = logging.getLogger(__name__)


class Mediator(object):
    def __init__(self, database, dump_files, dump_path):
        self.database = database
        self.is_dump = dump_files

        if self.is_dump:
            self.dump_path = self.check_dir(dump_path)

        self.enabled = True
        self.is_stopped = True

    async def mediate(self, in_q, process_q=None, enrich_q=None, report_q=None):
        try:
            logger.info("Running mediator coroutine")
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
                else isinstance(elem, tuple):
                    parent = elem[0]
                    children = elem[1]
                    if parent:
                        # Inserts result to db
                        _id = await self.database.insert_dm(parent)

                        if self.is_dump and isinstance(parent, Email):
                            await self.dump_to_file(parent.hash.sha256, parent.data)

                        parent._id = _id

                        if report_q:
                            await report_q.put(parent)

                        if children:
                            p = Parent(_id, self.database.collection_map[type(parent)])
                            logger.debug(f"Processing {len(children)} children")

                            # For each child reference the parent
                            for c in children:
                                logger.debug(f"Processing child")
                                c.parent = p

                                # Put on queue for enriching
                                if enrich_q and not c.is_enriched:
                                    logger.debug(f"Enqueuing {type(c)} for enriching")
                                    await enrich_q.put(c)

                                else:  # Store elem and put on report queue otherwise
                                    _id = await self.database.insert_dm(c)
                                    c._id = _id
                                    logger.debug(f"Inserted {type(c)} ")

                                    if report_q:
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
