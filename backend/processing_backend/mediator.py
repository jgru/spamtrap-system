import asyncio
import logging
import os
from aiofile import async_open

from datamodels import FeedMsg, Parent

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
            cnt = 0

            while self.enabled or in_q.qsize() > 0:
                elem = await in_q.get()

                # Persists feed msg and passes it to processor
                if isinstance(elem, FeedMsg):
                    cnt += 1
                    if elem.payload.get("sha256"):
                        # Writes to GridFS is slower, take it into account, if reading gets slow
                        _id = await self.database.insert_gridfs(
                            elem.payload["sha256"],
                            elem.payload["msg"],
                            metadata={"contentType": "message/rfc822"}
                        )
                        elem._id = _id

                        if self.is_dump:
                            await self.dump_to_file(elem.payload["sha256"], elem.payload["msg"])

                    await process_q.put(elem)

                # Handles parent-child-relationship of dataclasses
                elif isinstance(elem, tuple):
                    logger.debug("Received a tuple")
                    # Sets parent reference for its children
                    parent = elem[0]
                    children = elem[1]
                    if parent:
                        # Inserts result to db
                        _id = await self.database.insert_dm(parent)
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
                                    logger.info(f"Enqueuing {type(c)} for enriching")
                                    await enrich_q.put(c)
                                else:  # Store elem and put on report queue otherwise
                                    _id = await self.database.insert_dm(c)
                                    c._id = _id
                                    logger.debug(f"Inserted {type(c)} ")

                                    if report_q:
                                        logger.debug(f"Enqueuing {type(c)} for reporting")
                                        await report_q.put(c)

                elif elem:
                    if not elem.is_enriched:
                        if enrich_q:
                            logger.debug(f"Enqueuing {type(elem)} for enriching")
                            await enrich_q.put(elem)

                    else:  # elem is fully processed and enriched, persist it
                        logger.debug(f"Dumping: {type(elem)}")
                        _id = await self.database.insert_dm(elem)
                        elem._id = _id

                        if report_q:
                            await report_q.put(elem)

                in_q.task_done()
                logger.debug(f"Count {cnt}")
            logger.info("Stopped mediator task")

        except asyncio.CancelledError as e:
            self.enabled = False
            logger.info("Cancelled writer task")

    async def dump_to_file(self, filename, data):
        filepath = os.path.join(self.dump_path, filename)
        async with async_open(filepath, 'w') as afd:
            await afd.write(data)

    @staticmethod
    def check_dir(dump_path):
        abs_path = os.path.abspath(dump_path)
        if not os.path.exists(abs_path):
            os.makedirs(abs_path)
            logger.info(f"Creating {abs_path}")
        return abs_path
