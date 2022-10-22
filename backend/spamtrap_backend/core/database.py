import io
import logging
from dataclasses import asdict

from aiofile import async_open
from bson.objectid import ObjectId
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorGridFSBucket
from pymongo import MongoClient, ReturnDocument
from varname import nameof

from ..datamodels import (
    CollectionEnum,
    Email,
    FeedMsg,
    File,
    NetworkEntity,
    NetworkEvent,
    Url,
)

logger = logging.getLogger(__name__)


class DatabaseHandler(object):
    collection_map = {
        FeedMsg: CollectionEnum.raw,
        NetworkEvent: CollectionEnum.events,
        Url: CollectionEnum.url,
        Email: CollectionEnum.email,
        File: CollectionEnum.file,
        NetworkEntity: CollectionEnum.network_entity,
    }

    def __init__(self, host, port, database_name, indexttl=None):
        logger.info(f"Connecting to mongodb, using {database_name} as database")

        self.host = host
        self.port = port
        self.dbname = database_name
        self.fsname = f"{database_name}fs"
        self.indexttl = indexttl

        # Populate when event loop is running
        self.conn = None
        self.db = None
        self.fs = None

    async def connect_db(self, io_loop=None):
        if not self.conn:
            self.conn = AsyncIOMotorClient(
                self.host,
                self.port,
                io_loop=io_loop,
            )
            self.db = self.conn[self.dbname]
            self.fs = AsyncIOMotorGridFSBucket(self.conn[self.fsname])
            await self.init_db()

    def is_database_up(self):
        """Synchronous check of availability of DB host"""
        client = MongoClient(self.host, self.port, serverSelectionTimeoutMS=2000)

        return True if client else False

    async def init_db(self):
        await self.ensure_index(self.indexttl)

    async def ensure_index(self, indexttl=2592000):
        await self.db[self.collection_map[Url]].create_index(
            "url", unique=True, background=True, expireAfterSeconds=indexttl
        )
        await self.db[self.collection_map[File]].create_index(
            "hashes.sha512", unique=True, background=True, expireAfterSeconds=indexttl
        )
        await self.db[self.collection_map[NetworkEntity]].create_index(
            "ip", unique=True, background=True, expireAfterSeconds=indexttl
        )

    async def find_file_by_sha512(self, sha512):
        c = CollectionEnum.file
        document = await self.db[c.value].find_one({"hash.sha512": sha512})
        return document

    async def insert_gridfs(self, filename, data, metadata=None):
        logger.debug(f"Inserting {filename} in GridFS")

        # Converts data to bytes, if necessary
        if isinstance(data, str):
            data = data.encode("utf-8")

        # VERY SLOP OP - Do not use it and store duplicates
        # Check, if file already exists, do not store a duplicate
        # cursor = self.fs.find({"filename": filename}).limit(1)  # filename is a sha256
        # if cursor:
        #     logger.debug(f"File {filename} already exists")

        # Stores bytearray in GridFS
        _id = ObjectId()
        await self.fs.upload_from_stream_with_id(
            _id, filename, io.BytesIO(data), metadata=metadata
        )

        return _id

    async def retrieve_file(self, file_id, out_file="./retrieved_"):
        grid_out = await self.fs.open_download_stream(file_id)
        contents = await grid_out.read()

        async with async_open(out_file, "wb") as afd:
            await afd.write(contents)

    async def insert_dm(self, elem):
        _id = None

        if isinstance(elem, File):
            # Store blob in GridFS
            _id = await self.insert_file(elem)

        elif isinstance(elem, Url):
            _id = await self.insert_url(_id, elem)

        elif isinstance(elem, NetworkEntity):
            _id = await self.insert_network_entity(_id, elem)

        else:  # Inserts element in generic form
            _id = await self.insert_generic(_id, elem)

            logger.debug(f"Inserted {type(elem)} as {_id}")

        return _id

    async def insert_generic(self, _id, elem):
        # Infers collection name
        c = self.collection_map[type(elem)]

        # Prepare dict to insert
        elem_dict = asdict(elem)

        # Removes _id, which is null until now and leads to DuplicateKeyError
        del elem_dict[nameof(elem._id)]

        # Inserts doc
        result = await self.db[c.value].insert_one(elem_dict)

        # Retrieves MongoDB-ID
        _id = result.inserted_id

        return _id

    async def insert_network_entity(self, _id, elem):
        ne_dict = asdict(elem)

        # Prepare dict for upsert
        del ne_dict[nameof(elem.parent)]
        del ne_dict[nameof(elem.port)]
        del ne_dict[nameof(elem.category)]
        del ne_dict[nameof(elem._id)]

        # Infers collection name
        c = self.collection_map[type(elem)]

        # Data to insert
        categories = [elem.category]
        ports = [elem.port]

        # Forms query, if IP address is present
        if elem.ip:
            query = {"ip": elem.ip}

        # Forms query, if there is only a hostname
        else:
            query = {"hostname": elem.hostname}

        # Define insertion
        insertion = {
            "$set": ne_dict,
            "$push": {
                "parents": asdict(elem.parent),
            },
            "$addToSet": {  # do not add duplicates
                "category": {"$each": categories},
                "port": {"$each": ports},
            },
        }

        # Upsert -> modify existing, ReturnDocument.AFTER is necessary to retrieve ObjectID for net yet existing doc
        update_result = await self.db[c.value].find_one_and_update(
            query, insertion, upsert=True, return_document=ReturnDocument.AFTER
        )
        _id = update_result["_id"]

        return _id

    async def insert_url(self, _id, elem):
        url_dict = asdict(elem)

        # Prepare dict for upsert
        url_dict.pop(nameof(elem.parent))
        url_dict.pop(nameof(elem.extractions))
        url_dict.pop(nameof(elem._id))
        url_dict.pop(nameof(elem.exploits))

        # Prepare elements to append
        extractions = [asdict(e) for e in elem.extractions]
        exploits = elem.exploits

        # Retrieve collection name
        c = self.collection_map[type(elem)]

        # Forms query
        query = {"url": elem.url}

        # Define insertion
        insertion = {
            "$set": url_dict,
            "$push": {
                "parents": asdict(elem.parent),
            },
            "$addToSet": {  # do not add duplicates
                "exploits": {"$each": exploits},
                "extractions": {"$each": extractions},
            },
        }
        # Upsert -> modify existing, ReturnDocument.AFTER is necessary to retrieve ObjectID for net yet existing doc
        update_result = await self.db[c.value].find_one_and_update(
            query, insertion, upsert=True, return_document=ReturnDocument.AFTER
        )
        _id = update_result["_id"]

        return _id

    async def insert_file(self, elem):
        _id = await self.insert_gridfs(
            elem.hash.sha256, elem.data, metadata={"contentType": elem.encoding}
        )
        elem.file_id = _id

        # Store file metadata in file collection
        file_dict = asdict(elem)

        # Removing unused fields
        del file_dict[nameof(elem.data)]
        del file_dict[nameof(elem.encoding)]
        del file_dict[nameof(elem.parent)]
        del file_dict[nameof(elem.filename)]
        del file_dict[nameof(elem._id)]

        # Performs insertion (which is done by updating an eventually existing entry)
        c = self.collection_map[type(elem)]

        # Defines query
        query = {"hash": asdict(elem.hash)}

        # Updates file entry by appending filenames, parents and communicating hosts
        insertion = {
            "$set": file_dict,
            "$push": {
                "parents": asdict(elem.parent),
            },
            "$addToSet": {"filename": elem.filename},  # do not add duplicates
        }
        # Upsert -> modify existing, ReturnDocument.AFTER is necessary to retrieve ObjectID for net yet existing doc
        update_result = await self.db[c.value].find_one_and_update(
            query, insertion, upsert=True, return_document=ReturnDocument.AFTER
        )
        _id = update_result["_id"]

        return _id
