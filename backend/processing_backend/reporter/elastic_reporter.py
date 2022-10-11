import asyncio
import logging
from dataclasses import asdict

from bson.objectid import ObjectId

# API reference: https://elasticsearch-py.readthedocs.io/en/7.9.1/async.html
from elasticsearch import AsyncElasticsearch
from elasticsearch.serializer import JSONSerializer

from datamodels import File

logger = logging.getLogger(__name__)


class CustomJsonEncoder(JSONSerializer):
    """
    Custom JSON Encoder takes care of serializing bson.objectid.ObjectIds
    See https://elasticsearch-py.readthedocs.io/en/7.10.0/async.html#asyncelasticsearch for explanation and code
    reference.
    """

    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        else:
            return JSONSerializer.default(self, obj)


class ElasticReporter:
    """
    Reporter component, which receives extracted objects and checks if they should be pushed in an Elasticsearch
     instance. If so, it jsonifies these objects and sends the data as a POST request to ES.
    """

    def __init__(self, host, port, index, relevant_documents):
        self.es_host = host
        self.es_port = port

        self.es_index = index
        logger.debug(f"Using ES index {self.es_index}")

        self.relevant_types = relevant_documents
        logger.debug(f"Reporting {self.relevant_types}")

        self.enabled = True
        logger.info(f"Initialized reporting to ES on {self.es_host}:{self.es_port}")

    async def consume_to_report(self, in_q):
        """:return:
        Takes an async queue, aynchronously waits on elements and pushes retrieved elements to an Elasticseach instance.
        TODO: Operate on batches of elements for better performance.

        :param in_q: async queue, with elements to report
        """
        logger.info("Running reporter coroutine")
        conn = AsyncElasticsearch(
            hosts=[{"host": self.es_host, "port": self.es_port, "use_ssl": False}],
            serializer=CustomJsonEncoder(),
        )

        await self.log_es_info(conn)

        await self.check_index(conn, self.es_index)

        cnt = 0  # Just for debug info

        try:  # Necessary to handle asyncio.CancelledError
            while self.enabled or in_q.qsize() > 0:
                elem = await in_q.get()

                # Checks, if the actual element should be sent to ES
                if type(elem).__name__ in self.relevant_types:
                    logger.debug(f"Reporting {type(elem)}")
                    d = asdict(elem)

                    # Sets type of element explicily
                    d["event.type"] = type(elem).__name__

                    # Strips of binary data from File-objects
                    if isinstance(elem, File):
                        # Do not push binary data to ES
                        del d["blob"]

                    # Removes MongoDB ID, which would causes conflicts with ES indices
                    _id = d.pop("_id")

                    try:
                        # Inserts document
                        if _id:
                            # If MongoID is existent, specify it as ID to keep it reference
                            await conn.index(index=self.es_index, body=d, id=_id)
                        else:
                            await conn.index(index=self.es_index, body=d)

                        cnt += 1
                    except Exception as e:
                        logger.error(e)

                    logger.debug(f"Reported {cnt} elements to Elasticsearch")
                in_q.task_done()

        except asyncio.CancelledError:
            self.enabled = False
            logger.info("Reporting task cancelled")

        # Close conn to ES to avoid 'Unclosed client session' exception
        await conn.close()

        logger.info("Reporting task stopped")

    @staticmethod
    async def log_es_info(conn):
        """
        Log information on Elasticsearch instance used

        :param conn:
        :return:
        """
        info = await conn.info()
        logger.debug(info)

    async def check_index(self, conn, index):
        """
        Ensures, that index exists. If it is not existent, it will be created.
        :param conn: connection to ES
        :param index: str, name of the index
        :return:
        """
        is_existing = await conn.indices.exists(index=index)
        if not is_existing:
            await self.create_index_mapping(conn, index)
            logger.debug(f"Created ES index: {index}")
        else:
            logger.debug(f"ES index {index} is existent")

    INDEX_MAPPING = {
        "settings": {"number_of_shards": 2, "number_of_replicas": 1},
        "mappings": {
            "properties": {
                "event.type": {
                    "type": "keyword",
                    # "fields": {
                    #    "keyword": {
                    #        "type": "keyword",
                    #        "ignore_above": 256
                    #    }
                    # }
                },
                #######################
                # Email mapping
                #######################
                "attachment_count": {"type": "long"},
                "destination": {
                    "properties": {
                        "category": {
                            "type": "text",
                        },
                        "geo": {
                            "properties": {
                                "city_name": {
                                    "type": "text",
                                    "fields": {
                                        "keyword": {
                                            "type": "keyword",
                                            "ignore_above": 256,
                                        }
                                    },
                                },
                                "continent_name": {
                                    "type": "text",
                                    "fields": {
                                        "keyword": {
                                            "type": "keyword",
                                            "ignore_above": 256,
                                        }
                                    },
                                },
                                "country_iso_code": {
                                    "type": "text",
                                    "fields": {
                                        "keyword": {
                                            "type": "keyword",
                                            "ignore_above": 256,
                                        }
                                    },
                                },
                                "country_name": {
                                    "type": "text",
                                    "fields": {
                                        "keyword": {
                                            "type": "keyword",
                                            "ignore_above": 256,
                                        }
                                    },
                                },
                                "location": {"type": "geo_point"},
                            }
                        },
                        "ip": {
                            "type": "ip",
                        },
                        "port": {"type": "long"},
                    }
                },
                "domains": {
                    "type": "text",
                    "fields": {"keyword": {"type": "keyword", "ignore_above": 256}},
                },
                "file_id": {
                    "type": "text",
                    "fields": {"keyword": {"type": "keyword", "ignore_above": 256}},
                },
                "is_enriched": {"type": "boolean"},
                "message": {
                    "type": "text",
                },
                "message_id": {
                    "type": "text",
                    "fields": {"keyword": {"type": "keyword", "ignore_above": 256}},
                },
                "observer": {
                    "properties": {
                        "name": {
                            "type": "text",
                            "fields": {
                                "keyword": {"type": "keyword", "ignore_above": 256}
                            },
                        },
                        "type": {
                            "type": "text",
                            "fields": {
                                "keyword": {"type": "keyword", "ignore_above": 256}
                            },
                        },
                    }
                },
                "recipients": {
                    "type": "nested",
                    "properties": {
                        "address": {
                            "type": "text",
                            "fields": {
                                "keyword": {"type": "keyword", "ignore_above": 256}
                            },
                        },
                        "domain": {
                            "type": "text",
                            "fields": {
                                "keyword": {"type": "keyword", "ignore_above": 256}
                            },
                        },
                        "top_level_domain": {
                            "type": "text",
                            "fields": {
                                "keyword": {"type": "keyword", "ignore_above": 256}
                            },
                        },
                    },
                },
                "related": {
                    "type": "text",
                    "fields": {"keyword": {"type": "keyword", "ignore_above": 256}},
                },
                "reply_to": {
                    "properties": {
                        "address": {
                            "type": "text",
                            "fields": {
                                "keyword": {"type": "keyword", "ignore_above": 256}
                            },
                        },
                        "domain": {
                            "type": "text",
                            "fields": {
                                "keyword": {"type": "keyword", "ignore_above": 256}
                            },
                        },
                        "subdomain": {
                            "type": "text",
                            "fields": {
                                "keyword": {"type": "keyword", "ignore_above": 256}
                            },
                        },
                        "top_level_domain": {
                            "type": "text",
                            "fields": {
                                "keyword": {"type": "keyword", "ignore_above": 256}
                            },
                        },
                    }
                },
                "return_path": {
                    "properties": {
                        "address": {
                            "type": "text",
                            "fields": {
                                "keyword": {"type": "keyword", "ignore_above": 256}
                            },
                        },
                        "domain": {
                            "type": "text",
                            "fields": {
                                "keyword": {"type": "keyword", "ignore_above": 256}
                            },
                        },
                        "subdomain": {
                            "type": "text",
                            "fields": {
                                "keyword": {"type": "keyword", "ignore_above": 256}
                            },
                        },
                        "top_level_domain": {
                            "type": "text",
                            "fields": {
                                "keyword": {"type": "keyword", "ignore_above": 256}
                            },
                        },
                    }
                },
                "sender": {
                    "properties": {
                        "address": {
                            "type": "text",
                            "fields": {
                                "keyword": {"type": "keyword", "ignore_above": 256}
                            },
                        },
                        "domain": {
                            "type": "text",
                            "fields": {
                                "keyword": {"type": "keyword", "ignore_above": 256}
                            },
                        },
                        "subdomain": {
                            "type": "text",
                            "fields": {
                                "keyword": {"type": "keyword", "ignore_above": 256}
                            },
                        },
                        "top_level_domain": {
                            "type": "text",
                            "fields": {
                                "keyword": {"type": "keyword", "ignore_above": 256}
                            },
                        },
                    }
                },
                "sha256": {
                    "type": "text",
                    "fields": {"keyword": {"type": "keyword", "ignore_above": 256}},
                },
                "size": {"type": "long"},
                "source": {
                    "properties": {
                        "category": {
                            "type": "text",
                            "fields": {
                                "keyword": {"type": "keyword", "ignore_above": 256}
                            },
                        },
                        "geo": {
                            "properties": {
                                "city_name": {
                                    "type": "text",
                                    "fields": {
                                        "keyword": {
                                            "type": "keyword",
                                            "ignore_above": 256,
                                        }
                                    },
                                },
                                "continent_name": {
                                    "type": "text",
                                    "fields": {
                                        "keyword": {
                                            "type": "keyword",
                                            "ignore_above": 256,
                                        }
                                    },
                                },
                                "country_iso_code": {
                                    "type": "text",
                                    "fields": {
                                        "keyword": {
                                            "type": "keyword",
                                            "ignore_above": 256,
                                        }
                                    },
                                },
                                "country_name": {
                                    "type": "text",
                                    "fields": {
                                        "keyword": {
                                            "type": "keyword",
                                            "ignore_above": 256,
                                        }
                                    },
                                },
                                "location": {"type": "geo_point"},
                            }
                        },
                        "ip": {
                            "type": "ip",
                        },
                        "port": {"type": "long"},
                    }
                },
                "subject": {
                    "type": "text",
                    "fields": {"keyword": {"type": "keyword", "ignore_above": 256}},
                },
                "timestamp": {"type": "date"},
                "urls": {
                    "type": "text",
                    "fields": {"keyword": {"type": "keyword", "ignore_above": 256}},
                },
                #######################
                # File mapping
                #######################
                # TODO
                #######################
                # Url mapping
                #######################
                "url": {"type": "keyword", "ignore_above": 2048},
                "top_level_domain": {"type": "keyword", "ignore_above": 256},
                "domain": {"type": "keyword", "ignore_above": 2048},
                "subdomain": {"type": "keyword", "ignore_above": 2048},
                "path": {
                    "type": "text",
                },
                "scheme": {"type": "keyword", "ignore_above": 64},
                "parent": {
                    "type": "object",
                    "properties": {
                        "parent_id": {"type": "keyword", "ignore_above": 2048},
                        "parent_type": {"type": "keyword", "ignore_above": 512},
                    },
                },
                #######################
                # NetworkEntity mapping
                #######################
                "ip": {
                    "type": "ip",
                },
                "geo": {
                    "properties": {
                        "city_name": {
                            "type": "text",
                            "fields": {
                                "keyword": {"type": "keyword", "ignore_above": 256}
                            },
                        },
                        "continent_name": {
                            "type": "text",
                            "fields": {
                                "keyword": {"type": "keyword", "ignore_above": 256}
                            },
                        },
                        "country_iso_code": {
                            "type": "text",
                            "fields": {
                                "keyword": {"type": "keyword", "ignore_above": 256}
                            },
                        },
                        "country_name": {
                            "type": "text",
                            "fields": {
                                "keyword": {"type": "keyword", "ignore_above": 256}
                            },
                        },
                        "location": {"type": "geo_point"},
                    }
                },
                "port": {"type": "long"},
                "category": {
                    "type": "keyword",
                },
            }
        },
    }

    @classmethod
    async def create_index_mapping(cls, conn, index):
        """
        Creates an index, with the specified mapping
        :param conn: connection to ES
        :param index: str, name of the index

        """
        logger.debug(f"Creating index for {index}")

        response = await conn.indices.create(
            index=index,
            body=cls.INDEX_MAPPING,
            ignore=400,  # ignore 400 already exists code
        )

        logger.info(f"Created index - {response}")
