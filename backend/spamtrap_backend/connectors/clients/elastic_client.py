import logging
from dataclasses import asdict

from bson.objectid import ObjectId

# API reference: https://elasticsearch-py.readthedocs.io/en/7.9.1/async.html
from elasticsearch import AsyncElasticsearch
from elasticsearch.serializer import JSONSerializer

from ...datamodels import Email, File, NetworkEntity, Url

from ..reporter.base_reporter import BaseReporter

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


class ElasticReporter(BaseReporter):
    """Reporter component, which receives extracted objects and
    checks if they should be pushed in an Elasticsearch instance. If
    so, it jsonifies these objects and sends the data as a POST
    request to ES.

    """

    _type = "elasticsearch"

    def __init__(
        self,
        host="127.0.0.1",
        port=9200,
        index="malspam",
        relevant_documents=[
            Email.__name__,
            File.__name__,
            NetworkEntity.__name__,
            Url.__name__,
        ],
    ):

        self.es_host = host
        self.es_port = port
        # Create a connectio asynchronically in prepare_reporting()
        self.conn = None

        self.es_index = index
        logger.debug(f"Using ES index {self.es_index}")

        self.relevant_types = relevant_documents
        logger.debug(f"Reporting {self.relevant_types}")

        self.enabled = True

    async def prepare_reporting(self):
        self.conn = AsyncElasticsearch(
            hosts=[{"host": self.es_host, "port": self.es_port, "use_ssl": False}],
            serializer=CustomJsonEncoder(),
        )

        await self.log_es_info(self.conn)
        await self.check_index(self.conn, self.es_index)

        logger.info(f"Initialized reporting to ES on {self.es_host}:{self.es_port}")

    async def report(self, elem):
        """Takes an async queue, aynchronously waits on elements and
        pushes retrieved elements to an Elasticseach instance. TODO:
        Operate on batches of elements for better performance.

        :param elem: element to report (if it is relevant)

        """
        # Checks, if the actual element should be sent to ES
        if type(elem).__name__ in self.relevant_types:
            logger.debug(f"Reporting {type(elem)}")
            d = asdict(elem)

            # Sets type of element explicily
            d["event.type"] = type(elem).__name__

            # Do not push binary data to ES
            if type(elem) is Email or type(elem) is File:
                d.pop("data")

            # Removes MongoDB ID, which would causes conflicts with ES indices
            _id = d.pop("_id")

            try:
                # Inserts document
                if _id:
                    # If MongoID is existent, specify it as ID to keep it as a reference
                    await self.conn.index(index=self.es_index, body=d, id=_id)
                else:
                    await self.conn.index(index=self.es_index, body=d)

            except Exception as e:
                logger.error(e)
                return False

            logger.debug(f"Reported an element to Elasticsearch")

            return True

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
