
import asyncio
import json
import logging
from dataclasses import asdict

from bson.objectid import ObjectId
# API reference: https://elasticsearch-py.readthedocs.io/en/7.9.1/async.html
from elasticsearch import AsyncElasticsearch
from elasticsearch import exceptions
from elasticsearch.serializer import JSONSerializer

from datamodels import File

logger = logging.getLogger(__name__)


class CustomJsonEncoder(JSONSerializer):
    """
    Custom JSON Encoder takes care of serializing bson.objectid.ObjectIds
    See https://elasticsearch-py.readthedocs.io/en/7.10.0/async.html#asyncelasticsearch for code reference
    """
    def default(self, obj):
        if isinstance(obj, ObjectId):
            return str(obj)
        else:
            return JSONSerializer.default(self, obj)


class ElasticReporter:

    def __init__(self, host, port, index, relevant_documents):
        self.es_host = host
        self.es_port = port

        logger.info(f"Initialized reporting to ES on {self.es_host}:{self.es_port}")

        self.es_index = index
        logger.info(f"Using ES index {self.es_index}")

        self.relevant_types = relevant_documents
        self.enabled = True
        self.is_stopped = True

        logger.info(f"Reporting {self.relevant_types}")

    async def consume_to_report(self, in_q):

        logger.info("Running reporter coroutine")

        conn = AsyncElasticsearch(
            hosts=[{
                'host': self.es_host,
                'port': self.es_port,
                'use_ssl': False
            }],
            serializer=CustomJsonEncoder()
        )

        await self.get_es_info(conn)

        await self.check_index(conn, self.es_index)
        # await self.get_index_mapping(conn, self.es_index)

        self.is_stopped = False
        cnt = 0
        try:
            logger.info("Starting loop")
            while self.enabled or in_q.qsize() > 0:
                elem = await in_q.get()

                if type(elem).__name__ in self.relevant_types:
                    logger.info(f"Reporting {type(elem)}")
                    d = asdict(elem)
                    d['event.type'] = type(elem).__name__

                    if isinstance(elem, File):
                        # Do not push binary data to ES
                        del d['blob']

                    # Remove MongoDB ID, which would cause conflicts
                    d.pop('_id')

                    try:
                        # Insert document
                        if elem._id:
                            await conn.index(index=self.es_index, body=d, id=elem._id)
                        else:
                            await conn.index(index=self.es_index, body=d)

                        cnt += 1
                    except Exception as e:
                        logger.error(e)

                    logger.debug(f"Reported {cnt} elems")
                in_q.task_done()

        except asyncio.CancelledError:
            self.enabled = False
            logger.info("Reporting task cancelled")

        # Close conn to ES to avoid 'Unclosed client session' exception
        await conn.close()

        logger.info("Reporting task stopped")

    @staticmethod
    async def get_es_info(client):
        info = await client.info()
        logger.info(info)

    async def check_index(self, conn, index):
        is_existing = await conn.indices.exists(index=index)
        if not is_existing:
            await self.create_index_mapping(conn, index)
            logger.info(f"Created ES index: {index}")

    async def get_index_mapping(self, client, ind):
        # returns a list of all the cluster's indices
        all_indices = await client.indices.get_alias("*")

        # print all the attributes for client.indices
        print(dir(client.indices), "\n")

        # iterate over the index names
        for ind in all_indices:
            # skip indices with 'kibana' in name
            if "kibana" not in ind.lower():
                try:
                    # print the Elasticsearch index name
                    print("\nindex name:", ind)
                    if ind == "malspam":
                        # try and see if index has a _mapping template
                        try:
                            # returns dict object of the index _mapping schema
                            template = await client.indices.get_template(ind)
                            print("template schema:", json.dumps(template, indent=4))

                        except exceptions.NotFoundError as err:
                            print("get_template() error for", ind, "--", err)

                except exceptions.NotFoundError as err:
                    print("exceptions.NotFoundError error for", ind, "--", err)

    @staticmethod
    async def create_index_mapping(client, index):
        logger.info(f"Creating index mapping for {index}")
        mapping = {
            "settings": {
                "number_of_shards": 2,
                "number_of_replicas": 1
            },
            "mappings": {
                "properties": {
                    "event.type": {
                      "type": "keyword",
                        #"fields": {
                        #    "keyword": {
                        #        "type": "keyword",
                        #        "ignore_above": 256
                        #    }
                        #}
                    },
                    #######################
                    # Email mapping
                    #######################
                     "attachment_count": {
                        "type": "long"
                    },
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
                                                "ignore_above": 256
                                            }
                                        }
                                    },
                                    "continent_name": {
                                        "type": "text",
                                        "fields": {
                                            "keyword": {
                                                "type": "keyword",
                                                "ignore_above": 256
                                            }
                                        }
                                    },
                                    "country_iso_code": {
                                        "type": "text",
                                        "fields": {
                                            "keyword": {
                                                "type": "keyword",
                                                "ignore_above": 256
                                            }
                                        }
                                    },
                                    "country_name": {
                                        "type": "text",
                                        "fields": {
                                            "keyword": {
                                                "type": "keyword",
                                                "ignore_above": 256
                                            }
                                        }
                                    },
                                    "location": {
                                        "type": "geo_point"
                                    }
                                }
                            },
                            "ip": {
                                "type": "ip",
                            },
                            "port": {
                                "type": "long"
                            }
                        }
                    },
                    "domains": {
                        "type": "text",
                        "fields": {
                            "keyword": {
                                "type": "keyword",
                                "ignore_above": 256
                            }
                        }
                    },
                    "file_id": {
                        "type": "text",
                        "fields": {
                            "keyword": {
                                "type": "keyword",
                                "ignore_above": 256
                            }
                        }
                    },
                    "is_enriched": {
                        "type": "boolean"
                    },
                    "message": {
                        "type": "text",
                    },
                    "message_id": {
                        "type": "text",
                        "fields": {
                            "keyword": {
                                "type": "keyword",
                                "ignore_above": 256
                            }
                        }
                    },
                    "observer": {
                        "properties": {
                            "name": {
                                "type": "text",
                                "fields": {
                                    "keyword": {
                                        "type": "keyword",
                                        "ignore_above": 256
                                    }
                                }
                            },
                            "type": {
                                "type": "text",
                                "fields": {
                                    "keyword": {
                                        "type": "keyword",
                                        "ignore_above": 256
                                    }
                                }
                            }
                        }
                    },
                    "recipients": {
                        "type": "nested",
                        "properties": {
                            "address": {
                                "type": "text",
                                "fields": {
                                    "keyword": {
                                        "type": "keyword",
                                        "ignore_above": 256
                                    }
                                }
                            },
                            "domain": {
                                "type": "text",
                                "fields": {
                                    "keyword": {
                                        "type": "keyword",
                                        "ignore_above": 256
                                    }
                                }
                            },
                            "top_level_domain": {
                                "type": "text",
                                "fields": {
                                    "keyword": {
                                        "type": "keyword",
                                        "ignore_above": 256
                                    }
                                }
                            }
                        }
                    },
                    "related": {
                        "type": "text",
                        "fields": {
                            "keyword": {
                                "type": "keyword",
                                "ignore_above": 256
                            }
                        }
                    },
                    "reply_to": {
                        "properties": {
                            "address": {
                                "type": "text",
                                "fields": {
                                    "keyword": {
                                        "type": "keyword",
                                        "ignore_above": 256
                                    }
                                }
                            },
                            "domain": {
                                "type": "text",
                                "fields": {
                                    "keyword": {
                                        "type": "keyword",
                                        "ignore_above": 256
                                    }
                                }
                            },
                            "subdomain": {
                                "type": "text",
                                "fields": {
                                    "keyword": {
                                        "type": "keyword",
                                        "ignore_above": 256
                                    }
                                }
                            },
                            "top_level_domain": {
                                "type": "text",
                                "fields": {
                                    "keyword": {
                                        "type": "keyword",
                                        "ignore_above": 256
                                    }
                                }
                            }
                        }
                    },
                    "return_path": {
                        "properties": {
                            "address": {
                                "type": "text",
                                "fields": {
                                    "keyword": {
                                        "type": "keyword",
                                        "ignore_above": 256
                                    }
                                }
                            },
                            "domain": {
                                "type": "text",
                                "fields": {
                                    "keyword": {
                                        "type": "keyword",
                                        "ignore_above": 256
                                    }
                                }
                            },
                            "subdomain": {
                                "type": "text",
                                "fields": {
                                    "keyword": {
                                        "type": "keyword",
                                        "ignore_above": 256
                                    }
                                }
                            },
                            "top_level_domain": {
                                "type": "text",
                                "fields": {
                                    "keyword": {
                                        "type": "keyword",
                                        "ignore_above": 256
                                    }
                                }
                            }
                        }
                    },
                    "sender": {
                        "properties": {
                            "address": {
                                "type": "text",
                                "fields": {
                                    "keyword": {
                                        "type": "keyword",
                                        "ignore_above": 256
                                    }
                                }
                            },
                            "domain": {
                                "type": "text",
                                "fields": {
                                    "keyword": {
                                        "type": "keyword",
                                        "ignore_above": 256
                                    }
                                }
                            },
                            "subdomain": {
                                "type": "text",
                                "fields": {
                                    "keyword": {
                                        "type": "keyword",
                                        "ignore_above": 256
                                    }
                                }
                            },
                            "top_level_domain": {
                                "type": "text",
                                "fields": {
                                    "keyword": {
                                        "type": "keyword",
                                        "ignore_above": 256
                                    }
                                }
                            }
                        }
                    },
                    "sha256": {
                        "type": "text",
                        "fields": {
                            "keyword": {
                                "type": "keyword",
                                "ignore_above": 256
                            }
                        }
                    },
                    "size": {
                        "type": "long"
                    },
                    "source": {
                        "properties": {
                            "category": {
                                "type": "text",
                                "fields": {
                                    "keyword": {
                                        "type": "keyword",
                                        "ignore_above": 256
                                    }
                                }
                            },
                            "geo": {
                                "properties": {
                                    "city_name": {
                                        "type": "text",
                                        "fields": {
                                            "keyword": {
                                                "type": "keyword",
                                                "ignore_above": 256
                                            }
                                        }
                                    },
                                    "continent_name": {
                                        "type": "text",
                                        "fields": {
                                            "keyword": {
                                                "type": "keyword",
                                                "ignore_above": 256
                                            }
                                        }
                                    },
                                    "country_iso_code": {
                                        "type": "text",
                                        "fields": {
                                            "keyword": {
                                                "type": "keyword",
                                                "ignore_above": 256
                                            }
                                        }
                                    },
                                    "country_name": {
                                        "type": "text",
                                        "fields": {
                                            "keyword": {
                                                "type": "keyword",
                                                "ignore_above": 256
                                            }
                                        }
                                    },
                                    "location": {
                                        "type": "geo_point"
                                    }
                                }
                            },
                            "ip": {
                                "type": "ip",
                            },
                            "port": {
                                "type": "long"
                            }
                        }
                    },
                    "subject": {
                        "type": "text",
                        "fields": {
                            "keyword": {
                                "type": "keyword",
                                "ignore_above": 256
                            }
                        }
                    },
                    "timestamp": {
                        "type": "date"
                    },
                    "urls": {
                        "type": "text",
                        "fields": {
                            "keyword": {
                                "type": "keyword",
                                "ignore_above": 256
                            }
                        }
                    },
                    #######################
                    # File mapping
                    #######################
                    #TODO
                    #######################
                    # Url mapping
                    #######################

                    "url": {
                      "type": "keyword",
                      "ignore_above": 2048
                    },
                    "top_level_domain": {
                        "type": "keyword",
                        "ignore_above": 256
                    },
                    "domain": {
                        "type": "keyword",
                        "ignore_above": 2048
                    },
                    "subdomain": {
                        "type": "keyword",
                        "ignore_above": 2048
                    },
                    "path": {
                        "type": "text",
                    },
                    "scheme": {
                        "type": "keyword",
                         "ignore_above": 64
                    },
                    "parent": {
                        "type": "object",
                        "properties": {
                            "parent_id": {
                                "type": "keyword",
                                "ignore_above": 2048
                            },
                            "parent_type": {
                                "type": "keyword",
                                "ignore_above": 512
                            }
                        }
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
                                    "keyword": {
                                        "type": "keyword",
                                        "ignore_above": 256
                                    }
                                }
                            },
                            "continent_name": {
                                "type": "text",
                                "fields": {
                                    "keyword": {
                                        "type": "keyword",
                                        "ignore_above": 256
                                    }
                                }
                            },
                            "country_iso_code": {
                                "type": "text",
                                "fields": {
                                    "keyword": {
                                        "type": "keyword",
                                        "ignore_above": 256
                                    }
                                }
                            },
                            "country_name": {
                                "type": "text",
                                "fields": {
                                    "keyword": {
                                        "type": "keyword",
                                        "ignore_above": 256
                                    }
                                }
                            },
                            "location": {
                                "type": "geo_point"
                            }
                        }
                    },
                    "port": {
                        "type": "long"
                    },
                    "category": {
                        "type": "keyword",
                    }
                }
            }
        }

        response = await client.indices.create(
            index=index,
            body=mapping,
            ignore=400  # ignore 400 already exists code
        )

        logger.info(f"Created index - {response}")
