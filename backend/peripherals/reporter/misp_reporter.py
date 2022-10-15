import asyncio
import concurrent.futures
import io
import logging
from dataclasses import asdict
from functools import partial
from uuid import UUID, uuid5

from pymisp import ExpandedPyMISP, MISPEvent, MISPObject
from pymisp.tools import EMailObject, GenericObjectGenerator

from datamodels import Email, File, NetworkEntity, Url

from .base_reporter import BaseReporter

logger = logging.getLogger(__name__)

# Decouple pymisp's log level from the configured one
logging.getLogger("pymisp").setLevel(logging.ERROR)

from collections import OrderedDict


class SizedDict(OrderedDict):
    """OrderedDict which serves as ringbuffer. Last element is pruned
    if max_size is reached.
    """

    def __init__(self, *args, **kwargs):
        self.max_size = kwargs.pop("max_size", None)
        OrderedDict.__init__(self, *args, **kwargs)
        self._check_size()

    def __setitem__(self, key, value):
        OrderedDict.__setitem__(self, key, value)
        self._check_size()

    def _check_size(self):
        if self.max_size is not None:
            while len(self) > self.max_size:
                self.popitem(last=False)
                logger.debug("Pruning one element from cache")


class MISPReporter(BaseReporter):
    """Reporter component that receives extracted objects and checks
    if they should be pushed into a MISP instance.

    https://www.misp-project.org/misp-training/a.11-misp-data-model.pdf
    https://www.misp-project.org/misp-training/cheatsheet.pdf

    """

    _type = "misp"

    # Arbitrary root namespace for MISP UUIDs.
    # Event UUIDs are generated deterministically from a (root, cfg_hash) pair.
    NAMESPACE = UUID("d72b7729-3b02-409d-ba30-b7f9a02fcf2d")
    CACHE_SIZE = 1000

    def __init__(
        self,
        url="127.0.0.1",
        key="",
        relevant_documents=[
            Email.__name__,
            File.__name__,
            NetworkEntity.__name__,
            Url.__name__,
        ],
    ):
        self.misp_url = f"http://{url}" if not url.startswith("http") else url
        self.misp_key = key
        self.misp_verifycert = False

        # Populate those asynchronously
        self.misp = None
        self.loop = None

        self.relevant_types = relevant_documents

        logger.debug(f"Reporting {self.relevant_types}")

        self.enabled = True

        # Mapping of BSON Object Ids to MISP UUIDs
        self.cache = SizedDict(max_size=MISPReporter.CACHE_SIZE)

    async def prepare_reporting(self):
        self.loop = asyncio.get_running_loop()

        self.misp = ExpandedPyMISP(
            self.misp_url, self.misp_key, self.misp_verifycert, debug=False
        )
        logger.info(f"Initialized reporting to MISP on {self.misp_url}")

    @staticmethod
    def create_new_event(uuid):
        event = MISPEvent()
        event.uuid = uuid
        event.add_tag("spamtrap")
        event.info = "Spamtrap Event"

        return event

    def submit(self, elem):
        # See https://github.com/eCrimeLabs/vt2misp/blob/master/vt2misp.py#L70

        # Create a new event per email or standalone
        if isinstance(elem, Email):
            # Create event with a specific UUID
            event = self.create_new_event(
                str(uuid5(MISPReporter.NAMESPACE, str(elem.file_id)))
            )

            # https://www.misp-project.org/objects.html#_email
            #
            # Optimize this to avoid duplicate mail parsing
            misp_object = EMailObject(pseudofile=io.BytesIO(elem.raw.encode()))
            misp_object.uuid = str(uuid5(self.NAMESPACE, str(elem._id)))
            misp_object = event.add_object(
                misp_object, standalone=False, pythonify=True
            )
            # misp_object.uuid = str(uuid5(self.NAMESPACE, str(elem._id)))

            misp_event = self.misp.add_event(event, pythonify=True)

            if misp_event and misp_object:  # FIXME
                self.cache[misp_object.uuid] = event

        # Only consider derived objects if parent is relevant as well
        # (Maybe make this more generic in the future)
        elif elem.parent.parent_type in self.relevant_types:
            misp_object = None

            if isinstance(elem, Url):
                # https://www.misp-project.org/objects.html#_url
                misp_object = GenericObjectGenerator("url")
                misp_object.generate_attributes(
                    [
                        {
                            "url": elem.url,
                            "domain": elem.domain,
                            "subdomain": elem.subdomain,
                            "tld": elem.tld,
                            "scheme": elem.scheme,
                            "text": elem.category,
                        }
                    ]
                )
                relationship_type = "connected-to"

            elif isinstance(elem, NetworkEntity):
                misp_object = GenericObjectGenerator("ip-port")
                misp_object.generate_attributes(
                    [
                        {
                            "ip-dst": elem.ip,
                            "hostname": elem.hostname,
                            "dst-port": elem.port,
                            "country-code": elem.geo.country_iso_code
                            if elem.geo
                            else None,
                            "last-seen": elem.timestamp,
                            "text": elem.category,
                        }
                    ]
                )
                relationship_type = "extracted-from"

            elif isinstance(elem, File):
                misp_object = GenericObjectGenerator("file")
                misp_object.generate_attributes(
                    [{"filename": elem.filename, "sha256": elem.hash.sha256}]
                )
                size = misp_object.add_attribute("size-in-bytes", value=len(elem.blob))
                if int(size.value) > 0:
                    misp_object.add_attribute("md5", value=elem.hash.md5)
                    misp_object.add_attribute("sha1", value=elem.hash.sha1)
                    misp_object.add_attribute("sha256", value=elem.hash.sha256)
                    misp_object.add_attribute("sha512", value=elem.hash.sha512)
                    misp_object.add_attribute(
                        "malware-sample",
                        value=elem.filename,
                        data=elem.blob,
                        disable_correlation=True,
                    )

                relationship_type = "extracted-from"
            else:
                raise Exception("Unknown entity")

            misp_object.uuid = str(uuid5(self.NAMESPACE, str(elem._id)))

            misp_parent_object_uuid = str(
                uuid5(self.NAMESPACE, str(elem.parent.parent_id))
            )
            misp_event = self.cache.get(misp_parent_object_uuid)

            if not misp_event:  # No cache hit
                logger.debug("Cache miss. Could not retrieve misp_event from cache")

                misp_parent_object = self.misp.get_object(
                    misp_parent_object_uuid, pythonify=True
                )
                if isinstance(misp_parent_object, MISPObject):
                    misp_event_id = misp_parent_object.event_id
                    misp_event = self.misp.get_event(misp_event_id, pythonify=True)
                else:
                    logger.error(
                        f"Could not persist {elem._id}, because parent is not existing (yet)"
                    )
                    return False

            misp_object = misp_event.add_object(
                misp_object, standalone=False, pythonify=True
            )

            if misp_object:
                self.cache[misp_object.uuid] = misp_event

            logger.debug(f"Added relationship with {misp_parent_object_uuid}")
            # Relationships https://github.com/MISP/misp-objects/blob/cd3f54747ae4fc9d0d301741be17eb62a7f9549b/relationships/definition.json
            misp_object.add_reference(
                referenced_uuid=misp_parent_object_uuid,
                relationship_type=relationship_type,
                comment="Spamtrap derivation",
            )

            self.misp.update_event(misp_event)
        else:
            logger.debug(
                f"Intentionally do not deal with {elem._id}, "
                "since its parent should not be considered"
            )

        return True

    async def report(self, elem):
        """Takes an async queue, aynchronously waits on elements and
        pushes retrieved elements to an Elasticseach instance. TODO:
        Operate on batches of elements for better performance.

        :param in_q: async queue, with elements to report

        """

        # Checks if the actual element should be sent to ES
        if type(elem).__name__ in self.relevant_types:
            with concurrent.futures.ThreadPoolExecutor() as pool:
                upload = partial(self.submit, elem)
                result = await self.loop.run_in_executor(pool, upload)

                if result:
                    logger.debug(f"Reported {type(elem)} to MISP")

                return result

        return True
