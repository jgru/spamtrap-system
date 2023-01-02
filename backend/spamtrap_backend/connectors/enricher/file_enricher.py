import asyncio
import concurrent.futures
import logging
import sys

try:
    from sflock.abstracts import File as SflockFile
    from sflock.unpack import RarFile, TarFile, Zip7File, ZipFile
except ImportError:
    print("Missing dependencies:")
    print(
        "sudo apt-get install p7zip-full rar unace-nonfree; sudo pip install -U sflock"
    )
    sys.exit(1)


from ...datamodels import Extraction, File, HashFactory
from ..clients.sandbox_client import SandboxConnector
from .base_enricher import BaseEnricher

logger = logging.getLogger(__name__)


class FileEnricher(BaseEnricher):
    ignore_list = ["jpg", "png", "ico", "bmp", "gif"]
    applicable_types = (File,)

    def __init__(
        self,
        _type,
        **kwargs,
    ):
        logger.info(f"Start file enricher using {_type} sandbox")
        self.sandbox = SandboxConnector.get_sandbox(_type, **kwargs)

    async def enrich(self, f):

        if f.extension in File.ARCHIVE_EXTS:
            with concurrent.futures.ProcessPoolExecutor() as executor:
                return await asyncio.get_running_loop().run_in_executor(
                    executor, self.extract_archive, f
                )

        # Not of interest
        if f.content_guess in self.ignore_list:
            return None, None

        return await self.sandbox.enrich(f)

    @classmethod
    def extract_archive(cls, f):
        logger.debug(f"Extracting {f.filename}")
        content = f.data

        if f.password:
            # Sflock expects byte string
            pw = f.password.encode("utf-8")
        else:
            pw = None

        if f.extension == "zip":
            if "v5.1" in f.content_guess:
                # Unzip is not capable to process this version, 7z is required (Zip7File)
                archive_file = Zip7File(SflockFile(contents=content, password=pw))
            else:
                archive_file = ZipFile(SflockFile(contents=content, password=pw))
        elif f.extension == "rar":
            archive_file = RarFile(SflockFile(contents=content, password=pw))
        elif f.extension == "tar":
            archive_file = TarFile(SflockFile(contents=content, password=pw))
        else:  # Fallback to zip
            archive_file = Zip7File(SflockFile(contents=content, password=pw))

        files_in_zip = list(archive_file.unpack(password=pw, duplicates=[]))
        extracted_files = []

        for zf in files_in_zip:
            h = HashFactory.get_hashstruct_from_bytes(zf.contents)
            cg = zf.magic
            fn = zf.filename.decode("utf-8")
            ext = fn.rsplit(".", 1)[-1] if "." in fn else ""

            f.extractions.append(
                Extraction(content_guess=cg, extension=ext, description=fn, hash=h)
            )

            file_struct = File(
                content_guess=cg,
                extension=ext,
                encoding="application/octet-stream",  # alternative: "hex"
                filename=fn,
                hash=h,
                data=zf.contents,
                timestamp=f.timestamp,
            )
            extracted_files.append(file_struct)
            logger.info(f"Extracted {zf.filename}")

            f.is_enriched = True

        return f, extracted_files
