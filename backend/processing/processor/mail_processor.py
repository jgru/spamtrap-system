import base64
import logging
import re
from hashlib import sha256

import eml_parser
import magic
import validators
from datamodels import (
    Address,
    Email,
    EntityEnum,
    Extraction,
    File,
    Hash,
    NetworkEntityFactory,
    Observer,
    Url,
)
from netaddr import IPAddress
from processing_backend.processor.baseprocessor import BaseProcessor

logger = logging.getLogger(__name__)


class MailProcessor(BaseProcessor):
    # Hpfeeds channel name to be responsible for
    channels = ("spam.mails",)

    # Include 250 chars inside email collection entry
    MSG_THRESHOLD = 250

    # See https://github.com/SpamScope/spamscope/blob/develop/src/modules/utils.py + own modification
    RE_URL = re.compile(
        r"((?:(?:ht|f)tp(?:s?)|smb|ssh\:\/\/)(?:[!#$&-;=?-\[\]_a-z~]|%[0-9a-f]{2})+)",
        re.I,
    )

    # Regular expressions to find passphrases for OP ZipLock
    RE_PASS_PATTERNS = [
        r"Password:\s?([a-zA-Z0-9]*)",
        r"Archive pass:\s?([a-zA-Z0-9]*)",
        r"zip pass\s?([-a-zA-Z0-9]*)",
        r"Password\s-\s([a-zA-Z0-9]*)",
    ]

    def process(self, feed_entry):
        feed_payload = feed_entry.payload
        sha256 = feed_payload["sha256"]

        data = feed_entry.payload["msg"]

        try:  # Catches unexpected exceptions of eml_parser.EmlParser
            ep = eml_parser.EmlParser(
                include_raw_body=True, include_attachment_data=True
            )
            eml_dict = ep.decode_email_bytes(data.encode("utf-8"))
        except BaseException as e:
            logger.error(e)
            logger.error(f"eml_parser unable to parse message - {sha256}")
            return None, None

        attachments, files = self.extract_attachments(eml_dict)
        ts = self.retrieve_datetime_in_utc(eml_dict)

        src_raw = self.find_sender(eml_dict)
        source = NetworkEntityFactory.get_from_ip(
            src_raw, 25, EntityEnum.smtp_server, timestamp=ts
        )
        dest_raw = self.find_receiver(eml_dict)
        dest = NetworkEntityFactory.get_from_ip(
            dest_raw, 25, EntityEnum.honeypot, timestamp=ts
        )

        urls = []
        domains = []
        message = []

        if eml_dict.get("body"):
            # Extract URLs
            urls = self.extract_urls_dm(eml_dict)
            domains = self.extract_domains(eml_dict)

            # Extract content for preview
            message = eml_dict.get("body", {})[0].get("content", "")
            message = (
                message[: self.MSG_THRESHOLD]
                if len(message) > self.MSG_THRESHOLD
                else message
            )

        cc = eml_dict["header"].get("cc", [])

        message_id_list = eml_dict["header"]["header"].get("message-id")
        message_id = message_id_list[0] if message_id_list else ""

        # Extract subject line and handle empty subject
        subject = eml_dict["header"]["subject"]

        reply_to_raw = eml_dict["header"]["header"].get("reply-to", None)
        reply_to = self.sanitize_address(reply_to_raw[0]) if reply_to_raw else ""

        return_path_raw = eml_dict["header"]["header"].get("return-path", None)
        return_path = (
            self.sanitize_address(return_path_raw[0]) if return_path_raw else ""
        )

        sender = eml_dict["header"].get("from", "")
        recipients = eml_dict["header"].get("to", "")

        related = eml_dict["header"].get("received_ip", [])
        size = len(feed_entry.payload["msg"].encode("utf-8"))
        to = eml_dict["header"]["to"]

        m = Email(
            file_id=feed_entry._id,
            attachments=attachments,
            attachment_count=len(attachments),
            cc=[Address(c) for c in cc],
            destination=dest,
            domains=domains,
            message=message,
            message_id=message_id,
            observer=Observer(feed_entry.identifier),
            recipients=[Address(r) for r in recipients],
            related=related,
            reply_to=Address(reply_to),
            return_path=Address(return_path),
            sender=Address(sender),
            sha256=sha256,
            source=source,
            size=size,
            subject=subject,
            to=[Address(t) for t in to],
            timestamp=ts,
            urls=[u.url for u in urls],
            is_enriched=True,
            raw=data,
        )

        logger.debug("Mail successfully processed")

        return m, [*files, *urls]

    @staticmethod
    def check_payload_integrity(feed_payload):
        calc_hash = sha256(feed_payload["msg"].encode("utf-8")).hexdigest()
        sent_hash = feed_payload["sha256"]
        assert (
            calc_hash == sent_hash
        ), f"Received corrupt payload, hash mismatch: {calc_hash} - {sent_hash}"

        return sent_hash

    @staticmethod
    def sanitize_address(addr):

        pattern = "<(.*@.*)>"
        m = re.search(pattern, addr)
        if m:
            return m.group(1)
        else:
            return addr

    @staticmethod
    def extract_domains(eml_dict):
        domain_candidates = eml_dict.get("body", None)[0].get("domain", [])
        domains = []
        for d in domain_candidates:
            if validators.domain(d):
                domains.append(d)

        return domains

    @classmethod
    def extract_attachments(cls, eml_dict):
        attachments = []
        files = []

        try:
            for attachment in eml_dict["attachment"]:
                # Store as hex string
                b64data = attachment["raw"]
                decoded = base64.b64decode(b64data)
                content_guess = magic.from_buffer(decoded)

                hashes = Hash(
                    md5=attachment["hash"]["md5"],
                    sha1=attachment["hash"]["sha1"],
                    sha256=attachment["hash"]["sha256"],
                    sha512=attachment["hash"]["sha512"],
                )

                a = Extraction(
                    content_guess=content_guess,
                    extension=attachment["extension"],
                    description=attachment["filename"],
                    hash=hashes,
                )
                attachments.append(a)

                if attachment["extension"] in File.ARCHIVE_EXTS:
                    password = cls.search_pass(eml_dict)
                else:
                    password = None

                file = File(
                    content_guess=content_guess,
                    extension=attachment["extension"],
                    encoding="application/octet-stream",  # alternative: "hex"
                    filename=attachment["filename"],
                    hash=hashes,
                    blob=decoded,
                    timestamp=cls.retrieve_datetime_in_utc(eml_dict),
                    password=password,
                )
                files.append(file)
            logger.debug(f"Extracted {len(attachments)} attachments")
        # KeyError occurs, when there is no attachment, just swallow it
        except KeyError:
            pass

        return attachments, files

    @classmethod
    def search_pass(cls, eml_dict):
        logger.debug("Searching for password in mail body")
        for ptr in cls.RE_PASS_PATTERNS:
            for c in eml_dict["body"]:
                match = re.search(ptr, c["content"])
                if match:
                    logger.info(f"Found password {match.groups()[0]}")
                    return match.groups()[0]

        return None

    @classmethod
    def extract_urls_dm(cls, eml_dict):
        url_list = []
        ts = cls.retrieve_datetime_in_utc(eml_dict)
        if len(eml_dict["body"]) > 0:
            for b in eml_dict["body"]:
                uris = b.get("uri", [])
                for i, uri in enumerate(uris):
                    if re.match(cls.RE_URL, uri):
                        url_list.append(Url(uri, ts))

        return url_list

    @staticmethod
    def extract_urls(o_data):
        url_list = []

        try:
            uris = o_data["body"][0]["uri"]
            for i, url in enumerate(uris):
                url_list.append({"url": {"url": url}})

        # Catches KeyError, which occur, if there's no URL
        except KeyError:
            # No urls in mail
            return []

        return url_list

    @staticmethod
    def is_public_ip(ip):
        ip_obj = IPAddress(ip)

        if not ip_obj.is_private() and not ip_obj.is_reserved():
            return True

        return False

    @classmethod
    def find_sender(cls, eml_dict):
        xorgip = cls.retrieve_header_field(eml_dict, "x-originating-ip")
        recv_srv_list, recv_ip_list = cls.retrieve_mtas(eml_dict)

        if xorgip:
            # X-Originating-IP is stored in a list e.g. "[185.189.xxx.xx]"
            xorgip = xorgip.replace("[", "").replace("]", "")

            # Overcomes situations, where one of the MTAs stores X-Org-IP
            # from another MTA and not from submitting client
            if xorgip not in recv_ip_list:
                return xorgip

        extern_ips = cls.find_extern(recv_srv_list, recv_ip_list)

        if len(extern_ips) > 0:
            return extern_ips[-1]

        return None

    @classmethod
    def find_receiver(cls, eml_dict):
        recv_srv_list, recv_ip_list = cls.retrieve_mtas(eml_dict)
        extern_ips = cls.find_extern(recv_srv_list, recv_ip_list)

        if len(extern_ips) > 1:
            return extern_ips[0]
        else:  # take private ip

            """
            #pprint.pprint(eml_dict['header']['received'][0])
            #pprint.pprint(eml_dict['header']['received'])
            i = 0
            #print(eml_dict['header']['received'])
            max = len(eml_dict['header']['received'])
            while i < max:
                by = eml_dict['header']['received'][i].get("by", None)

                if by and len(by) > 0:
                    addr = by[1]  #[ip, hostname]
                    # Workaround for eml_parser's IPv6 parsing errors
                    # TODO remove, when fixed
                    #if addr.startswith("6:"):
                    #    addr = addr[2:]

                    return addr

                i += 1
            """
            return None  # eml_dict['header']['received'][i]['by'][0]

    @staticmethod
    def retrieve_mtas(eml_dict):
        recv_srvs = []
        for field in eml_dict["header"]["received"]:
            recv_srv = field.get("from", None)
            if recv_srv:
                recv_srvs.append(recv_srv)

        recv_ips = []

        try:
            for val in eml_dict["header"]["received_ip"]:
                # print("Received-IP: " + val)
                recv_ips.append(val)
        except:
            pass

        return recv_srvs, recv_ips

    @staticmethod
    def find_extern(recv_srvs, recv_ips):
        """
        This double checking is necessary, because eml_parser greps IPs and stores them in m['header']['received_ip'],
        which are actually not a sending address!!!

        :param recv_srvs:
        :param recv_ips:
        :return:
        """
        extern_list = []
        for s in recv_srvs:
            for i in s:
                for rip in recv_ips:
                    if rip == i:
                        if MailProcessor.is_public_ip(i):
                            if i not in extern_list:
                                extern_list.append(i)
        return extern_list

    @staticmethod
    def retrieve_header_field(eml_dict, key):
        if key in eml_dict["header"]["header"].keys():
            for val in eml_dict["header"]["header"][key]:
                return val

    @staticmethod
    def retrieve_datetime_in_utc(eml_dict):
        return eml_dict["header"]["date"]
