import argparse
import asyncio
import json
import logging
import ssl
import time
from abc import ABC, abstractmethod

import aioimaplib
import yaml

from .feed_distributor import AMQPDistributor, HpfeedsDistributor

logger = logging.getLogger(__name__)


class AsyncIMAPCollector:
    INBOX = "INBOX"
    MAILSTATE = "UNSEEN"
    START_TIMEOUT = 5

    # Don't go lower as 5 secs, some MDAs will refuse to inform you about new msg
    # they send 'stop_wait_server_push' all the time all the time, even if there are new msgs
    CHECK_TIMEOUT = 5

    def __init__(
        self,
        protocol,
        host,
        port,
        username,
        password,
        fetch_all=False,
        delete=False,
        continuous_fetch=True,
    ):
        logger.info(f"Creating collector for {username}")
        self.protocol = protocol
        self.mail_host = host
        self.mail_port = port
        self.user = username
        self.pw = password
        self.fetch_all = fetch_all
        self.is_delete = delete
        self.continuous_fetch = continuous_fetch
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
        self.enabled = False

    def __str__(self):
        return str(self.__dict__)

    def check_msg_count(self, info_list):
        logger.info(f"Checking message count for {self.user}")

        # Loop over info list and check for relevant keywords
        for elem in info_list:
            elem = elem.decode()

            if "EXISTS" in elem:
                logger.info(f'{self.user}: {elem.split(" EXISTS")[0]} msgs in total')
            elif "RECENT" in elem:
                msg_count = elem.split(" RECENT")[0]
                logger.info(f"{self.user}: {msg_count} new msgs")
                if int(msg_count) > 0:
                    return True
        return False

    async def connect(self):
        imap_client = aioimaplib.IMAP4_SSL(
            host=self.mail_host, port=self.mail_port, ssl_context=self.ctx
        )
        await imap_client.wait_hello_from_server()

        result, lines = await imap_client.login(self.user, self.pw)

        if result != "OK":
            logger.debug(f"Could not login to {self.user}")
            logger.debug(f"{result}, {lines}")
        return imap_client

    async def check_mailbox(self, queue):
        logger.debug(f"Fetching messages for {self.user}")
        imap_client = await self.connect()
        res, data = await imap_client.select(self.INBOX)
        has_new = self.check_msg_count(data)

        resp = ""
        items = []

        if self.fetch_all:
            resp, items = await imap_client.search("ALL")
        elif has_new:
            resp, items = await imap_client.search("UNSEEN")

        if resp == "OK":
            await self.fetch_and_queue(imap_client, items, queue)

        if self.continuous_fetch:
            await asyncio.sleep(self.CHECK_TIMEOUT)
            await self.wait_for_new_message(imap_client, queue)
        else:
            await imap_client.logout()

    @staticmethod
    async def fetch_and_queue(imap_client, items, queue):
        if (
            len(items[0]) > 0
        ):  # items => ['46 47', 'Search completed (0.001 + 0.000 secs).']
            logger.info(f"Fetching new mails")
            mail_ids = items[0].split(" ")
            for mail_id in mail_ids:
                logger.info(f"Processing {mail_id}")
                # data = ['1 FETCH (FLAGS (\\Seen) RFC822 {3755}', bytes, fetch time]
                result, data = await imap_client.fetch(mail_id, "(RFC822)")

                await queue.put(data[1])

    # wait for new mail messages without using CPU - see RFC2177
    async def wait_for_new_message(self, imap_client, queue):
        logger.debug(f"Waiting on new messages for {self.user}")

        self.enabled = True
        start = time.time()
        try:
            while self.enabled:
                idle = await imap_client.idle_start(timeout=self.START_TIMEOUT)
                msg = await imap_client.wait_server_push()
                logger.info(f"{self.user} -{msg}")  # Print debugging purposes
                imap_client.idle_done()

                # Resulting msgs to expect:
                # For idle: ['OK Still here'], "stop_wait_server_push" for idle
                # If there is new mail: ['48 EXISTS', '1 RECENT']<-dovecote, ['+ idling]<- Gmail IMAP
                if isinstance(msg, list):
                    # EXISTS is standard dovecot, "+ idling" is Google IMAP
                    if "EXISTS" in msg[0] or "+" in msg[0]:
                        resp, items = await imap_client.search("UNSEEN")
                        if resp == "OK":
                            await self.fetch_and_queue(imap_client, items, queue)

                # Reconnect after 20 minutes
                if time.time() - start > 1200:
                    await imap_client.logout()
                    imap_client = await self.connect()
                    await imap_client.select(self.INBOX)

                await asyncio.wait_for(idle, self.CHECK_TIMEOUT)

        except asyncio.CancelledError:
            self.enabled = False
        except asyncio.TimeoutError:
            logger.debug("Timeout error")
        finally:
            await imap_client.logout()


class CollectorManager:
    def __init__(
        self,
        feed_config,
        mailbox_config,
        fetch_all=False,
        delete=False,
        continuous_fetch=False,
    ):
        logger.info("Created CollectorManager")
        self.accounts = self.read_account_config(
            mailbox_config, fetch_all, delete, continuous_fetch
        )
        self.distributor = HpfeedsDistributor(**self.read_config(feed_config))

    async def harvest(self):

        logging.info(f"Starting to harvest with {len(self.accounts)} collectors...")
        loop = asyncio.get_running_loop()
        q = asyncio.Queue()

        # Distribute messages as background task
        distributor_coro = loop.create_task(self.distributor.distribute_queued(q))
        tasks = []

        for acc in self.accounts:
            tasks.append(acc.check_mailbox(q))

        await asyncio.gather(*tasks)

        logging.info(f"Mailbox coros completed")
        distributor_coro.cancel()
        await distributor_coro

    def read_account_config(self, account_config, fetch_all, delete, continuous_fetch):
        accounts_as_json = self.read_config(account_config)
        accounts = []
        for acc in accounts_as_json:
            logging.info(f"Parsed account config for {acc['username']}")
            accounts.append(
                AsyncIMAPCollector(
                    **acc,
                    fetch_all=fetch_all,
                    delete=delete,
                    continuous_fetch=continuous_fetch,
                )
            )

        return accounts

    @staticmethod
    def read_config(path_to_config):
        with open(path_to_config, "r") as ymlfile:
            cfg_dict = yaml.safe_load(ymlfile)
        return cfg_dict
