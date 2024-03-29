import argparse
import asyncio
import logging
import signal
import time

import yaml

from .aioimap_collector import AsyncIMAPCollector, CollectorManager
from .aiolmtp_collector import CustomLMTPHandler, LMTPController
from .message_distributor import MessageDistributor

logger = logging.getLogger()


def read_config(path_to_config):
    with open(path_to_config, "r") as ymlfile:
        cfg_dict = yaml.safe_load(ymlfile)
    return cfg_dict


def setup_logging(file_log=None, customize_aioimaplib=False):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    # Define syslog style logging; maybe include T%(thread)d
    formatter = logging.Formatter(
        "%(asctime)-15s %(levelname)s %(module)s P%(process)d %(message)s"
    )

    if file_log:
        file_log = logging.FileHandler(file_log)
        file_log.setLevel(logging.DEBUG)
        file_log.setFormatter(formatter)
        logger.addHandler(file_log)

    console_log = logging.StreamHandler()
    console_log.setLevel(logging.DEBUG)
    console_log.setFormatter(formatter)
    logger.addHandler(console_log)


def customize_aioimaplib_logger(formatter, file_log=None):
    aioimaplib_logger = logging.getLogger("aioimaplib.aioimaplib")
    aioimaplib_logger.addHandler(formatter)

    if file_log:
        aioimaplib_logger.addHandler(file_log)


async def shutdown(signal, loop):
    """Cleanup tasks tied to the service's shutdown."""
    logging.info(f"Received exit signal {signal.name}...")

    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    try:
        [task.cancel() for task in tasks]
        logging.info(f"Cancelling {len(tasks)} tasks")
        logging.info(f"Wait at least {2 * AsyncIMAPCollector.START_TIMEOUT} secs")
        await asyncio.gather(*tasks, return_exceptions=True)
    except Exception as e:
        logger.info(e)
    logging.info(f"Cancelled {len(tasks)} tasks")
    loop.stop()


def register_signals(loop):
    signals = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)
    for s in signals:
        loop.add_signal_handler(s, lambda s=s: asyncio.create_task(shutdown(s, loop)))


def get_lmtp_args():
    parser = argparse.ArgumentParser(
        description="Catch all LMTP-server, which run behind a Postfix to forward all emails to a hpfeeds broker."
    )
    parser.add_argument(
        "-f",
        "--feed-config",
        type=str,
        default="/usr/local/etc/feed_config.yml",
        help="Config file in yaml-syntax specifying broker to use",
    )
    parser.add_argument(
        "-m",
        "--maildir",
        type=str,
        help="Path to an eventual backup maildir, so that messages do not get lost, if broker or subscribers are not available.",
    )
    parser.add_argument(
        "-p",
        "--port",
        type=int,
        default=24,
        help="Port, where the LMTP server is listening on",
    )
    args = parser.parse_args()

    return args


def run_lmtp(port, maildir, conf):
    setup_logging()
    args = get_lmtp_args()
    conf = read_config(args.feed_config)
    loop = asyncio.new_event_loop()
    q = asyncio.Queue()

    # Set up and run hpfeeds distributor
    distributor = MessageDistributor.get_distributor(**conf)
    loop.create_task(distributor.distribute_queued(q))

    # Create SMTP server and run it
    handler = CustomLMTPHandler(maildir, q)

    # Hands over loop to controller, to ensure distributor and server are attached to the same loop
    server = LMTPController(
        handler, hostname="", port=port, loop=loop, enable_SMTPUTF8=True
    )

    # The event loop is run by the controller
    server.start()

    logger.info("LMTP server running")

    try:
        # AIOSMTPD runs the loop itself
        server = run_lmtp(args.port, args.maildir, conf)
        # Block main thread and stop server, which closes the event loop, when SIGINT is received
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()


def log_config(args):
    logger.info(f"Config mailboxes: {args.mailbox_config}")
    logger.info(f"Config broker: {args.feed_config}")
    logger.info(f"Config fetch : {args.fetch_all}")
    logger.info(f"Config delete: {args.delete}")
    logger.info(f"Config continuous_fetch: {args.continuous_fetch}")


def get_imap_args():
    parser = argparse.ArgumentParser(
        description="Retrieves emails from an IMAP server in an async manner. Tested with gmail and dovecot."
    )
    parser.add_argument(
        "-f",
        "--feed-config",
        type=str,
        default="./config/feed_config.yaml",
        help="Config file in yaml syntax specifying broker to use",
    )
    parser.add_argument(
        "-m",
        "--mailbox-config",
        type=str,
        default="./config/mailbox_credentials.yaml",
        help="Config file in yaml syntax specifying mailboxes to query",
    )
    parser.add_argument(
        "-a",
        "--fetch-all",
        action="store_true",
        help="Fetch all messages in INBOX, otherwise fetch only, unseen msgs",
    )
    parser.add_argument(
        "-d",
        "--delete",
        action="store_true",
        help="Delete messages after fetch (doublecheck, that broker is available!)",
    )
    parser.add_argument(
        "-c",
        "--continuous-fetch",
        action="store_true",
        help="Perform single fetch only, otherwise fetcher runs continuosly",
    )

    args = parser.parse_args()
    # args.fetch_all = False
    # args.continuous_fetch = False

    return args


def run_imap_collector():
    # Start logging
    setup_logging(customize_aioimaplib=True)
    # Parse CLI
    args = get_imap_args()
    log_config(args)

    # Prepare collection
    cm = CollectorManager(**vars(args))

    # Get loop and setup signal handling
    loop = asyncio.new_event_loop()
    register_signals(loop)

    try:
        logging.info("Starting async mail collector...")
        loop.run_until_complete(cm.harvest())
    except (asyncio.TimeoutError, asyncio.CancelledError):
        logger.debug("Main loop stopped")
