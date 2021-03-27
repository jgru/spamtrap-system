import argparse
import asyncio
import logging
import time

import aiosmtpd.controller
import aiosmtpd.handlers
import aiosmtpd.lmtp
import yaml

from catchall_lmtp.feed_distributor import HpfeedsDistributor
from catchall_lmtp.lmtp_server import CustomLMTPHandler
from catchall_lmtp.lmtp_server import LMTPController
logger = logging.getLogger()


def read_config(path_to_config):
    with open(path_to_config, "r") as ymlfile:
        cfg_dict = yaml.safe_load(ymlfile)
    return cfg_dict


def setup_logging(file_log=None):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    # Define syslog style logging; maybe include T%(thread)d
    formatter = logging.Formatter('%(asctime)-15s %(levelname)s %(module)s P%(process)d %(message)s')

    if file_log:
        file_log = logging.FileHandler(file_log)
        file_log.setLevel(logging.DEBUG)
        file_log.setFormatter(formatter)
        logger.addHandler(file_log)

    console_log = logging.StreamHandler()
    console_log.setLevel(logging.DEBUG)
    console_log.setFormatter(formatter)
    logger.addHandler(console_log)


def get_args():
    parser = argparse.ArgumentParser(description="Catch all LMTP-server, which run behind a Postfix to forward all emails to a hpfeeds broker.")
    parser.add_argument("-f", "--feed-config", type=str, default="/usr/local/etc/feed_config.yml",
                        help="Config file in yaml-syntax specifying broker to use")
    parser.add_argument("-m", "--maildir", type=str,
                        help="Path to an eventual backup maildir, so that messages do not get lost, if broker or subscribers are not available.")
    parser.add_argument("-p", "--port", type=int, default=24, help="Port, where the LMTP server is listening on")
    args = parser.parse_args()
    args.feed_config = "./feed_config.yml"
    args.maildir = "./data"
    args.port = 8824
    return args


def run_lmtp(port, maildir, conf):
    loop = asyncio.get_event_loop()
    q = asyncio.Queue()

    # Set up and run hpfeeds distributor
    distributor = HpfeedsDistributor(**conf)
    loop.create_task(distributor.distribute_queued(q))

    # Create SMTP server and run it
    handler = CustomLMTPHandler(maildir, q)

    # Hands over loop to controller, to ensure distributor and server are attached to the same loop
    server = LMTPController(handler, hostname="", port=port, loop=loop, enable_SMTPUTF8=True)

    # The event loop is run by the controller
    server.start()

    logger.info("LMTP server running")

    return server


if __name__ == '__main__':
    setup_logging()
    logging.info("Starting async catch-all SMTP server...")
    args = get_args()
    conf = read_config(args.feed_config)

    server = None

    try:
        # AIOSMTPD runs the loop itself
        server = run_lmtp(args.port, args.maildir, conf)
        # Block main thread and stop server, which closes the event loop, when SIGINT is received
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()
