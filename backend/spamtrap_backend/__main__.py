import argparse
import asyncio
import logging
import signal

import yaml

from . import datamodels
from .connectors.enricher.enricher import Enricher
from .connectors.reporter.reporter import Reporter
from .core.database import DatabaseHandler
from .core.mediator import Mediator
from .core.message_ingestor import MessageIngestor
from .core.processor.processor import Processor

logger = logging.getLogger()


def setup_logging(logfile=None):
    # Clean all handlers, which are polluted from Thug
    for h in logger.handlers:
        logger.removeHandler(h)

    logger.setLevel(logging.DEBUG)

    # Define syslog style logging; maybe include T%(thread)d
    formatter = logging.Formatter(
        "%(asctime)-15s %(levelname)s %(module)s P%(process)d %(message)s"
    )

    if logfile:
        file_log = logging.FileHandler(logfile)
        file_log.setLevel(logging.DEBUG)
        file_log.setFormatter(formatter)
        logger.addHandler(file_log)

    console_log = logging.StreamHandler()
    console_log.setFormatter(formatter)
    console_log.setLevel(logging.DEBUG)
    logger.addHandler(console_log)


async def shutdown(recv_sig, loop):
    """
    Stops all tasks to enable controlled shutdown behaviour
    See Hattingh, Using AsyncIO in Python, p. 68 and
    https://gist.github.com/nvgoldin/30cea3c04ee0796ebd0489aa62bcf00a
    for code reference.

    """
    logging.info(f"Received exit signal {recv_sig.name}...")

    # To avoid multiple executions
    loop.remove_signal_handler(recv_sig.SIGTERM)
    loop.remove_signal_handler(recv_sig.SIGINT)
    loop.remove_signal_handler(recv_sig.SIGHUP)

    tasks = [
        t
        for t in asyncio.all_tasks()
        if t != asyncio.current_task() and not t.cancelled() and not t.done()
    ]

    try:
        [task.cancel() for task in tasks]
        logging.info(f"Cancelling {len(tasks)} tasks")

        await asyncio.gather(*tasks, return_exceptions=True)

    except Exception as e:
        logger.info(e)

    logging.info(f"Cancelled {len(tasks)} tasks")
    loop.stop()


def register_signals(loop):
    signals = (signal.SIGHUP, signal.SIGTERM, signal.SIGINT)
    for s in signals:
        loop.add_signal_handler(s, lambda s=s: asyncio.create_task(shutdown(s, loop)))

    logger.info("Registered signal handlers")


def parse_config(path_to_config):
    with open(path_to_config, "r") as ymlfile:
        cfg_dict = yaml.safe_load(ymlfile)
    return cfg_dict


NUM_MEDIATORS = 1  # 12
NUM_PROCESSORS = 1  # 6  # Should not exceed available cores
NUM_ENRICHERS = 1  # Should be oriented at the number of availables analysis guests


def parse_args():
    parser = argparse.ArgumentParser(
        description="Processing backend of spamtrap system. This component is able to"
        "subscribe to hpfeeds-channel and receive messages in th eform of"
        "JSON files from there. These messages will be persisted, further"
        "processed depending on the name of the originating channel, enriched"
        "with the help of Thug and Cuckoo and reported to an Elastic stack."
    )
    parser.add_argument(
        "--config",
        dest="config_file",
        default="./config/backend.yml",
        help="A YAML-file, which is used to specify the components"
        "to run and services to contact.",
    )
    args = parser.parse_args()

    return args.config_file


def read_config(cfg_path):
    # Read config file in YAML-syntax
    conf = parse_config(cfg_path)

    return conf


def run_backend(config):
    logger.info("Starting spamtrap backend")

    # # Retrieves reference on event loop
    loop = asyncio.new_event_loop()  # asyncio.get_running_loop()

    # Handles SIGINT, SIGTERM, SIGHUP
    register_signals(loop)

    # Sets Geo-IP-database, if specified in config file
    datamodels.NetworkEntityFactory.GEO_DB = (
        config.get("geo_db")
        if config.get("geo_db")
        else datamodels.NetworkEntityFactory.GEO_DB
    )

    # Creates the components:
    #
    # Creates the ingestor dealing with hpfeeds messages
    ingestor = MessageIngestor.get_message_ingestor(**config["ingesting"])

    # Turnstile of dataflow
    mediator_queue = asyncio.Queue()

    # Starts ingesting of hpfeeds
    loop.create_task(ingestor.ingest(queue=mediator_queue))

    # Defines processors and creates corresponding async tasks
    processor = Processor()
    process_queue = asyncio.Queue(
        maxsize=1000  # await put() blocks when the queue reaches maxsize
    )

    for _ in range(NUM_PROCESSORS):
        loop.create_task(processor.decompose_from_stream(process_queue, mediator_queue))

    # Starts enricher, if enabled in config
    enrich_queue = asyncio.Queue()
    report_queue = asyncio.Queue()

    docs_to_enrich = set.union(
        *map(
            set,
            [
                d.get("relevant_documents")
                for k, d in config["peripherals"].items()
                if d.get("enrich", False) and d.get("enabled", False)
            ],
        ),
        set(),  # Append empty set
    )

    docs_to_report = set.union(
        *map(
            set,
            [
                d.get("relevant_documents")
                for k, d in config["peripherals"].items()
                if not d.get("enrich", False) and d.get("enabled", False)
            ],
        ),
        set(),  # Append empty set
    )

    enrich_queue, report_queue = start_connectors(
        config,
        loop,
        mediator_queue,
    )
    logger.debug(config["peripherals"].items())

    # Creates the mediator who distributes messages and artifacts
    mediator = Mediator(docs_to_enrich, docs_to_report, **config["persistance"])

    # Defines mediator tasks, which distribute elements to the responsible components
    for _ in range(NUM_MEDIATORS):
        loop.create_task(
            mediator.mediate(mediator_queue, process_queue, enrich_queue, report_queue)
        )
    # Runs the loop until shutdown is induced by signaling
    loop.run_forever()


def start_connectors(config, loop, mediator_queue):
    report_queue = None
    enrich_queue = None

    enriching_connectors = {
        k: d
        for k, d in config["peripherals"].items()
        if d.get("enrich", False) and d.get("enabled", False)
    }

    if any(enriching_connectors):
        # Defines enrichers and creates corresponding async tasks
        enricher = Enricher(**enriching_connectors)
        enrich_queue = asyncio.Queue(maxsize=1000)

        for _ in range(NUM_ENRICHERS):
            loop.create_task(enricher.enrich_from_stream(enrich_queue, mediator_queue))

    reporting_connectors = {
        k: d
        for k, d in config["peripherals"].items()
        if not d.pop("enrich", False) and d.get("enabled", False)
    }

    if any(reporting_connectors):
        # Defines reporter and creates corresponding async task
        reporter = Reporter(**reporting_connectors)
        report_queue = asyncio.Queue(maxsize=1000)
        loop.create_task(reporter.report_from_stream(report_queue))

    return enrich_queue, report_queue


def main():
    cfg_path = parse_args()
    config = read_config(cfg_path)

    # Setup logging environment
    setup_logging(config["logging"]["file"])
    del config["logging"]

    run_backend(config)


if __name__ == "__main__":
    main()
