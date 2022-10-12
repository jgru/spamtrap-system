import argparse
import logging
import tempfile

from thug.ThugAPI import ThugAPI

logger = logging.getLogger(__name__)


class ThugAnalyzer(ThugAPI):
    """
    Specifically configured wrapper class providing Thug's funtionality.

    """

    log = logging.getLogger("Thug")

    def __init__(self, configuration_path="./config/thug", timeout=10):
        logger.info(f"Starting ThugAnalyzer using config in {configuration_path}")
        ThugAPI.__init__(self, configuration_path=configuration_path)

        self.referer = "http://www.google.com/"
        self.timeout = timeout
        self.set_timeout(timeout)

        self.connect_timeout = 1
        self.set_connect_timeout(self.connect_timeout)

        self.disable_cert_logging()
        self.disable_code_logging()

        # No console log, just return resulting JSON
        self.set_log_quiet()

    def generate_json_report(self):
        """
        Return JSON Thug report from logging. Taken from
        https://github.com/SpamScope/spamscope/blob/develop/src/modules/attachments/thug_analysis.py

        :return: str, analysis result as JSON log
        """
        if not self.log.ThugOpts.json_logging:
            return

        p = self.log.ThugLogging.modules.get("json", None)
        if p is None:
            return

        m = getattr(p, "get_json_data", None)
        if m is None:
            return

        try:
            report = m(tempfile.gettempdir())
        except TypeError:
            return
        else:
            return report

    def analyze(self, url):
        """
        Performs an analysis of the given URL
        :param url: str, URL to analyze
        :return: str, analysis resulst as JSON log

        """
        # Set useragent to Internet Explorer 9.0 (Windows 7)
        self.set_useragent("win7ie90")

        # Enable JSON logging mode (requires file logging mode enabled)
        self.set_json_logging()

        # Initialize logging
        self.log_init(url)

        # Run analysis
        self.run_remote(url)

        # Log analysis results
        self.log_event()

        return self.generate_json_report()


def run_thug(url, timeout, config_dir):
    """
    Conveniance helper function to kick of Thug analysis and print the resulting analysis report JSON to stdout

    :param url: str, URL to analyze
    :param config_dir: str, path to the direction, where Thugs configuration files (scripts, personalities,...) reside

    :return: None, print analysis result as JSON string on stdout
    """
    thug_instance = ThugAnalyzer(config_dir, timeout=timeout)
    json_log = thug_instance.analyze(url)

    # Prints result in form of a JSON log to stdout
    print(json_log)


def get_args():
    """
    Helper function to retrieve command line arguments
    :return:
    """
    parser = argparse.ArgumentParser(
        description="Run Thug from the command line"
    )
    parser.add_argument(
        "-c",
        "--config-dir",
        type=str,
        default="../../config/thug",
        help="Config file in yaml syntax specifying broker to use",
    )
    parser.add_argument("-u", "--url", type=str, required=True, help="URL to analyze")
    parser.add_argument(
        "-t",
        "--timeout",
        default=15,
        type=int,
        help="Analysis timeout for each page (redirects also) in seconds",
    )
    parsed_args = parser.parse_args()

    return parsed_args


if __name__ == "__main__":
    args = get_args()
    run_thug(args.url, args.timeout, config_dir=args.config_dir)
