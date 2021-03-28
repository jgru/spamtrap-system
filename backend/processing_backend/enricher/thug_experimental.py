import logging
import thug
from thug.ThugAPI import ThugAPI
from thug.ThugAPI.Watchdog import Watchdog
from thug.DOM.DFT import DFT
import STPyV8
import json
import tempfile
#thug.__configuration_path__ = "/etc/config/thug/"
import base64
import sys
import pprint

logger = logging.getLogger(__name__)


# See https://github.com/SpamScope/spamscope/blob/develop/src/modules/attachments/thug_analysis.py
class CustomWatchdog(Watchdog):
    log = logging.getLogger("Thug")

    def __init__(self, time, callback=None):
        Watchdog.__init__(self, time, callback=callback)

    def handler(self, signum, frame):
        """
        Handles Thug timeout to suppress general SIGTERM.

        """
        msg = "The analysis took more than {} seconds.".format(self.time)
        self.log.critical(msg)

        if self.callback:
            self.callback(signum, frame)

        self.log.ThugLogging.log_event()
        raise Exception(msg)


class ThugAnalyzer(ThugAPI):
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
        #self.threshold = 2

        #self.set_log_dir("../")
        # No console log
        #self.set_log_quiet()
        #self.set_log_output("./log")

    def _ThugAPI__run(self, window):
        with STPyV8.JSLocker():
            with CustomWatchdog(self.log.ThugOpts.timeout,
                                callback=self.watchdog_cb):
                dft = DFT(window)
                dft.run()


    # See: https://github.com/SpamScope/spamscope/blob/develop/src/modules/attachments/thug_analysis.py
    def generate_json_report(self):
        """
        Return JSON Thug report from logging
        """
        if not self.log.ThugOpts.json_logging:
            return

        p = self.log.ThugLogging.modules.get('json', None)
        if p is None:
            return

        m = getattr(p, 'get_json_data', None)
        if m is None:
            return

        try:
            report = json.loads(m(tempfile.gettempdir()))
        except TypeError:
            return
        else:
            return report

    def analyze(self, url):
        #self.set_mongodb_address("mongodb://127.0.0.1:27017")
        #self.set_mongodb_address("127.0.0.1:27017")
        self.set_elasticsearch_logging()
        # Set useragent to Internet Explorer 9.0 (Windows 7)
        self.set_useragent('win7ie90')
        #self.set_timeout(str(self.timeout))

        # Enable file logging mode
        #self.set_file_logging()

        # Enable JSON logging mode (requires file logging mode enabled)
        self.set_json_logging()
        #self.set_log_dir("/media/user01/data/Dropbox/study/masterthesis/lab/spamtrap-backend/config/thug/etc/thug")
        #self.set_log_output("testlog")
        # Set referer to http://www.honeynet.org
        #self.set_referer(self.referer)
        self.set_debug()
        #self.set_broken_url()
        # Initialize logging
        self.log_init(url)

        # Run analysis
        self.run_remote(url)

        # Log analysis results
        self.log_event()

        return self.generate_json_report()

if __name__ == "__main__":
    t = ThugAnalyzer("../../config/thug/")
    #js = t.analyze("https://hide.maruo.co.jp/software/bin3/hm896b4_signed.exe")
    js = t.analyze("http://192.168.178.134:8080/pGxeS5Q1VY2jq")
    #js = t.analyze("https://hide.maruo.co.jp/software/bin3/hm896b4_signed.exe")

    #js = t.analyze("https://elearning.hs-albsig.de/goto.php?target=crs_302506&client_id=HS-ALBSIG")
    #js = t.analyze("https://webconf.vc.dfn.de/df-20201117-m117/")
    #js = t.analyze("https://elearning.hs-albsig.de/login.php?target=crs_302506&cmd=force_login&lang=de")
    pprint.pprint(js)
    for elem in js['files']:
        for k,v in elem.items():
            if k == "data":
                blob = base64.b64decode(elem[k])
                with open("test", "wb") as f:
                    f.write(blob)



