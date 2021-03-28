#!/usr/bin/python3

import argparse
import asyncio
import base64
import code
import copy
import email
import email.header
import email.utils
import enum
import json
import logging
import mailbox
import os
# This module does not work on Windows
# pylint: disable=import-error
import readline
import smtplib
import ssl
import sys
import unicodedata
from contextlib import ExitStack
from datetime import date
from datetime import datetime
from email import message_from_bytes, message_from_string
from email import policy
from hashlib import sha256
from logging.handlers import TimedRotatingFileHandler
# TOOD: P3 - See if we can disabled it - used for a handy shortcut to identify Lambda
# pylint: disable=unused-wildcard-import
from urllib.request import urlopen

import dns.resolver
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP, syntax
from hpfeeds.asyncio import ClientSession

log = logging.getLogger('mail.fosr')
COMMASPACE = ', '


class HpfeedsDistributor:
    """Distributes mail to hpfeeds broker"""

    def __init__(self, broker="localhost", port=20000, tls=True, identity="writer", secret="secret",
                 channels=["spam.mails"]):

        super(HpfeedsDistributor, self).__init__()
        logging.info("Created distributor")
        self.queue = None
        self.identity = identity
        self.broker = broker
        self.port = port
        self.secret = secret
        self.channels = channels
        self.enabled = False
        self.tls_enabled = True if tls == "True" else False

    @staticmethod
    def construct_hpfeeds_msg(msg):
        # logger.info(f'Construction msg')
        msg_digest = sha256(msg).hexdigest()

        # logger.info(f'Received msg from: {parsed_msg["from"]} - {msg_digest}')

        msg_dict = {
            "msg": msg.decode("utf-8"),
            'sha256': msg_digest
        }
        return json.dumps(msg_dict)

    async def distribute(self):
        logging.info(f"Starting to distribute to {self.broker}:{self.port}...")
        self.enabled = True

        if self.tls_enabled:
            # create default SSL context, which requires valid cert chain
            client = ClientSession(self.broker, self.port, self.identity, self.secret, ssl=self.tls_enabled)
        else:
            client = ClientSession(self.broker, self.port, self.identity, self.secret)

        if not self.queue:
            self.queue = asyncio.queues.Queue()

        while self.enabled or self.queue.qsize() > 0:

            try:
                msg = await self.queue.get()
                msg_as_json = self.construct_hpfeeds_msg(msg)
                for c in self.channels:
                    client.publish(c, msg_as_json)

            except asyncio.CancelledError:
                self.enabled = False
                logging.debug(f"Distribution to {self.broker} cancelled")

        logging.debug(f"Stopped to distribute to {self.broker}...")


class GlobalConfig:
    """This class stores the global configurations you may want to adapt for your installation."""

    # FQDN of the honeypot
    FAKE_HOSTNAME = 'mail.localhost'

    # A relative MAILBOX_PATH path will be interpreted starting from the user's home folder
    # A path starting with a . will be interpreted as a relative path
    MAILBOX_PATH = './maildir'
    MAILBOX_INBOX_NAME = 'inbox'
    MAILBOX_LOGS_NAME = 'logs'
    MAILBOX_SENTPROBE_NAME = 'sentProbes'

    # Path to the certificate files to handle command STARTTLS and explicit TLS SMTP
    # You can create such a pair of files using the following command:
    # $ openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem
    INSTALL_CERTIFICATE_CERT_FILE = 'cert.pem'
    INSTALL_CERTIFICATE_KEY_FILE = 'key.pem'

    # You shouldn't run this script as root, but under the identity of a limited user.
    # Thus, this flag allows you to start the SMTP listeners (tcp/25, tcp/465 & tcp/587) under a high port.
    # If BASE_PORT_NUMBER is set to 6000, the SMTP servers will listen on tcp/6025, tcp/6465 & tcp/6587.
    # Traffic redirection to these ports can be achieved in many ways. Two popular options are to use either:
    # - iptable PREROUTING & REDIRECT rules
    # - NATing options on your router connected to the Internet
    BASE_PORT_NUMBER = 6000

    # The script forwards max MAX_RELAY_PER_DAY messages per day to avoid being used as spam relay in case a bug is found and exploited
    MAX_RELAY_PER_DAY = 20

    # Relays the message if the following string is found in the subject of an email
    # To facilitate your tests, consider using swaks:
    # $ swaks --to proberecipient@malicious.com --server smtp.example.org --from victim@example.com --header "Subject: TEST-EMAIL_bd5328c8"
    TEST_PROBE_RELAY_SUBJECT = 'TEST-EMAIL_bd5328c8'
    TEST_PROBE_RELAY_SMTPFROM = 'sender@example.org'
    TEST_PROBE_RELAY_SMTPTO = 'recipient@example.org'
    TEST_PROBE_RELAY_SERVER = [('smtp.example.org', 25)]
    # Set this variable to True if your TEST_PROBE_RELAY_SERVER server supports explicit TLS on tcp/465 or tcp/587
    TEST_PROBE_RELAY_SERVER_EXPLICIT_TLS = False

    # Configuration settings IPV6_* only apply if your machine has IPv6 connectivity to Internet.
    # If your machine does NOT have IPv6, ignore these settings as they are irrelevant for you

    # IPV6_FORCE_IPV4_MX_FOR_DOMAINS forces the script to connect to the IPv4 address of the MX for all listed domains.
    # This is mainly due to some providers (typically GMail) requesting PTR records for IPv6 addresses used to send mails.
    # (see https://github.com/waaeh/FakeOpenSmtpRelay/issues/1)
    # If you have IPv6 connectivity AND you have a valid PTR record for the IPv6 address used to relay mail, simply set [].
    IPV6_FORCE_IPV4_MX_FOR_DOMAINS = ['gmail.com']

    # Dynamic references updated at least daily by class ConfigInEmail
    IPV4 = None
    IPV6 = None

    # Dynamic reference passed on startup via arg --testMode
    TEST_MODE = False
    PORTS = [25, 465, 587]

class Helpers:
    """Helper class with static methods usable in the whole project."""

    @staticmethod
    def get_maildir_path():
        """Returns an absolute path for the maildir folder."""
        if '/' in GlobalConfig.MAILBOX_PATH[0]:
            return os.path.join(GlobalConfig.MAILBOX_PATH)

        if '.' in GlobalConfig.MAILBOX_PATH[0]:
            return os.path.realpath(GlobalConfig.MAILBOX_PATH)

        return os.path.join(os.path.expanduser("~"), GlobalConfig.MAILBOX_PATH)

    @staticmethod
    def get_inbox():
        return Helpers.get_maildir(GlobalConfig.MAILBOX_INBOX_NAME)

    @staticmethod
    def get_maildir(maildir_folder):
        """Returns a mailbox object for a given maildir_folder."""
        mdir = mailbox.Maildir(Helpers.get_maildir_path())
        if maildir_folder == 'inbox':
            return mdir

        if maildir_folder in mdir.list_folders():
            return mdir.get_folder(maildir_folder)
        else:
            return mdir.add_folder(maildir_folder)

    @staticmethod
    def get_mailbox(mailbox_name):
        """Returns a mailbox object for a given mailbox_name."""
        return Helpers.get_maildir(mailbox_name)

    @staticmethod
    def prompt_choice(options, prompt):
        """Proposes options to the choice to the user, with prompt as description."""
        while True:
            output = input(prompt)
            if output in options:
                return output
            else:
                print("Bad option. Options: " + ", ".join(options))

    @staticmethod
    def trim_str(s, l, ellipsis=True):
        """Trims string s to length l-2 and completes the string with "..", unless ellipsis is set to False."""
        if s is None:
            return ""
        if ellipsis:
            return (s[:l - 2] + '..') if len(s) > l else s
        else:
            return (s[:l]) if len(s) > l else s

    @staticmethod
    def get_json_from_url(url):
        """Requests value from url, assumes the response is a JSON string and converts it directly to a Python object."""
        j = json.loads(urlopen(url).read().decode())
        return j

    @staticmethod
    async def check_port(ip, port, loop):
        """Async port scanner - source: http://gunhanoral.com/python/2017/07/04/async-port-check.html"""
        conn = asyncio.open_connection(ip, port, loop=loop)
        try:
            # pylint: disable=unused-variable
            reader, writer = await asyncio.wait_for(conn, timeout=5)
            logging.debug('Helpers.check_port(%s, %i): OK' % (ip, port))
            return {'hostname': ip, 'port': port, 'open': True}
        except:
            logging.debug('Helpers.check_port(%s, %i): NOK' % (ip, port))
            return {'hostname': ip, 'port': port, 'open': False}

    @staticmethod
    async def get_open_tcp_ports_async(dests, ports, loop):
        """Async scheduler for port scanner - source: http://gunhanoral.com/python/2017/07/04/async-port-check.html"""
        tasks = [asyncio.ensure_future(Helpers.check_port(d, p, loop)) for d in dests for p in ports]
        responses = await asyncio.gather(*tasks)
        return responses

    @staticmethod
    def get_open_tcp_ports(hostnames, arr_ports):
        """Async port scanner helper - source: http://gunhanoral.com/python/2017/07/04/async-port-check.html"""
        if Helpers.loop is None:
            Helpers.loop = asyncio.get_event_loop()

        future = asyncio.ensure_future(Helpers.get_open_tcp_ports_async(hostnames, arr_ports, Helpers.loop))
        Helpers.loop.run_until_complete(future)
        return future.result()

    @staticmethod
    def read_config(path_to_config):
        with open(path_to_config, "r") as cf:
            content = cf.read()
        return json.loads(content)


class RelayMessage:
    """Routines to verify if a message can be relayed and perform the relay if desired."""

    def __init__(self, inbox, msgKey):
        self.inbox = inbox
        self.msg = inbox[msgKey]
        self.msgKey = msgKey
        self.canRelay = True
        self.logs = []
        self.rcpt = None
        self.smtpFrom = None
        self.secureConnSupport = False
        self.secureConnList = []
        self.rcptBestMx = []
        self.verifyDone = False
        self.sent_probes_mbox = Helpers.get_mailbox(GlobalConfig.MAILBOX_SENTPROBE_NAME)

    async def verify_async(self):
        if self.msg["X-RcptTo"] is None:
            self.logs.append("No X-RcptTo address")
            self.canRelay = False
        else:
            self.rcpt = self.msg["X-RcptTo"]
            self.logs.append("Email would be relayed to " + self.rcpt)

        # TODO: P2 - consider checking if the from address is a valid email address, as it might hinder some relaying
        if self.msg["X-MailFrom"] is None:
            self.logs.append("No X-MailFrom address")
            self.canRelay = False
        else:
            self.smtpFrom = self.msg["X-MailFrom"]
            self.logs.append("Email would be relayed with SMTP envelope sender " + self.smtpFrom)

        # Get rcpt domain details
        if self.rcpt is not None:
            self.rcptDomain = self.rcpt.split(", ")[0].split("@")[1]
            self.rcptMxAnswers = dns.resolver.query(self.rcptDomain, 'MX')
            self.logs.append("Domain " + self.rcptDomain + " has " + str(len(self.rcptMxAnswers)) + " MX servers: " + (
                "; ".join(map(str, self.rcptMxAnswers))))
            if len(self.rcptMxAnswers) == 0:
                self.logs.append("No MX server for domain " + self.rcptDomain)
                self.canRelay = False

        refPorts = [465, 587]
        mx_servers = [r.exchange.to_text()[:-1] for r in self.rcptMxAnswers]
        scan_results = await Helpers.get_open_tcp_ports_async(mx_servers, refPorts, self.loop)

        # If there are services allowing explicit TLS found...
        secure_services_arr = [m for m in scan_results if m['open'] == True]
        if secure_services_arr:
            self.secureConnSupport = True
            for svc in secure_services_arr:
                self.logs.append("Support for secure port on %s, port %i" % (svc['hostname'], svc['port']))
                self.rcptBestMx.append((svc['hostname'], svc['port']))
        else:
            self.logs.append("No support for secure ports found... ")
            # If no secure port is open, we get the best 3 email servers
            # TODO: P2 have a IPv6 preference for sending emails / selecting exchange servers
            # print(dns.resolver.query('gmail.com', 'MX').response)
            # Explore r.response.additional
            # r.response.additional[1].rdtype etc; 1 = A, 28 = AAAA
            # r.response.additional[1][0].address = IP address
            self.rcptMxAnswers.rrset.items.sort(key=lambda x: x.preference)
            for mx in self.rcptMxAnswers.rrset.items[:3]:
                self.rcptBestMx.append((mx.exchange.to_text()[:-1], 25))

        # Once we have our list of preferred MX servers, we need to check if we have some IPv6 edge case
        if GlobalConfig.IPV6 is not None:
            # Verify the config only if we have an IPv6 address
            if self.rcptDomain in GlobalConfig.IPV6_FORCE_IPV4_MX_FOR_DOMAINS:
                # Get server, resolve ipv4 and force the IPv4 as host
                updated_rcptBestMx = []
                for mx in self.rcptBestMx:
                    mx_a_response = dns.resolver.query(mx[0], 'A')
                    ipv4_of_mx = mx_a_response.rrset[0].address
                    updated_rcptBestMx.append((ipv4_of_mx, mx[1]))

                self.rcptBestMx = updated_rcptBestMx

        self.logs.append("Has support for Secure connexion: " + str(self.secureConnSupport))
        for i in self.rcptBestMx:
            self.logs.append("Possible connexions: %s:%i" % i)

        self.verifyDone = True

    def relay(self, *, interactive=True, force=False):
        """Relays the message; accepts optionnally only named arguments"""

        # We assume that all verifications were done
        if not force and self.verifyDone is False:
            print("Message was not verified first. Perform this action before trying to relay it")
            return

        if not force and self.canRelay is False:
            print("Message cannot be relayed - canRelay = False. See logs for further details")
            return

        new_msg = self.create_relayed_message(self.msg)

        if GlobalConfig.TEST_MODE:
            self.smtpFrom = GlobalConfig.TEST_PROBE_RELAY_SMTPFROM
            self.rcpt = GlobalConfig.TEST_PROBE_RELAY_SMTPTO
            self.rcptBestMx = GlobalConfig.TEST_PROBE_RELAY_SERVER
            self.secureConnSupport = GlobalConfig.TEST_PROBE_RELAY_SERVER_EXPLICIT_TLS

        if interactive:
            print("\n\n" + new_msg.as_string() + "\n")
            print("This message will be sent with SMTP envelop From: %s -> To: %s" % (self.smtpFrom, self.rcpt))
            opt = Helpers.prompt_choice(['Y', 'N'], "Do you want to send this message ([Y]es, [N]o)? ")
            if opt == 'N':
                return

        # Sending the message
        # TODO: P2 enhance error handling and rotate across servers
        self.logs.append("Trying to send message '%s' from %s to %s using server %s..." % (
        new_msg["Subject"], self.smtpFrom, self.rcpt, self.rcptBestMx[0]))
        # if self.secureConnSupport:
        if self.rcptBestMx[0][1] == 465:
            server = smtplib.SMTP_SSL(self.rcptBestMx[0][0], self.rcptBestMx[0][1], GlobalConfig.FAKE_HOSTNAME, None,
                                      None, 30)
        else:
            try:
                server = smtplib.SMTP(self.rcptBestMx[0][0], self.rcptBestMx[0][1], GlobalConfig.FAKE_HOSTNAME, 30)

            except Exception:
                server = smtplib.SMTP(self.rcptBestMx[1][0], self.rcptBestMx[1][1], GlobalConfig.FAKE_HOSTNAME, 30)

        server.set_debuglevel(1)
        smtplib_sendmail_res = None
        smtplib_sendmail_quit = None
        smtplib_sendmail_exception = None
        try:
            # If we're connecting over plain SMTP, we need to
            # 1. send a ehlo
            # 2. check the server capabilities for STARTTLS
            # 3. if available enable STARTTLS and reissue ehlo
            if self.secureConnSupport is False:
                server.ehlo(GlobalConfig.FAKE_HOSTNAME)
                if 'starttls' in server.esmtp_features:
                    server.starttls()

            server.ehlo(GlobalConfig.FAKE_HOSTNAME)
            smtplib_sendmail_res = server.sendmail(self.smtpFrom, self.rcpt, new_msg.as_string())
            smtplib_sendmail_quit = server.quit()
        except Exception as inst:
            print(type(inst))  # the exception instance
            print(inst.args)  # arguments stored in .args
            smtplib_sendmail_exception = inst
            # print(inst)           # __str__ allows args to be printed directly
            self.logs.append("Error while trying to send message: %s" % inst)
            print("Error while trying to send message: %s" % inst)

        self.logs.append("smtplib terminated with sendmail status '%s' and quit '%s'" % (
        smtplib_sendmail_res, smtplib_sendmail_quit))
        print("smtplib terminated with sendmail status '%s' and quit '%s'" % (
        smtplib_sendmail_res, smtplib_sendmail_quit))

        # Store in the sent probes folder
        # Adds the result of the sending probe in a header before storing it
        new_msg.add_header("X-Relay-Sendmail-Date", datetime.now().isoformat())
        new_msg.add_header("X-Relay-Sendmail-Sent", str(smtplib_sendmail_res))
        new_msg.add_header("X-Relay-Sendmail-Quit", str(smtplib_sendmail_quit))
        new_msg.add_header("X-Relay-Sendmail-Exception", str(smtplib_sendmail_exception))
        # Add a flag on the original message in the inbox that the message has been read and answered (RA)
        msg_in_inbox = self.msg
        msg_in_inbox.add_flag("RA")
        self.inbox[self.msgKey] = msg_in_inbox
        self.sent_probes_mbox.add(new_msg)

    def create_relayed_message(self, original_msg):
        msg = copy.copy(original_msg)
        # We first delete all headers we added ourselves
        headers_to_delete = ['X-UID', 'Status', 'X-Keywords', 'X-Status', 'X-RcptTo', 'X-MailFrom', 'X-INetSim-Id',
                             'X-INetSim-RCPT', 'X-Peer', 'X-FOSR-Client-Status']
        for h in msg:
            # X-Relay-Sendmail-* headers are also removed if found, in case someone copies an email from sentProbes to inbox again
            if h in headers_to_delete or h.startswith('X-Relay-Sendmail-'):
                del (msg[h])

        # Check to avoid python errors when no charset is defined, such as
        # "Error while trying to send message: 'ascii' codec can't encode character XX"
        if msg.get_charset() is None:
            msg_payload = msg.get_payload()
            if type(msg_payload) is str:
                for c in range(0, len(msg_payload)):
                    if ord(msg_payload[c]) > 128:
                        msg_payload = msg_payload[:c] + ' ' + msg_payload[c + 1:]

                msg.set_payload(msg_payload)

        return msg


class ConfigInEmail:
    """Daily logs and configuration are stored in an email in mailbox logs. This class assists in creating, retrieving or saving content."""

    def __init__(self):
        self.todayDate = date.today().isoformat()
        self.mbox = Helpers.get_mailbox(GlobalConfig.MAILBOX_LOGS_NAME)
        self.msg = None
        for key, msg in self.mbox.iteritems():
            if msg["Subject"] is not None and msg["Subject"] == "Logs from " + self.todayDate:
                self.msgKey = key
                self.msg = msg
        if len(self.mbox) == 0 or self.msg is None:
            self.msg = self.create_new_config()

    def __del__(self):
        self.mbox.close()

    def create_new_mail(self):
        msg = mailbox.mboxMessage()
        address = email.utils.formataddr(('InetSim Relayer', 'tests@example.com'))
        # See https://pymotw.com/3/mailbox/
        msg["Date"] = email.utils.formatdate()
        msg["Message-ID"] = email.utils.make_msgid("logs-" + self.todayDate)
        msg["From"] = address
        msg["To"] = address
        msg["Subject"] = "Logs from " + self.todayDate
        return msg

    def create_new_config(self):
        msg = self.create_new_mail()
        ipv4_check_url = "https://api.ipify.org/?format=json"  # 'https://v4.ident.me/.json' not providing json anymore
        ipv6_check_url = 'https://api64.ipify.org/?format=json'

        ipv4 = Helpers.get_json_from_url(ipv4_check_url)['ip']
        GlobalConfig.IPV4 = ipv4
        ipv6 = None
        try:
            ipv6 = Helpers.get_json_from_url(ipv6_check_url)['ip']
            GlobalConfig.IPV6 = ipv6
        except:
            # We dont do anything special if no IPv6 is found, variable is already set to None
            pass

        obj = {
            'global':
                {
                    'ipv4': ipv4,
                    'ipv6': ipv6,
                    'maxRelayPerDay': GlobalConfig.MAX_RELAY_PER_DAY,
                    'todayRelayCount': 0
                },
            'logs': []
        }
        msg.set_payload(json.dumps(obj, indent=2))

        self.msgKey = self.mbox.add(msg)
        return msg

    def read(self):
        return json.loads(self.msg.get_payload())

    def write(self, config):
        # Only write back the config when a change actually occurred
        if config != json.loads(self.msg.get_payload()):
            newMsg = self.create_new_mail()
            newMsg.set_payload(json.dumps(config, indent=2))
            self.mbox.remove(self.msgKey)
            self.msgKey = self.mbox.add(newMsg)
            self.msg = newMsg


class Exec():
    """Handles the interactive runtime."""

    def __init__(self):
        self.loop = None

    def get_screen_width(self):
        self.rows, self.columns = os.popen('stty size', 'r').read().split()
        self.rows = int(self.rows)
        self.columns = int(self.columns)
        return self.columns

    def print_mailbox(self, mailbox):
        # Try to optimize the screen size: static colums are 26 char in size. Default match is for a console of 80 char width
        dynSize = (17, 17, 20)
        widthColumns = self.get_screen_width()
        if widthColumns > 80:
            widthToDistribute = int((widthColumns - 80) / 3)
            dynSize = tuple(x + widthToDistribute for x in dynSize)

        tableFormat = '%-3i%-5s%-18s' + '%-' + str(dynSize[0]) + 's%-' + str(dynSize[1]) + 's%-' + str(dynSize[2]) + 's'

        # TODO: P2 fix subject if Unicode with the emails.util helper
        mailboxValues = mailbox.values()
        for key in range(0, len(mailbox)):
            msg = mailboxValues[key]
            if 'T' not in msg.get_flags():
                content = (
                    key,
                    msg.get_flags(),
                    Helpers.trim_str(msg["Date"], 17, False),
                    Helpers.trim_str(msg["X-MailFrom"], dynSize[0]),
                    Helpers.trim_str(msg["X-RcptTo"], dynSize[1]),
                    Helpers.trim_str(msg["Subject"], dynSize[2])
                )
                print(tableFormat % (content))

    def run(self):
        self.inbox = Helpers.get_mailbox(GlobalConfig.MAILBOX_INBOX_NAME)
        self.print_mailbox(self.inbox)

        while True:
            opt = Helpers.prompt_choice(['R', 'V', 'S', 'Q'],
                                        "Enter your prompt_choice ([R]efresh, [V]erify, [S]end, [Q]uit): ")

            if opt == 'Q':
                print("Bye!")
                return

            if opt == 'R':
                self.inbox.close()
                self.inbox = Helpers.get_mailbox(GlobalConfig.MAILBOX_INBOX_NAME)
                self.print_mailbox(self.inbox)

            # Option Verify and Send share the same initial steps (verify)
            if opt in ['V', 'S']:
                if opt == 'V':
                    input_text = "Enter the ID of the email to verify: "
                else:
                    input_text = "Enter the ID of the email to send: "

                indexMail = int(input(input_text))
                indexMail = self.inbox.keys()[indexMail]
                rm = RelayMessage(self.inbox, indexMail)
                if self.loop is None:
                    self.loop = asyncio.get_event_loop()

                rm.loop = self.loop

                future = asyncio.ensure_future(rm.verify_async())
                self.loop.run_until_complete(future)
                for log in rm.logs:
                    print(log)

                # Specific code branch for sending emails
                if opt == 'S':
                    opt = Helpers.prompt_choice(['Y', 'N'], "Confirm you want to send this message ([Y]es, [N]o): ")
                    if opt == 'Y':
                        # We already run the script in interactive mode, so we force the relay to be interactive as well
                        rm.relay(interactive=True)


class FakeOpenSmtpServer(SMTP):
    """Subclass of aiosmtpd SMTP class. This is where you e.g. add additional commands your SMTP server should support."""

    log = logging.getLogger('mail.fosr.server')

    # Example of additional commands added to our custom server
    # @syntax('PING [ignored]')
    # async def smtp_PING(self, arg):
    # 	await self.push('259 Pong')

    # Tests
    # swaks --server [IP]:6025 --auth --auth-user test --auth-password test
    # Source: https://github.com/aio-libs/aiosmtpd/pull/10/files
    # Source: http://www.samlogic.net/articles/smtp-commands-reference-auth.htm
    @syntax('AUTH LOGIN PLAIN CRAM-MD5 CRAM-SHA1')
    async def smtp_AUTH(self, arg):
        # We do only basic validation checks here, the remaining is done in the handler
        return_code_str = None
        if not self.session.host_name:
            return_code_str = '503 Error: send HELO first'

        args = arg.split(' ')
        if len(args) > 2:
            return_code_str = '500 Too many values'
        if len(args) == 0:
            return_code_str = '500 Not enough value'

        # pylint: disable=access-member-before-definition
        if hasattr(self, 'authenticated') and self.authenticated:
            return_code_str = '503 Already authenticated'

        # At this stage, if return_code_str is not None some error occurred and we don't handle the hook
        # -> straight to the end, returning and logging the error
        if return_code_str is None:
            status = await self._call_handler_hook('AUTH', args)
            if status is None:  # aka smtp.py pattern 'if status is MISSING:'
                self.authenticated = True
                return_code_str = '235 2.7.0 Authentication successful'
            else:
                return_code_str = status

        # Finally we log and return the result to the client
        self.log.info('{session_peer!r} AUTH response returning "{return_code}" to client...'.format(
            session_peer=self.session.peer,
            return_code=return_code_str
        )
        )
        await self.push(return_code_str)
        return

    # Old dead code for now
    # if method != 'PLAIN':
    # 	await self.push('500 PLAIN method or die')
    # 	return
    # blob = None
    # if len(args) == 1:
    # 	await self.push('334')  # your turn, send me login/password
    # 	line = await self._reader.readline()
    # 	blob = line.strip()
    # 	if blob == '*':
    # 		await self.push("501 Auth aborted")
    # 		return
    # else:
    # 	blob = args[1]
    # log.debug('%r login/password %s' % (self.session.peer, blob))
    # if blob == '=':
    # 	login = None
    # 	password = None
    # else:
    # 	try:
    # 		loginpassword = b64decode(blob, validate=True)
    # 	except Exception:
    # 		await self.push("501 5.5.2 Can't decode base64")
    # 		return
    # 	try:
    # 		_, login, password = loginpassword.split(b"\x00")
    # 	except ValueError:  # not enough args
    # 		await self.push("500 Can't split auth value")
    # 		return
    # if self.auth_method(login, password):
    #	self.authenticated = True
    #	await self.push('235 2.7.0 Authentication successful')
    # else:
    #	await self.push('535 5.7.8 Authentication credentials '
    #						 'invalid')

    # Overriding connection_made of smtp.py to get further logging, especially of SSL details
    def connection_made(self, transport):
        super().connection_made(transport)
        s = transport.get_extra_info('socket')
        self.session.cipher = transport.get_extra_info('cipher')
        if self.session.cipher is None:
            self.log.info('{session_peer!r} connection_made with plain tcp socket between {client} <=> {server}'.format(
                session_peer=self.session.peer,
                client=s.getpeername(),
                server=s.getsockname()
            )
            )
        else:
            # TODO: P3 - log further details such as client certificate presented by the client, see https://docs.python.org/3/library/asyncio-protocol.html#asyncio.BaseTransport.get_extra_info
            self.session.cipher = transport.get_extra_info('cipher')
            self.log.info(
                '{session_peer!r} connection_made with SSL socket between {client} <=> {server} and cipher {cipher}'.format(
                    session_peer=self.session.peer,
                    client=s.getpeername(),
                    server=s.getsockname(),
                    cipher=self.session.cipher
                )
            )


class FakeOpenSmtpHandler():
    """Handler for aiosmtpd requests. There's no point of keeping the inheritance of Message, as we implemented everything of Message now."""

    def __init__(self, mail_dir, distributor=None, message_class=None, *, loop=None):
        self.mailbox = mailbox.Maildir(mail_dir)
        self.mail_dir = mail_dir
        self.message_class = message_class
        self.log = logging.getLogger('mail.fosr.handler')
        self.loop = loop or asyncio.get_event_loop()
        self.distributor = distributor

    async def handle_AUTH(self, server, session, envelope, args):

        if len(args) == 2 and args[0].upper() == 'PLAIN':
            self.log.info("%r AUTH PLAIN with values %s" % (session.peer, args[1]))
            session.auth = args[1]
            filter_result = RuleHandler.filter_AUTH(session, envelope, args)
            if filter_result is None:
                return None  # aka smtp.py pattern 'if status is MISSING:'
            else:
                self.log.info(
                    '{session_peer!r} AUTH triggered rule "{rule_name}" - returning code "{return_code}" to client...'.format(
                        session_peer=session.peer,
                        rule_name=filter_result.name,
                        return_code=filter_result.return_code_str
                    )
                )
                return filter_result.return_code_str

        challenge = '334 '
        if args[0].upper() == 'LOGIN':
            # If no username is specified, we ask first user than password
            if len(args) == 1:
                challenge += 'VXNlcm5hbWU6'
            else:
                challenge += 'UGFzc3dvcmQ6'

        if args[0].upper().startswith('CRAM'):
            # pylint: disable=unused-variable
            algo = args[0].split('-')[1]
            msgid_parts = email.utils.make_msgid().split('@')[0].split('.')
            challenge += '<%s.%s@%s>' % (msgid_parts[2], msgid_parts[0][1:], GlobalConfig.FAKE_HOSTNAME)
            challenge = '334 %s' % base64.b64encode(bytes(challenge, 'ascii'))

        self.log.info('{session_peer!r} handle_AUTH - sending "{response}" to client...'.format(
            session_peer=session.peer,
            response=challenge
        )
        )
        await server.push(challenge)

        line = await server._reader.readline()
        self.log.info('{session_peer!r} handle_AUTH - received "{response}" as challenge response...'.format(
            session_peer=session.peer,
            response=line
        )
        )

        if args[0].upper() == 'LOGIN':
            if len(args) == 1:
                self.log.info('{session_peer!r} handle_AUTH - sending "{response}" to client...'.format(
                    session_peer=session.peer,
                    response='334 UGFzc3dvcmQ6'
                )
                )
                await server.push('334 UGFzc3dvcmQ6')
                line2 = await server._reader.readline()
                self.log.info("%r AUTH LOGIN received username %s and password %s" % (session.peer, line, line2))
                session.auth = (line, line2)
            else:
                self.log.info("%r AUTH LOGIN received username %s and password %s" % (session.peer, args[1], line))
                session.auth = (args[1], line)


        else:
            self.log.info("%r AUTH %s received values %s" % (session.peer, args[0], line))
            session.auth = line

        filter_result = RuleHandler.filter_AUTH(session, envelope, args)
        if filter_result is None:
            return None  # aka smtp.py pattern 'if status is MISSING:'
        else:
            self.log.info(
                '{session_peer!r} AUTH triggered rule "{rule_name}" - returning code "{return_code}" to client...'.format(
                    session_peer=session.peer,
                    rule_name=filter_result.name,
                    return_code=filter_result.return_code_str
                )
            )
            return filter_result.return_code_str

    async def handle_RSET(self, server, session, envelope):
        filter_result = RuleHandler.filter_RSET(session, envelope)
        if filter_result is None:
            return '250 OK'
        else:
            self.log.info(
                '{session_peer!r} RSET triggered rule "{rule_name}" - returning code "{return_code}" to client...'.format(
                    session_peer=session.peer,
                    rule_name=filter_result.name,
                    return_code=filter_result.return_code_str
                )
            )
            return filter_result.return_code_str

    async def handle_EHLO(self, server, session, envelope, hostname):
        filter_result = RuleHandler.filter_EHLO(session, envelope, hostname)
        if filter_result is None:
            session.host_name = hostname
            # Mandatory handle implementation
            await server.push('250-AUTH LOGIN PLAIN CRAM-MD5 CRAM-SHA1')
            # TODO: P3 - consider implementing extension PIPELINING
            self.log.info('{session_peer!r} EHLO - returning code "{return_code}" to client...'.format(
                session_peer=session.peer,
                return_code='250 HELP'
            )
            )
            return '250 HELP'
        else:
            session.host_name = hostname
            await server.push('250-AUTH LOGIN PLAIN CRAM-MD5 CRAM-SHA1')
            self.log.info(
                '{session_peer!r} EHLO triggered rule "{rule_name}" - returning code "{return_code}" to client...'.format(
                    session_peer=session.peer,
                    rule_name=filter_result.name,
                    return_code=filter_result.return_code_str
                )
            )
            return filter_result.return_code_str

    # Source: https://github.com/python/cpython/blob/3.7/Lib/smtplib.py
    async def handle_DATA(self, server, session, envelope):
        try:
            message = self.prepare_message(session, envelope)
            filter_result = RuleHandler.filter_DATA(session, message)
            if filter_result is None:
                msg_key = self.mailbox.add(message)

                if self.distributor:
                    await self.distributor.queue.put(envelope.content)

                self.log.info("%r No matching rule found, saved in maildir - message key %s" % (session.peer, msg_key))
                # TODO: P3 - pass the message key as in the example below
                # 250 2.0.0 s5X2gWaHKVkfss5X7gXzPK mail accepted for delivery\r\n
                return '250 OK'

            # We have to handle the result of the rule
            self.log.info(
                '{session_peer!r} {rule_type} message ({rule_name}) just logged - from {msg_from} to {msg_to}'.format(
                    session_peer=session.peer,
                    msg_from=message['X-MailFrom'],
                    msg_to=message['X-RcptTo'],
                    rule_name=filter_result.name,
                    rule_type=str(filter_result.rule_type).split('.')[1]
                )
            )
            force_save_msg = False
            if filter_result.code_on_msg is not None:
                force_save_msg = filter_result.code_on_msg(message)

            # Saving emails if we explcitely want, or want to relay them
            if filter_result.save_msg or filter_result.relay or force_save_msg:
                if filter_result.mailbox_folder == '':
                    msg_key = self.mailbox.add(message)
                else:
                    if filter_result.mailbox_folder in self.mailbox.list_folders():
                        tmp_mb = self.mailbox.get_folder(filter_result.mailbox_folder)
                    else:
                        tmp_mb = self.mailbox.add_folder(filter_result.mailbox_folder)
                    msg_key = tmp_mb.add(message)

            if filter_result.relay:
                configObj = ConfigInEmail()
                config = configObj.read()
                if config["global"]["todayRelayCount"] > config["global"]["maxRelayPerDay"]:
                    config["logs"].append(
                        datetime.now().isoformat() + ": todayRelayCount limit reached, disabling relaying emails for today")
                    self.log.info('{session_peer!r} {rule_type} message ({rule_name}) relay logs: {logs}'.format(
                        session_peer=session.peer,
                        logs='todayRelayCount limit reached, disabling relaying emails for today.',
                        rule_name=filter_result.name,
                        rule_type=str(filter_result.rule_type).split('.')[1]
                    )
                    )
                else:
                    rm = RelayMessage(self.mailbox, msg_key)
                    rm.loop = self.loop
                    await rm.verify_async()

                    self.log.info(
                        '{session_peer!r} {rule_type} message ({rule_name}) should be relayed? {can_relay}'.format(
                            session_peer=session.peer,
                            can_relay=rm.canRelay,
                            rule_name=filter_result.name,
                            rule_type=str(filter_result.rule_type).split('.')[1]
                        )
                    )
                    # No interactive mode
                    rm.relay(interactive=False)
                    self.log.info('{session_peer!r} {rule_type} message ({rule_name}) relay logs: {logs}'.format(
                        session_peer=session.peer,
                        logs=rm.logs,
                        rule_name=filter_result.name,
                        rule_type=str(filter_result.rule_type).split('.')[1]
                    )
                    )
                    config["global"]["todayRelayCount"] += 1
                    config["logs"] = config["logs"] + [datetime.now().isoformat()] + rm.logs

                # In any case, we want to save the logs
                configObj.write(config)

            # TODO: P2 - log the response
            return filter_result.return_code_str

        except Exception as e:
            self.log.warning("%r Exception %s on line %i" % (session.peer, e, sys.exc_info()[2].tb_lineno))
            self.mailbox.add(message)

        return '250 OK'

    def handle_STARTTLS(self, selfObj, session, envelope):
        '''This method only catches the ciphers on a STARTTLS; Explicit TLS connections are caught using connection_made() in the server implementation.'''

        session.cipher = selfObj.transport.get_extra_info('cipher')
        self.log.info('{session_peer!r} STARTTLS with ciphers {cipher}...'.format(
            session_peer=session.peer,
            cipher=session.cipher
        )
        )
        return True

    async def handle_exception(self, error):
        self.log.exception('SMTP session exception: %s' % error)
        status = '542 Internal server error'
        return status

    def prepare_message(self, session, envelope):
        # If the server was created with decode_data True, then data will be a
        # str, otherwise it will be bytes.
        data = envelope.content
        if isinstance(data, bytes):
            message = message_from_bytes(data, self.message_class)
        else:
            assert isinstance(data, str), (
                'Expected str or bytes, got {}'.format(type(data)))
            message = message_from_string(data, self.message_class)
        message['X-Peer'] = str(session.peer)
        message['X-MailFrom'] = envelope.mail_from
        message['X-RcptTo'] = COMMASPACE.join(envelope.rcpt_tos)
        # TODO: P2 - store all session related data (EHLO, AUTH, ...) in a header for easier lambda & post-processing rules

        cipher = ''
        if session.cipher is not None:
            cipher = '\n\t(version={tls_version} cipher={cipher_name} bits={bits})'.format(
                tls_version=session.cipher[1],
                cipher_name=session.cipher[0],
                bits=session.cipher[2]
            )
        # TODO: P3 - queueId configurable  / random
        # ID : base64.b64encode(str.encode(email.utils.make_msgid().split('@')[0].split('.')[2][:-10:-1]))
        # receivedTxt = 'from {session_hostname} ([{session_peer}])\n\tby {server_name} with ESMTP id DA85237F{cipher}\n\tfor <{rcpt_to}>; {timestamp}'.format(
        # 		session_hostname=session.host_name,
        # 		session_peer=session.peer[0],
        # 		server_name=GlobalConfig.FAKE_HOSTNAME,
        # 		cipher=cipher,
        # 		rcpt_to=envelope.rcpt_tos[0],
        # 		timestamp=email.utils.formatdate()
        # 	)
        # message._headers.insert(0, receivedTxt)
        receivedTxt = 'from %s ([%s])\n\tby %s with ESMTP id DA85237F%s\n\tfor <%s>; %s'
        message._headers.insert(0, ('Received', receivedTxt % (
        session.host_name, session.peer[0], GlobalConfig.FAKE_HOSTNAME, cipher, envelope.rcpt_tos[0],
        email.utils.formatdate())))
        return message


class FakeOpenSmtpController(Controller):
    """Implementation of the aiosmtpd Controller."""

    # The factory will automatically set the host, port & ssl_context
    def factory(self):
        # The controller seems to use ssl_context where SMTP uses tls_context...
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(GlobalConfig.INSTALL_CERTIFICATE_CERT_FILE, GlobalConfig.INSTALL_CERTIFICATE_KEY_FILE)
        return FakeOpenSmtpServer(self.handler, hostname=GlobalConfig.FAKE_HOSTNAME, ident='SMTP Mailer ready',
                                  tls_context=context, loop=self.loop)


# Source: https://docs.python.org/3/library/json.html
# Source: https://realpython.com/python-json/
class RuleEncoder(json.JSONEncoder):
    # pylint: disable=method-hidden
    def default(self, obj):
        if isinstance(obj, Rule):
            result = {}
            result['__RuleObjVersion__'] = 1
            for d in obj.__dict__:
                # We don't store lambdas, as we have their str equivalent as well
                if d not in ['conditions', 'code_on_msg']:
                    if isinstance(obj.__dict__[d], RuleType):
                        result[d] = str(obj.__dict__[d]).split('.')[1]
                    else:
                        result[d] = obj.__dict__[d]
            return result
        else:
            return json.JSONEncoder.default(self, obj)


# TODO: P2 - refactor to add a method add_rule
# TODO: P2 - add version of rule handler to ease migration from previous format
class RuleHandler:
    """Static helper functions designed to be typed interactively in the Python shell offered by FOSR."""
    # Class variable, available from everywhere
    DATA_rules = []
    AUTH_rules = []
    RSET_rules = []
    EHLO_rules = []
    ruleset = {
        'DATA': DATA_rules,
        'AUTH': AUTH_rules,
        'RSET': RSET_rules,
        'EHLO': EHLO_rules,
    }
    _sorted_DATA_rules = []
    _sorted_AUTH_rules = []
    _sorted_RSET_rules = []
    _sorted_EHLO_rules = []
    enabled_ruleset = {
        'DATA': _sorted_DATA_rules,
        'AUTH': _sorted_AUTH_rules,
        'RSET': _sorted_RSET_rules,
        'EHLO': _sorted_EHLO_rules,
    }

    filename = 'rules.json'

    help_str = '''Welcome to Fake Open SMTP Relay (FOSR)!

				See https://github.com/waaeh/FakeOpenSmtpRelay for the latest, up-to-date documentation.

				You can use this interactive Python console to alter on the fly the configuration of FOSR, without having to restart the script / SMTP daemons. A common scenario is to create on the fly a custom filtering rule for an ongoing phishing campaign.

				Most useful commands:
				- Helpers.get_inbox() returns a maildir object referencing the current inbox
				- Class Rule allows you to define your own rules
				- Class RuleHelper defines several methods designed to be used in your custom rule
				- RuleHandler.show_emails() shows you the emails currently in your inbox and allows you relaying selected messages to their intended recipients
				- RuleHandler.load_rules_from_file() loads the rules from file {filename}
				- RuleHandler.dump_rules_to_file() saves the current ruleset to file {filename}
				- RuleHandler.purge_inbox_per_rule([rule_object]) applies [rule] to the current inbox.
				- RuleHandler.rebuild_filters() is required after you added or edited a rule

				See https://github.com/waaeh/FakeOpenSmtpRelay/FOSR_Examples.md for further examples of commands to run within this interactive window.
	'''.format(
        filename=filename
    )

    @staticmethod
    def help():
        print(RuleHandler.help_str.replace('\t', ''))

    Help = help

    @staticmethod
    def load_rules_from_file(*, forceInit=False):
        if os.path.isfile(RuleHandler.filename):
            try:
                logging.info('Try loading rules from file %s....' % RuleHandler.filename)
                with open(RuleHandler.filename, 'r') as f:
                    RuleHandler.ruleset = json.load(f, object_hook=RuleHandler.decode_rules_from_json)

                RuleHandler.DATA_rules = RuleHandler.ruleset['DATA']
                RuleHandler.AUTH_rules = RuleHandler.ruleset['AUTH']
                RuleHandler.RSET_rules = RuleHandler.ruleset['RSET']
                RuleHandler.EHLO_rules = RuleHandler.ruleset['EHLO']
                RuleHandler.rebuild_filters()
            except Exception as e:
                logging.warning('Rule load from JSON failed: %s' % e)
                print('Rule load from JSON failed: %s' % e)
                # If an exception occurs, only load the hardcoded rules if forceInit has been explicitely specified
                if forceInit:
                    RuleHandler.init()
        else:
            RuleHandler.init()

        print("You have {nb_rules} rules loaded, {nb_rules_enabled} of them being enabled.".format(
            nb_rules=len([rules for x in RuleHandler.ruleset for rules in RuleHandler.ruleset[x]]),
            nb_rules_enabled=len(
                [rules for x in RuleHandler.enabled_ruleset for rules in RuleHandler.enabled_ruleset[x]])
        )
        )

    @staticmethod
    def decode_rules_from_json(dct):
        if '__RuleObjVersion__' in dct:
            r = Rule(dct['name'], RuleType[dct['rule_type']])
            r.priority = dct['priority']
            r.enabled = dct['enabled']
            r.save_msg = dct['save_msg']
            r.mailbox_folder = dct['mailbox_folder']
            r.relay = dct['relay']
            r.return_code = dct['return_code']
            r.return_code_str = dct['return_code_str']
            r.code_on_init_str = dct['code_on_init_str']
            if r.code_on_init_str is not None and r.code_on_init_str != '':
                exec(r.code_on_init_str, globals())

            r.code_on_msg_str = dct['code_on_msg_str']
            if r.code_on_msg_str is not None and r.code_on_msg_str != '':
                r.code_on_msg = eval(r.code_on_msg_str)
            else:
                r.code_on_msg = None

            r.conditions_str = dct['conditions_str']
            r.conditions = []
            for c in r.conditions_str:
                r.conditions.append(eval(c))
            return r
        else:
            return dct

    @staticmethod
    def dump_rules_to_file():
        # TODO: P2 - only keep backup of file if the file really changed
        backup_filename = ''
        if os.path.isfile(RuleHandler.filename):
            backup_filename = RuleHandler.filename + '.' + datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
            os.rename(RuleHandler.filename, backup_filename)

        with open(RuleHandler.filename, 'w') as f:
            json.dump(RuleHandler.ruleset, f, cls=RuleEncoder, indent=4)

    @staticmethod
    def show_emails():
        e = Exec()
        e.run()

    @staticmethod
    def purge_inbox_per_rule(rule):
        myLogger = logging.getLogger('mail.fosr.offlineprocessing')
        reason = '{rule_type} message ({rule_name})'.format(
            rule_name=rule.name,
            rule_type=str(rule.rule_type).split('.')[1]
        )
        m = Helpers.get_maildir('inbox')
        for key, message in m.iteritems():
            for condition in rule.conditions:
                if condition(message):
                    myLogger.info("%r %s just logged - from %s to %s" % (
                    message['X-Peer'], reason, message['X-MailFrom'], message['X-RcptTo']))
                    force_save_msg = False
                    if rule.code_on_msg is not None:
                        force_save_msg = rule.code_on_msg(message)
                    if not force_save_msg:
                        m.remove(key)
                    break

    @staticmethod
    def purge_inbox_per_lambda(msg, lambda_exp):
        myLogger = logging.getLogger('mail.fosr.offlineprocessing')
        m = Helpers.get_maildir('inbox')
        for key, message in m.iteritems():
            if lambda_exp(message):
                myLogger.info("%r %s just logged - from %s to %s" % (
                message['X-Peer'], msg, message['X-MailFrom'], message['X-RcptTo']))
                m.remove(key)

    @staticmethod
    def rebuild_filters():
        RuleHandler._sorted_DATA_rules = sorted([rules for rules in RuleHandler.DATA_rules if rules.enabled],
                                                key=lambda r: r.priority)
        RuleHandler._sorted_AUTH_rules = sorted([rules for rules in RuleHandler.AUTH_rules if rules.enabled],
                                                key=lambda r: r.priority)
        RuleHandler._sorted_RSET_rules = sorted([rules for rules in RuleHandler.RSET_rules if rules.enabled],
                                                key=lambda r: r.priority)
        RuleHandler._sorted_EHLO_rules = sorted([rules for rules in RuleHandler.EHLO_rules if rules.enabled],
                                                key=lambda r: r.priority)
        RuleHandler.enabled_ruleset = {
            'DATA': RuleHandler._sorted_DATA_rules,
            'AUTH': RuleHandler._sorted_AUTH_rules,
            'RSET': RuleHandler._sorted_RSET_rules,
            'EHLO': RuleHandler._sorted_EHLO_rules,
        }

    # Pattern - filter_X for each handle_X of FOSR_Handler
    # Returns None if no matching rule has been found, otherwise the first matching Rule object
    @staticmethod
    def filter_DATA(session, msg):
        for rule in RuleHandler._sorted_DATA_rules:
            if any([lambda_expression(msg) for lambda_expression in rule.conditions]):
                return rule

        return None

    @staticmethod
    # TODO: P3 - convert the auth_arr in auth_obj
    def filter_AUTH(session, envelope, auth_arr):
        for rule in RuleHandler._sorted_AUTH_rules:
            if any([lambda_expression(session, envelope, auth_arr) for lambda_expression in rule.conditions]):
                return rule

        return None

    @staticmethod
    def filter_RSET(session, envelope):
        for rule in RuleHandler._sorted_RSET_rules:
            if any([lambda_expression(session, envelope) for lambda_expression in rule.conditions]):
                return rule

        return None

    @staticmethod
    def filter_EHLO(session, envelope, hostname):
        for rule in RuleHandler._sorted_EHLO_rules:
            if any([lambda_expression(session, envelope, hostname) for lambda_expression in rule.conditions]):
                return rule

        return None

    # TODO: P2 - consider adding hooks for HELO, NOOP, STARTTLS, MAIL FROM, RCPT TO, VRFY,
    # Note that this will require handlers in the FOSR handler

    @staticmethod
    def init():
        logging.info('Loading rules from code - method RuleHandler.init()....')

        # Only rule enabled by default, relaying emails containing the server's IPv4 address in the subject
        rule1 = Rule("Relay msg if IP address is present", RuleType.PROBE)
        rule1.add_condition(
            "lambda msg: msg['Subject'] is not None and type(msg['Subject']) is str and GlobalConfig.TEST_PROBE_RELAY_SUBJECT in msg['Subject']")
        rule1.add_condition(
            "lambda msg: msg['Subject'] is not None and type(msg['Subject']) is str and GlobalConfig.IPV4 in msg['Subject']")
        rule1.relay = True
        RuleHandler.DATA_rules.append(rule1)

        # When enabled, this rule has a higher priority than rules with default priority (100). This allows us to explicitly not relay messages which would otherwise be forwarded by rule1
        rule2 = Rule("Known spammers we want to ignore", RuleType.PROBE)
        rule2.priority = 50
        rule2.add_condition(
            "lambda msg: msg['Subject'] is not None and type(msg['Subject']) is str and 'UNIQUE_STRING_IN_PROBE' in msg['Subject']")
        rule2.add_condition(
            "lambda msg: msg['To'] is not None and type(msg['To']) is str and 'XXXX@gmail.com' in msg['To']")
        rule2.enabled = False
        RuleHandler.DATA_rules.append(rule2)

        # Example of a SPAM rule, discarding received messages matching either conditions. The only reference to the received email is in the logs
        rule3 = Rule("Unicode spammers", RuleType.SPAM)
        rule3.add_condition(
            "lambda msg: msg['From'] is not None and type(msg['From']) is str and msg['From'].startswith('NAME_OF_SPAMMER')")
        # Covers emails having a Unicode tick as first character in their subject
        rule3.add_condition(
            "lambda msg: msg['Subject'] is not None and type(msg['Subject']) is str and msg['Subject'].startswith('=?UTF-8?b?4pyF?=')")
        rule3.save_msg = False
        rule3.enabled = False
        RuleHandler.DATA_rules.append(rule3)

        # Second example of a SPAM rule with high priority to discard all msgs sent by John Doe
        rule4 = Rule("Scammer John Doe", RuleType.SPAM)
        rule4.save_msg = False
        rule4.enabled = False
        rule4.priority = 50
        rule4.add_condition(
            "lambda msg: msg['From'] is not None and type(msg['From']) is str and 'John Doe' in msg['From']")
        RuleHandler.DATA_rules.append(rule4)

        # This spam rule relies on helpers in RuleHelper, throwing away emails if the from is in cyrillic
        rule5 = Rule("Cyrillic 'from'", RuleType.SPAM)
        rule5.add_condition(
            "lambda msg: msg['From'] is not None and type(msg['From']) is email.header.Header and 'CYRILLIC' in RuleHelper.get_unicode_name(RuleHelper.decode_header_content(msg, 'From'))")
        rule5.save_msg = False
        rule5.enabled = False
        RuleHandler.DATA_rules.append(rule5)

        # Phisher1 is sending out creative probes we want to relay, including the server's IP address in SMTP header X-SpamInfo instead of subject or within the last 20 lines of the email content
        rulePhisher1 = Rule("Phisher1 probes", RuleType.PROBE)
        rulePhisher1.add_condition(
            "lambda msg: msg['To'] is not None and type(msg['To']) is str and 'XXXX@hotmail.com' in msg['To']")
        rulePhisher1.add_condition(
            "lambda msg: msg['X-SpamInfo'] is not None and type(msg['X-SpamInfo']) is str and GlobalConfig.IPV4 in msg['X-SpamInfo']")
        # Is our IP address in the last 20 lines of the payload?
        rulePhisher1.add_condition(
            "lambda msg: type(msg.get_payload()) is str and RuleHelper.is_str_in_lines(GlobalConfig.IPV4, msg.get_payload().split('\\n')[-20:])")
        rulePhisher1.relay = True
        rulePhisher1.enabled = False
        RuleHandler.DATA_rules.append(rulePhisher1)

        # Here we intercept a phishing campaign which sends its messages from a very specific From address
        rulePhisher2 = Rule("Phisher2 campaign", RuleType.PHISH)
        rulePhisher2.add_condition(
            "lambda msg: msg['From'] is not None and type(msg['From']) is str and 'XXXXX@XXXX.com' in msg['From']")
        rulePhisher2.save_msg = False
        # We want to be sure that the rule gets executed after the IP lookup
        rulePhisher2.priority = 110
        # The following code will be run when the rule is created, defining a custom function get_Phisher2_urls and a global empty array Phisher2_urls
        # If the URL retrieved in the email is new, we return True, causing the message to be saved in our inbox
        # pylint: disable=anomalous-backslash-in-string
        rulePhisher2.set_code_on_init(
"""
Phisher2_urls = []
def get_Phisher2_urls(msg):
	p = base64.b64decode(msg.get_payload().replace('\\n',''))
	urls = re.findall('<a href="(https?://\S+)"', str(p))
	for url in set(urls):
		if url not in Phisher2_urls:
			logging.warn('Phishing URL - %s' % url)
			Phisher2_urls.append(url)
			return True

	return False
"""
		)
        rulePhisher2.set_code_on_msg("lambda msg: get_Phisher2_urls(msg)")
        rulePhisher2.enabled = False
        RuleHandler.DATA_rules.append(rulePhisher2)

        # OTHER TEST RULES
        t = Rule("TEST RSET RULE", RuleType.PROBE)
        t.add_condition("lambda session, envelope: session.host_name == GlobalConfig.TEST_PROBE_RELAY_SUBJECT")
        t.return_code_str = '200 LOL'
        t.enabled = False
        RuleHandler.RSET_rules.append(t)

        t2 = Rule("TEST EHLO RULE", RuleType.PROBE)
        t2.add_condition("lambda session, envelope, hostname: hostname == GlobalConfig.TEST_PROBE_RELAY_SUBJECT")
        t2.return_code_str = '200 LOL'
        t2.enabled = False
        RuleHandler.EHLO_rules.append(t2)

        ruleAuth1 = Rule("TEST AUTH RULE", RuleType.PROBE)
        ruleAuth1.enabled = False
        ruleAuth1.add_condition(
            "lambda session, envelope, args: session.auth is not None and type(session.auth) is tuple and len(session.auth) == 2 and session.auth[0] == 'XXXX' and session.auth[1] == 'XXXX'")
        RuleHandler.AUTH_rules.append(ruleAuth1)

        t_code = Rule("TEST CODE RULE", RuleType.PHISH)
        t_code.add_condition("lambda msg: msg['Subject'] is not None and msg['Subject'] == 'My_super_secret_subject'")
        t_code.save_msg = False
        t_code.set_code_on_init(
"""
Test_test_test_msg = []
def Test_test_test_def(msg):
	p = msg.get_payload().replace('\\n','')
	if p not in Test_test_test_msg:
		logging.warn('New email content - %s' % p)
		Test_test_test_msg.append(p)
		return True

	return False
"""
		)
        t_code.set_code_on_msg("lambda msg: Test_test_test_def(msg)")
        t_code.enabled = False
        RuleHandler.DATA_rules.append(t_code)

        RuleHandler.rebuild_filters()


class Rule:
    """Rule object, defining filtering rules and results."""
    # NOK - we have 250 HELP or 250 OK as possible return code... Check the protocol!
    # 250 is the default OK code, but some servers use it for RSET and NOOP; we don't want to do so by default...
    return_code_to_str = a = {200: 'OK', 250: 'OK', 451: 'Temporary server error. Please try again later'}

    def __init__(self, name, rule_type):
        self.name = name
        self.rule_type = rule_type
        self.priority = 100
        self.conditions = []
        self.conditions_str = []
        self.enabled = True
        # TODO: P3 - consider decoding about save based on rule_type (e.g. probe & malware = save, spam not)
        # TODO: P3 - SPAM could also have a higher priority by default...
        self.save_msg = True
        self.mailbox_folder = ''
        self.relay = False
        self.return_code = 250
        self.return_code_str = ("%i %s" % (self.return_code, Rule.return_code_to_str[self.return_code]))
        # The idea is to be able to
        # 1. Execute code on startup to initialize variables and functions
        # 2. On messages, parse / extract data and
        #	 a. Log
        # 	 b. Force save msg
        #	 c. ??? report URLs ???
        # => code_once is a simple EXEC
        # => code_on_msg is a lambda returning True / False for force save, or a complex reply?
        self.code_on_init_str = ''
        self.code_on_msg = None
        self.code_on_msg_str = ''

    def add_condition(self, lambda_str):
        self.conditions_str.append(lambda_str)
        self.conditions.append(eval(lambda_str))

    def set_code_on_init(self, code_txt):
        self.code_on_init_str = code_txt
        exec(code_txt, globals())

    def set_code_on_msg(self, lambda_str):
        self.code_on_msg_str = lambda_str
        self.code_on_msg = eval(lambda_str)

    def set_return_code(self, int_code):
        self.return_code = int_code
        self.return_code_str = ("%i %s" % (self.return_code, Rule.return_code_to_str[self.return_code]))

    def __repr__(self):
        txt = ''
        for c in self.conditions_str:
            txt += '\n\t - ' + c
        return "Object Rule with attributes %r and conditions %s" % (self.__dict__, txt)


# TODO: P2 - ADD
# - Version
# - ExpirationTime
# - Comment
# - Add daily statistics


class RuleType(enum.Enum):
    """Enumeration of possible Rule Types."""
    PROBE = 10
    SPAM = 50
    PHISH = 100
    MALWARE = 500


class RuleHelper:
    """Static helper class designed to be used in Rule lambda expressions"""

    @staticmethod
    def get_base64_repr(keyword):
        variations = ['', 'A', 'AA']
        results = []
        for v in variations:
            results.append(base64.b64encode(bytes(v + keyword, 'ascii')).decode()[4:-4])

        return results

    @staticmethod
    def is_str_in_lines(str, lines):
        for line in lines:
            if str in line:
                return True

        return False

    @staticmethod
    def get_unicode_name(character):
        if character is None or len(character) == 0:
            return None

        return unicodedata.name(character[0])

    @staticmethod
    def decode_header_content(msg, header_name):
        if msg is None or msg[header_name] is None:
            return None

        decoded_txt = email.header.decode_header(msg[header_name])
        if decoded_txt[0][1] is None:
            return decoded_txt[0][0]
        else:
            return decoded_txt[0][0].decode(decoded_txt[0][1])


if __name__ == "__main__":
    with ExitStack() as resources:
        handler = [TimedRotatingFileHandler("aiosmtpd.log", when="midnight", interval=1)]
        # TODO: P3 - if --debug, raise further logging details
        logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s %(message)s',
                            handlers=handler)
        # TODO: P2 - consider compressing the logs directly, as shown in
        # https://stackoverflow.com/questions/8467978/python-want-logging-with-log-rotation-and-compression
        # https://docs.python.org/3/howto/logging-cookbook.html#using-a-rotator-and-namer-to-customize-log-rotation-processing

        parser = argparse.ArgumentParser(description='Simulates a Fake Open SMTP relay.')
        parser.add_argument('-i', '--interactive', action='store_true')
        parser.add_argument('-t', '--testMode', action='store_true')
        parser.add_argument('-d', '--debug', action='store_true')
        parser.add_argument("-f", "--feed-config", type=str,
                            help="Config file in JSON-syntax specifying hpfeeds broker to use")
        args = parser.parse_args()

        # TODO remove for production
        args.testMode = True
        args.feed_config = "./feed_config.json"

        # Check prerequisits
        if sys.version_info < (3, 5):
            raise ImportError("Python 3.5 or greater is required")
        if 'dns.resolver' not in sys.modules:
            print("This script requires module dns.resolver. Please install it before re-running the script:")
            print("E.g. sudo apt-get install python3-pip && sudo pip3 install dnspython3")
            raise ModuleNotFoundError(
                "This script requires module dns.resolver. Please install it before re-running the script")
        if 'aiosmtpd' not in sys.modules:
            print("This script requires module aiosmtpd. Please install it before re-running the script:")
            print("E.g. sudo apt-get install python3-pip && sudo pip3 install aiosmtpd")
            raise ModuleNotFoundError(
                "This script requires module aiosmtpd. Please install it before re-running the script")
        if 'hpfeeds' not in sys.modules:
            print("This script requires module hpfeeds. Please install it before re-running the script:")
            print("E.g. sudo apt-get install python3-pip && sudo pip3 install hpfeeds")
            raise ModuleNotFoundError(
                "This script requires module aiosmtpd. Please install it before re-running the script")
        if not os.path.exists(GlobalConfig.INSTALL_CERTIFICATE_CERT_FILE) or not os.path.exists(
                GlobalConfig.INSTALL_CERTIFICATE_KEY_FILE):
            print("This script requires a (self-signed) x509 key pair. Create one with the following command:")
            print("openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem")
            raise FileNotFoundError('File %s and/or %s was not found' % (
            GlobalConfig.INSTALL_CERTIFICATE_CERT_FILE, GlobalConfig.INSTALL_CERTIFICATE_KEY_FILE))

        logging.info('Creating / loading ConfigInEmail() to handle dynamic variables...')
        configObj = ConfigInEmail()
        config = configObj.read()
        GlobalConfig.IPV4 = config['global']['ipv4']
        GlobalConfig.IPV6 = config['global']['ipv6']

        loop = asyncio.get_event_loop()  # asyncio.new_event_loop()

        if args.feed_config:
            feed_conf = Helpers.read_config(args.feed_config)
            d = HpfeedsDistributor(**feed_conf)
            loop.create_task(d.distribute())

        if args.testMode:
            GlobalConfig.TEST_MODE = True

        if args.interactive:
            e = Exec()
            e.run()

        else:
            maildir_path = Helpers.get_maildir_path()

            handler = FakeOpenSmtpHandler(maildir_path, distributor=d)

            for i, p in enumerate(GlobalConfig.PORTS):
                logging.info(f'Starting "standard" SMTP server on port {GlobalConfig.BASE_PORT_NUMBER + p}')

                # Handle implicit TLS
                if p == 465:
                    print("attaching ctx")
                    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
                    context.load_cert_chain(GlobalConfig.INSTALL_CERTIFICATE_CERT_FILE,
                                            GlobalConfig.INSTALL_CERTIFICATE_KEY_FILE)
                    controller = FakeOpenSmtpController(handler, hostname='', port=(GlobalConfig.BASE_PORT_NUMBER + p), loop=loop, ssl_context=context)
                else:
                    controller = FakeOpenSmtpController(handler, hostname='', port=(GlobalConfig.BASE_PORT_NUMBER + p), loop=loop)

                # Creates server tasks in background for all ports, except the last one
                if i < len(GlobalConfig.PORTS)-1:
                    s = loop.create_task(loop.create_server(controller.factory, host="", port=(GlobalConfig.BASE_PORT_NUMBER + p)))

            # Last server task is controlled by the controller itself, which runs all servers in a thread
            controller.start()

            logging.info('Startup done.')
            logging.info('Loading rules...')
            RuleHandler.load_rules_from_file(forceInit=True)
            logging.info('Rules loaded.')

            # Enables autocomplete
            # Source: http://blog.e-shell.org/221
            readline.parse_and_bind('tab:complete')
            # Source: https://www.digitalocean.com/community/tutorials/how-to-debug-python-with-an-interactive-console
            b = "\nWelcome in the FOSR interactive prompt. Type RuleHandler.help() to get help or [Ctrl]+[d] to close the script and stop all controllers!\n\n"

            # Alias for shorter commands in the interactive console
            RH = RuleHandler

            code.interact(banner=b, local=locals())

            print('Saving the rules and stopping controllers, please wait...')
            logging.info('Saving the rules...')
            RuleHandler.dump_rules_to_file()
            logging.info('Stopping all controllers...')

# Waiting for all currently running async methods to finish...
# TODO: P2 - NOK
# pending = asyncio.Task.all_tasks()
# loop.run_until_complete(asyncio.gather(*pending))

logging.info('FakeOpenSmtpRelay stopped, bye!')
