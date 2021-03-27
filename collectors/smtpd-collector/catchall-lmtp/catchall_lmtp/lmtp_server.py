import email
import logging
import mailbox
import os
from email.policy import SMTP
from aiosmtpd.controller import Controller
from aiosmtpd.lmtp import LMTP
logger = logging.getLogger()


class LMTPController(Controller):
    """Implementation of the aiosmtpd Controller to create an LMTP server."""
    # Factory creates LMTP instance with custom handler
    def factory(self):
        return LMTP(self.handler)  # custom handler gets passed to __init__


class CustomLMTPHandler:
    inbox = "inbox"

    def __init__(self, maildir_path=None, queue=None):
        if maildir_path:
            self.maildir = mailbox.Maildir(os.path.join(maildir_path, self.inbox), create=True)
        else:
            self.maildir = None

        self.mail_dir = maildir_path
        self.queue = queue

        logger.info(f"Created SMTP handler")

    def __del__(self):
        self.maildir.close()

    # Check receiving domains in handle_RCPT() eventually
    # See https://stackoverflow.com/questions/45447491/how-do-i-properly-support-starttls-with-aiosmtpd
    async def handle_DATA(self, server, session, envelope):

        # Store in local mailbox
        if self.mail_dir:
            self.store(envelope.content)

        # Distribute to backend
        if self.queue:
            await self.queue.put(envelope.content)

        # logger.info(str(decoded_payloads, 'utf-8'))

        return '250 OK'

    def store(self, data):
        msg = email.message_from_bytes(data, policy=SMTP)
        msg_key = self.maildir.add(msg)
        return msg_key
