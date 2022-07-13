# collectors

This directory contains the different collectors, which were implemented to collect (mal)spam-mails and transport those to the message broker.

-   [fosr-collector](fosr-collector/readme.md) realizes a fake open SMTP relay
-   [imap-collector](imap-collector/readme.md) retrieves (mal)spam from various IMAP spamtraps concurrently
-   [smtp-collector](smtp-collector/readme.md) realizes a fake destination SMTP server with catchall (domain-wide) mailboxes
