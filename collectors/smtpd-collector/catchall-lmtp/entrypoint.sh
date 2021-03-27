#!/bin/bash

# Pass args like:
#python3.8 /usr/local/bin/lmtp_server.py -p 8587 -m /data/testdir -f /usr/local/etc/feed_config.yml
python3.8 /usr/local/bin/catchall_lmtp.py "$@"
