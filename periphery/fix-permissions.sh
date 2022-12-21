#!/bin/sh
#
# Script to create bind mounted dirs and fix permissions thereof
#
mkdir -p mongodb/mongodb_data/
sudo chown -R 1001 mongodb/mongodb_data/
mkdir -p elasticstack/elasticsearch/data
sudo chown -R 1000:1000 elasticstack/elasticsearch/data
