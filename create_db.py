#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import argparse
import gzip
import time
import csv
import logging
import math
import os
import os.path

from netaddr import iprange_to_cidrs


# I removed arin.db.gz, arin-nonauth.db.gz, if you have access to the real ARIN
# data dumps, feel free to re-add them.
FILELIST = ['afrinic.db.gz', 'apnic.db.inet6num.gz', 'apnic.db.inetnum.gz', 
            'lacnic.db.gz', 'ripe.db.inetnum.gz', 'ripe.db.inet6num.gz']

NUM_WORKERS = 1
LOG_FORMAT = '%(asctime)-15s - %(name)-9s - %(levelname)-8s - %(processName)-11s - %(filename)s - %(message)s'
CURRENT_FILENAME = "empty"
VERSION = '2.0'


class ContextFilter(logging.Filter):
    def filter(self, record):
        record.filename = CURRENT_FILENAME
        return True


logger = logging.getLogger('create_db')
logger.setLevel(logging.INFO)
f = ContextFilter()
logger.addFilter(f)
formatter = logging.Formatter(LOG_FORMAT)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
logger.addHandler(stream_handler)


def get_source(filename: str):
    if filename.startswith('afrinic'):
        return b'afrinic'
    elif filename.startswith('apnic'):
        return b'apnic'
    elif filename.startswith('arin'):
        return b'arin'
    elif filename.startswith('lacnic'):
        return b'lacnic'
    elif filename.startswith('ripe'):
        return b'ripe'
    else:
        logger.error(f"Can not determine source for {filename}")
    return None


def parse_property(block: str, name: str) -> str:
    match = re.findall(b'^%s:\s?(.+)$' % (name), block, re.MULTILINE)
    if match:
        # remove empty lines and remove multiple names
        x = b' '.join(list(filter(None, (x.strip().replace(
            b"%s: " % name, b'').replace(b"%s: " % name, b'') for x in match))))
        # remove multiple whitespaces by using a split hack
        # decode to latin-1 so it can be inserted in the database
        return ' '.join(x.decode('latin-1').split())
    else:
        return None


def parse_property_inetnum(block: str) -> str:
    # RIR WHOIS IPv4
    match = re.findall(
        rb'^inetnum:[\s]*((?:\d{1,3}\.){3}\d{1,3})[\s]*-[\s]*((?:\d{1,3}\.){3}\d{1,3})', block, re.MULTILINE)
    if match:
        # netaddr can only handle strings, not bytes
        ip_start = match[0][0].decode('utf-8')
        ip_end = match[0][1].decode('utf-8')
        cidrs = iprange_to_cidrs(ip_start, ip_end)
        return cidrs
    # RIR WHOIS IPv6
    match = re.findall(
        rb'^inet6num:[\s]*([0-9a-fA-F:\/]{1,43})', block, re.MULTILINE)
    if match:
        return match[0]
    # LACNIC WHOIS IPv4 
    match = re.findall(
        rb'^inetnum:[\s]*((?:\d{1,3}\.){1,3}\d{1,3}/\d{1,2})', block, re.MULTILINE)
    if match:
        # LACNIC appears to be using a shorthand notation for CIDR ranges. I 
        # have noticed that when a network ends with octets of 0, these octets 
        # are sometimes omitted; leaving you with values like '1.0/16' and 
        # '1.0.0/24'. These may equally be mistakes, though there are quite a
        # few compelling cases in the file which make it seem otherwise.
        if match[0].count(b'.') == 1:
            idx = match[0].index(b'/')
            prefix = match[0][:idx].decode("utf-8")
            suffix = match[0][idx:].decode("utf-8")
            return f'{prefix}.0.0{suffix}'.encode('utf-8')
        elif match[0].count(b'.') == 2:
            idx = match[0].index(b'/')
            prefix = match[0][:idx].decode("utf-8")
            suffix = match[0][idx:].decode("utf-8")
            return f'{prefix}.0{suffix}'.encode('utf-8')
        else:
            return match[0]
   # TODO: Logic for parsing IRR data format from ARIN and other members of the 
   # IRR program: http://www.irr.net/docs/list.html
    logger.warning(f"Could not parse inetnum on block {block}")
    return None


def read_blocks(filename: str) -> list:
    if filename.endswith('.gz'):
        opemethod = gzip.open
    else:
        opemethod = open

    cust_source = get_source(filename.split('/')[-1])
    single_block = b''
    blocks = []

    with opemethod(filename, mode='rb') as f:
        for line in f:
            # skip comments
            if line.startswith(b'%') or line.startswith(b'#') or line.startswith(b'remarks:'):
                continue
            # block end
            if line.strip() == b'':
                if single_block.startswith(b'inetnum:') or single_block.startswith(b'inet6num:'):
                    # add source
                    single_block += b"cust_source: %s" % (cust_source)
                    blocks.append(single_block)
                    if len(blocks) % 1000 == 0:
                        logger.debug(f"parsed another 1000 blocks ({len(blocks)} so far)")
                    single_block = b''
                    # comment out to only parse x blocks
                    # if len(blocks) == 100:
                    #    break
                else:
                    single_block = b''
            else:
                single_block += line
    
    logger.info(f"Got {len(blocks)} blocks")
    global NUM_BLOCKS
    NUM_BLOCKS = len(blocks)
    return blocks


def parse_blocks(blocks, csv_writer):
    for block in blocks:
        inetnum = parse_property_inetnum(block)
        netname = parse_property(block, b'netname')
        description = parse_property(block, b'descr')
        country = parse_property(block, b'country')
        maintained_by = parse_property(block, b'mnt-by')
        created = parse_property(block, b'created')
        last_modified = parse_property(block, b'last-modified')
        source = parse_property(block, b'cust_source')

        if isinstance(inetnum, list):
            for cidr in inetnum:
                row = [str(cidr), netname, description, country, maintained_by, created, last_modified, source]
                csv_writer.writerow(row)
        else:
            row = [inetnum.decode("utf-8"), netname, description, country, maintained_by, created, last_modified, source]
            csv_writer.writerow(row)


def main(output_file):
    overall_start_time = time.time()

    with open(output_file, 'w') as output_file_handle:
        csv_writer = csv.writer(output_file_handle, delimiter='\t', quoting=csv.QUOTE_MINIMAL)
        for entry in FILELIST:
            global CURRENT_FILENAME
            CURRENT_FILENAME = entry
            f_name = f"./databases/{entry}"

            if os.path.exists(f_name):
                logger.info(f"parsing database file: {f_name}")
                start_time = time.time()
                blocks = read_blocks(f_name)
                logger.info(f"database parsing finished: {round(time.time() - start_time, 2)} seconds")

                logger.info('parsing blocks')
                start_time = time.time()
                parse_blocks(blocks, csv_writer)
                logger.info(f"block parsing finished: {round(time.time() - start_time, 2)} seconds")
            else:
                logger.info(f"File {f_name} not found. Please download using download_dumps.sh")

    print('Done!')

    CURRENT_FILENAME = "empty"
    logger.info(f"script finished: {round(time.time() - overall_start_time, 2)} seconds")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Parse WHOIS databases into single TSV file')
    parser.add_argument('-o', dest='output_file', type=str, required=True, help="Output TSV file")
    parser.add_argument("-d", "--debug", action="store_true", help="set loglevel to DEBUG")
    parser.add_argument('--version', action='version', version=f"%(prog)s {VERSION}")
    args = parser.parse_args()

    if args.debug:
        logger.setLevel(logging.DEBUG)

    main(args.output_file)
