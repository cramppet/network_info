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
from irrd.rpsl.rpsl_objects import rpsl_object_from_text


FILELIST = [
    'arin_db.txt',

    'afrinic.db.gz', 

    'apnic.db.inet6num.gz', 
    'apnic.db.inetnum.gz', 
    'apnic.db.route-set.gz', 
    'apnic.db.route.gz', 
    'apnic.db.route6.gz', 

    'lacnic.db.gz', 

    'ripe.db.inetnum.gz', 
    'ripe.db.inet6num.gz',
    'ripe.db.route-set.gz',
    'ripe.db.route.gz',
    'ripe.db.route6.gz',

    'arin.db.gz',
    'arin-nonauth.db.gz',
    'level3.db.gz',
    'nttcom.db.gz',
    'radb.db.gz',
    'tc.db.gz'
]

ARIN_ORGS = {}
LOG_FORMAT = '%(asctime)-15s - %(name)-9s - %(levelname)-8s - %(processName)-11s - %(filename)s - %(message)s'
CURRENT_FILENAME = "empty"
VERSION = '2.0'


class ContextFilter(logging.Filter):
    def filter(self, record):
        record.filename = CURRENT_FILENAME
        return True


logger = logging.getLogger('create_tsv')
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
    elif filename.startswith('level3'):
        return b'level3'
    elif filename.startswith('nttcom'):
        return b'nttcom'
    elif filename.startswith('radb'):
        return b'radb'
    elif filename.startswith('tc'):
        return b'tc'
    else:
        logger.error(f"Can not determine source for {filename}")
    return None


def parse_property(block: str, name: str) -> str:
    match = re.findall('^%s:\s?(.+)$' % (name), block, re.MULTILINE)
    if match:
        # remove empty lines and remove multiple names
        x = ' '.join(list(filter(None, (x.strip().replace(
            "%s: " % name, '').replace("%s: " % name, '') for x in match))))
        # remove multiple whitespaces by using a split hack
        # decode to latin-1 so it can be inserted in the database
        return ' '.join(x.split())
    else:
        return None


def parse_arin_inetnum(block: str) -> str:
    # ARIN WHOIS IPv4
    match = re.findall(r'^NetRange:[\s]*((?:\d{1,3}\.){3}\d{1,3})[\s]*-[\s]*((?:\d{1,3}\.){3}\d{1,3})', block, re.MULTILINE)
    if match:
        # netaddr can only handle strings, not bytes
        ip_start = match[0][0]
        ip_end = match[0][1]
        cidrs = iprange_to_cidrs(ip_start, ip_end)
        return cidrs
    # ARIN WHOIS IPv6
    match = re.findall(r'^NetRange:[\s]*([0-9a-fA-F:\/]{1,43})[\s]*-[\s]*([0-9a-fA-F:\/]{1,43})', block, re.MULTILINE)
    if match:
        # netaddr can only handle strings, not bytes
        ip_start = match[0][0]
        ip_end = match[0][1]
        cidrs = iprange_to_cidrs(ip_start, ip_end)
        return cidrs
    logger.warning(f"Could not parse ARIN block {block}")
    return None


def read_blocks(filename: str) -> list:
    if filename.endswith('.gz'):
        opemethod = gzip.open
    else:
        opemethod = open

    cust_source = get_source(filename.split('/')[-1])
    single_block = b''
    blocks = []

    # APNIC/LACNIC/RIPE/AFRINIC/IRR are all in RPSL
    def is_rpsl_block_start(line):
        if line.startswith(b'inetnum:'):
            return True
        elif line.startswith(b'inet6num:'):
            return True
        elif line.startswith(b'route:'):
            return True
        elif line.startswith(b'route6:'):
            return True
        elif line.startswith(b'route-set:'):
            return True
        return False

    # ARIN's WHOIS database is in a custom format
    def is_arin_block_start(line):
        if line.startswith(b'NetHandle:'):
            return True
        elif line.startswith(b'V6NetHandle:'):
            return True
        elif line.startswith(b'OrgID:'):
            return True
        return False

    with opemethod(filename, mode='rb') as f:
        for line in f:
            # skip comments
            if line.startswith(b'%') or line.startswith(b'#'):
                continue
            # block end
            if line.strip() == b'':
                if is_rpsl_block_start(single_block) or is_arin_block_start(single_block):
                    # add source
                    single_block += b"cust_source: %s" % (cust_source)
                    blocks.append(single_block)
                    if len(blocks) % 1000 == 0:
                        logger.debug(f"parsed another 1000 blocks ({len(blocks)} so far)")
                    single_block = b''
                else:
                    single_block = b''
            else:
                single_block += line
    
    logger.info(f"Got {len(blocks)} blocks")
    global NUM_BLOCKS
    NUM_BLOCKS = len(blocks)
    return blocks


def range_to_cidr(inetnum):
    match = re.findall(r'((?:\d{1,3}\.){3}\d{1,3})[\s]*-[\s]*((?:\d{1,3}\.){3}\d{1,3})', inetnum, re.MULTILINE)
    if match:
        # netaddr can only handle strings, not bytes
        ip_start = match[0][0]
        ip_end = match[0][1]
        return iprange_to_cidrs(ip_start, ip_end)[0]
    else:
        return inetnum


def parse_blocks(blocks, csv_writer):
    def is_arin_customer(block):
        return block.startswith('OrgID:')

    def is_arin_network(block):
        return block.startswith('NetHandle:') or block.startswith('V6NetHandle:')

    for block in blocks:
        # The RPSL parser works on str not bytes
        b = block.decode('utf-8', 'ignore') 

        inetnum = ''
        netname = ''
        description = ''
        country = ''
        maintained_by = ''
        created = ''
        last_modified = ''
        source = ''

        # ARIN has an Organization object which you have to parse out in order
        # to get any details about network blocks
        if is_arin_customer(b):
            orgid = parse_property(b, 'OrgID')
            orgname = parse_property(b, 'OrgName')
            country = parse_property(b, 'Country')
            ARIN_ORGS[orgid] = (orgname, country)
            continue

        # ARIN's dump format is also not in RPSL for whatever reason. They
        # decided to make their own custom format.
        elif is_arin_network(b):
            inetnum = parse_arin_inetnum(b)
            orgid = parse_property(b, 'OrgID')
            netname = parse_property(b, 'NetName')
            description = parse_property(b, 'NetHandle')
            # ARIN IPv6
            if not description:
                description = parse_property(b, 'V6NetHandle')
            country = ARIN_ORGS[orgid][1]
            maintained_by = ARIN_ORGS[orgid][0]
            created = parse_property(b, 'RegDate')
            last_modified = parse_property(b, 'Updated')
            source = parse_property(b, 'cust_source')

        # All other data dumps are in RPSL so we can use a proper parser
        # provided by the irrd package
        else:
            try:
                rpsl_object = rpsl_object_from_text(b)

                if 'inetnum' in rpsl_object.parsed_data:
                    inetnum = rpsl_object.parsed_data['inetnum']
                elif 'inet6num' in rpsl_object.parsed_data:
                    inetnum = rpsl_object.parsed_data['inet6num']
                elif 'route' in rpsl_object.parsed_data:
                    inetnum = rpsl_object.parsed_data['route']
                elif 'route6' in rpsl_object.parsed_data:
                    inetnum = rpsl_object.parsed_data['route6']
                elif 'route-set' in rpsl_object.parsed_data:
                    netname = rpsl_object.parsed_data['route-set']
                    # Changes type from str -> list
                    if 'members' in rpsl_object.parsed_data:
                        inetnum = rpsl_object.parsed_data['members']

                # Some of these might exist, or not, depends entirely on RIR/IRR
                if 'netname' in rpsl_object.parsed_data:
                    netname = rpsl_object.parsed_data['netname']
                if 'descr' in rpsl_object.parsed_data:
                    description = ' '.join(rpsl_object.parsed_data['descr'])
                if 'country' in rpsl_object.parsed_data:
                    country = ' '.join(rpsl_object.parsed_data['country'])
                if 'mnt-by' in rpsl_object.parsed_data:
                    maintained_by = ' '.join(rpsl_object.parsed_data['mnt-by'])
                if 'last-modified' in rpsl_object.parsed_data:
                    last_modified = ' '.join(rpsl_object.parsed_data['last-modified'])
                if 'changed' in rpsl_object.parsed_data:
                    last_modified = ' '.join(rpsl_object.parsed_data['changed'])
                if 'created' in rpsl_object.parsed_data:
                    created = ' '.join(rpsl_object.parsed_data['created'])
                
                # Source is special, we should always have a source value 
                if 'source' in rpsl_object.parsed_data:
                    source = rpsl_object.parsed_data['source']
                else:
                    source = parse_property(b, 'cust_source')
            except Exception as ex:
                logger.error(ex)

        if isinstance(inetnum, list):
            for cidr in inetnum:
                c = range_to_cidr(str(cidr))
                row = [c, netname, description, country, maintained_by, created, last_modified, source]
                csv_writer.writerow(row)
        else:
            row = [range_to_cidr(inetnum), netname, description, country, maintained_by, created, last_modified, source]
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

            # Free the memory associated with the large dictionary
            # since it is exclusive to ARIN's WHOIS database dump.
            if entry == 'arin_db.txt':
                global ARIN_ORGS
                ARIN_ORGS = {}

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
