#!/usr/bin/env python

"""
PowerDNS pipe backend for generating reverse DNS entries and their
forward lookup.

pdns.conf example:

launch=pipe
pipe-command=/usr/local/sbin/pipe-local-ipv6-wrapper
pipe-timeout=500

### LICENSE ###

The MIT License

Copyright (c) 2009 Wijnand "maze" Modderman
Copyright (c) 2010 Stefan "ZaphodB" Schmidt
Copyright (c) 2011 Endre Szabo
Copyright (c) 2017 Technical University of Munich (Lukas Erlacher)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

import sys
import os
import logging
from logging.handlers import TimedRotatingFileHandler
import time
import netaddr
from IPy import IP
import radix
import yaml
from copy import deepcopy

LOGLEVEL = 40
CONFIG = 'dynrev.yaml'

VERSION = 0.9
DIGITS = '0123456789abcdefghijklmnopqrstuvwxyz'
SCRIPTNAME = os.path.basename(sys.argv[0])


def setup_logger(level=20):
    """
    set up log
    設定 log

    :param level: log level, default info
    :return: logger
    """
    logHandler = TimedRotatingFileHandler('/var/log/powerdns-dynamic-reverse-backend/PowerDNS-Dynamic-Reverse-Backend.log',
                                          when='W6', interval=4, backupCount=6, encoding='utf-8')
    logHandler.setFormatter(
        logging.Formatter(fmt='[%(asctime)s] %(levelname)s %(message)s',
                          datefmt='%Y-%m-%d %H:%M:%S')
    )

    logger = logging.getLogger('PowerDNS-Dynamic-Reverse-Backend')
    logger.addHandler(logHandler)

    if level == 40:
        logger.setLevel(logging.ERROR)
    elif level == 20:
        logger.setLevel(logging.INFO)
    elif level == 10:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.DEBUG)

    return logger


def parse(defaults, prefixes, rtree, logger, fd, out):
    def log_message(level, message=None, **kwargs):
        if level >= LOGLEVEL:
            message = "%s; %s" % (
            message, ", ".join(filter(None, map(lambda k: "%s=%s" % (k, repr(str(kwargs[k]))), kwargs.keys()))))
            #out.write("LOG\t{message}\n".format(message=message))
            return  message

    logger.debug(log_message(10, "starting up"))

    line = fd.readline().strip()
    if not line.startswith('HELO'):
        out.write("FAIL\n")
        out.flush()
        logger.info(log_message(20, "unknown line received from powerdns, expected HELO", line=line))
        sys.exit(1)
    else:
        out.write("OK\t%s ready with %d prefixes configured\n" % (SCRIPTNAME, len(prefixes)))
        logger.debug(log_message(10, 'powerdns HELO received, ready to process requests', prefixes_count=len(prefixes)))
        out.flush()

    lastnet = 0
    while True:
        line = fd.readline().strip()
        if not line:
            break

        #syslog.syslog('<<< %s' % (line,))
        logger.debug(log_message(10, "got input line from powerdns", line=line))

        request = line.split('\t')
        if request[0] == 'AXFR':
            if not lastnet == 0:
                out.write("DATA\t%s\t%s\tSOA\t%d\t%s\t%s %s %s 10800 3600 604800 3600\n" % \
                        (lastnet['forward'], 'IN', lastnet['ttl'], qid, lastnet['dns'], lastnet['email'], time.strftime('%Y%m%d%H')))
                lastnet = lastnet
                for ns in lastnet['nameserver']:
                    out.write("DATA\t{qname}\t{qclass}\tNS\t{ttl}\t{id}\t{content}\n".format(
                        qname=lastnet['forward'], qclass='IN', ttl=lastnet['ttl'], id=qid, content=ns))
            out.write("END\n")
            out.flush()
            continue
        if len(request) < 6:
            out.write("LOG\tPowerDNS sent unparsable line\n")
            out.write("FAIL\n")
            out.flush()
            continue

        #q&d handling of different pdns pipe backend protocol versions
        try:
            kind, qname, qclass, qtype, qid, ip = request
        except ValueError:
            kind, qname, qclass, qtype, qid, ip, their_ip = request
        logger.info(log_message(20, "parsed query", qname=qname, qtype=qtype, qclass=qclass, qid=qid, ip=ip))

        if qtype in ['AAAA', 'ANY']:
            ipv6 = qname.split(".", 1)
            if "static.ip.net.tw" in ipv6[1].lower():
                ipv6 = ipv6[0].replace("-", ":")
                try:
                    node = rtree.search_best(ipv6)
                except:
                    node = None
                if node:
                    if node.data['prefix'].version == 6:
                        out.write("DATA\t{qname}\t{qclass}\tAAAA\t{ttl}\t{id}\t{content}\n".format(
                            qname=qname, qclass=qclass, ttl=prefixes[node.data['prefix']]['ttl'], id=qid, content=ipv6))

            # for ip_range in prefixes.keys():
            #     key = prefixes[ip_range]
            #     if qname.endswith('.%s' % (key['forward'],)) and key['version'] == 6 and qname.startswith(key['prefix']):
            #         node = qname[len(key['prefix']):].replace('%s.%s' % (key['postfix'], key['forward'],), '')
            #         try:
            #             node = base36decode(node)
            #             ipv6 = netaddr.IPAddress(int(ip_range.value) + int(node))
            #             out.write("DATA\t{qname}\t{qclass}\tAAAA\t{ttl}\t{id}\t{content}\n".format(
            #                 qname=qname, qclass=qclass, ttl=key['ttl'], id=qid, content=ipv6))
            #             break
            #         except ValueError:
            #             node = None

        if qtype in ['A', 'ANY']:
            ipv4 = qname.split(".", 1)
            if "static.ip.net.tw" in ipv4[1].lower():
                ipv4 = ipv4[0].replace("-", ".", 3)
                try:
                    node = rtree.search_best(ipv4)
                except:
                    node = None

                if node:
                    if node.data['prefix'].version == 4:
                        out.write("DATA\t{qname}\t{qclass}\tA\t{ttl}\t{id}\t{content}\n".format(
                            qname=qname, qclass=qclass, ttl=prefixes[node.data['prefix']]['ttl'], id=qid, content=ipv4))
            # for ip_range in prefixes.keys():
            #     key = prefixes[ip_range]
            #     if qname.endswith('.%s' % (key['forward'],)) and key['version'] == 4 and qname.startswith(key['prefix']):
            #         node = qname[len(key['prefix']):].replace('%s.%s' % (key['postfix'], key['forward'],), '')
            #         try:
            #             node = base36decode(node)
            #             ipv4 = netaddr.IPAddress(int(ip_range.value) + int(node))
            #             out.write("DATA\t{qname}\t{qclass}\tA\t{ttl}\t{id}\t{content}\n".format(
            #                 qname=qname, qclass=qclass, ttl=key['ttl'], id=qid, content=ipv4))
            #             break
            #         except ValueError:
            #             log(3, 'failed to base36 decode host value', node=node)

        if qtype in ['PTR', 'ANY'] and qname.endswith('.ip6.arpa'):
            ptr = qname.split('.')[:-2][::-1]
            ipv6 = ':'.join(''.join(ptr[x:x+4]) for x in range(0, len(ptr), 4))
            try:
                netaddr.IPAddress(ipv6)
            except:
                continue
            node = rtree.search_best(str(ipv6))
            if node:
                ip_range, key = node.data['prefix'], prefixes[node.data['prefix']]
                content = str(ipv6).replace(":", "-") + "." + key['forward']
                out.write("DATA\t{qname}\t{qclass}\tPTR\t{ttl}\t{id}\t{content}\n".format(
                    qname=qname, qclass=qclass, ttl=key['ttl'], id=qid, content=content)
                )
        if qtype in ['PTR', 'ANY'] and qname.endswith('.in-addr.arpa'):
            ptr = qname.split('.')[:-2][::-1]
            ipv4 = '.'.join(x for x in ptr)
            try:
                ipv4 = netaddr.IPAddress(ipv4)
            except:
                ipv4 = netaddr.IPAddress('127.0.0.1')
            node = rtree.search_best(str(ipv4))
            if node:
                ip_range, key = node.data['prefix'], prefixes[node.data['prefix']]
                content = str(ipv4).replace(".", "-") + "." + key['forward']
                out.write("DATA\t{qname}\t{qclass}\tPTR\t{ttl}\t{id}\t{content}\n".format(
                    qname=qname, qclass=qclass, ttl=key['ttl'], id=qid, content=content)
                )
        if qtype in ['SOA', 'ANY', 'NS']:
            for ip_range in prefixes.keys():
                if qname == prefixes[ip_range]['domain']:
                    if  qtype == 'SOA':
                        out.write("DATA\t{qname}\t{qclass}\tSOA\t{ttl}\t{id}\t{dns} {email} {time} 10800 3600 604800 3600\n".format(
                            qname=qname, qclass=qclass, ttl=defaults['ttl'], id=qid, dns=defaults['dns'],
                            email=defaults['email'], time=time.strftime('%Y%m%d%H')))
                    if qtype in ['ANY', 'NS']:
                        for ns in defaults['nameserver']:
                            out.write("DATA\t{qname}\t{qclass}\tNS\t{ttl}\t{id}\t{content}\n".format(
                                qname=qname, qclass=qclass, ttl=defaults['ttl'], id=qid, content=ns))
                    break
                elif qname == prefixes[ip_range]['forward']:
                    if not qtype == 'NS':
                        out.write(
                            "DATA\t{qname}\t{qclass}\tSOA\t{ttl}\t{id}\t{dns} {email} {time} 10800 3600 604800 3600\n".format(
                                qname=prefixes[ip_range]['forward'], qclass=qclass, ttl=prefixes[ip_range]['ttl'], id=qid, dns=defaults['dns'],
                                email=defaults['email'], time=time.strftime('%Y%m%d%H')))
                    if qtype in ['ANY', 'NS']:
                        for ns in defaults['nameserver']:
                            out.write("DATA\t{qname}\t{qclass}\tNS\t{ttl}\t{id}\t{content}\n".format(
                                qname=qname, qclass=qclass, ttl=defaults['ttl'], id=qid, content=ns))

        out.write("END\n")
        out.flush()

    logger.info(log_message(10, "terminating"))
    return 0


def parse_config(config_path):
    network = dict()
    with open(config_path) as config_file:
        config_dict = yaml.load(config_file)

    defaults = config_dict.get('defaults', {})
    prefixes = {netaddr.IPNetwork(prefix): info for prefix, info in config_dict['prefixes'].items()}
    for key in prefixes:
        if 'subnet' in prefixes[key]:
            subnet = list(key.subnet(prefixes[key]['subnet']))
            if subnet:
                for i in subnet:
                    network[i] = deepcopy(prefixes[key])
            else:
                network[key] = deepcopy(prefixes[key])
        else:
            network[key] = deepcopy(prefixes[key])

    for zone in network:
        if 'domain' not in network[zone]:
            network[zone]['domain'] = IP(str(zone.cidr)).reverseName()[:-1]

    rtree = radix.Radix()

    for prefix in network.keys():
        node = rtree.add(str(prefix))
        node.data['prefix'] = prefix
    return defaults, network, rtree


if __name__ == '__main__':
    logger = setup_logger(LOGLEVEL)
    if len(sys.argv) > 1:
        config_path = sys.argv[1]
        if len(sys.argv) > 2:
            LOGLEVEL = int(sys.argv[2])
    else:
        config_path = CONFIG

    defaults, prefixes, rtree = parse_config(config_path)
    sys.exit(parse(defaults, prefixes, rtree, logger, sys.stdin, sys.stdout))
