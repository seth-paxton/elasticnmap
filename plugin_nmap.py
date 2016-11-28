#!/usr/bin/env python

from datetime import datetime
import json
import os
from elasticsearch import Elasticsearch
import nmap


def store(data, index, dtype):
    """
    Store data in ES
    """

    es_conn = Elasticsearch(['localhost'])
    res = es_conn.index(index=index, doc_type=dtype, body=data)

    return res

def scan(cidr, ports):
    """
    Instantiate scanner
    """
    nmapper = nmap.PortScanner()
    nmapper.scan(cidr, ports)

    return nmapper


def scan_results(nmapper):
    """
    scan_results parses scan nmapperap scan and converts it to json
    """

    scan_list = []
    nmapperap_dict = {}
    for host in nmapper.all_hosts():
        scan_time = datetime.now()
        tcp_ports_dict = {}
        udp_ports_dict = {}
        for port in nmapper[host].all_tcp():
            if nmapper[host].has_tcp(port) and nmapper[host]['tcp'][port]['state'] == 'open':
                tcp_ports_dict[port] = nmapper[host]['tcp'][port]
        for port in nmapper[host].all_udp():
            if nmapper[host].has_tcp(port):
                udp_ports_dict[port] = nmapper[host]['udp'][port]
        nmapperap_dict['host'] = host
        nmapperap_dict['timestamp'] = scan_time.isoformat()
        nmapperap_dict['state'] = nmapper[host].state()
        nmapperap_dict['tcp_ports'] = tcp_ports_dict
        nmapperap_dict['udp_ports'] = udp_ports_dict
        scan_list.append(nmapperap_dict.copy())

    return scan_list

def main():
    """
    Run the tool
    """
    cidr = os.environ['CIDR']
    ports = os.environ['PORTS']
    scans = scan(cidr, ports)
    results = scan_results(scans)
    for hosts in results:
        hosts = json.dumps(hosts)
        print hosts
        store(hosts, "nmap", "scans")

if __name__ == "__main__":
    main()
