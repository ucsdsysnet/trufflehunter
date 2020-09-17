import subprocess
import os
import re

# Find the max_ttls for all domains.
# Audrey forgets what she was using this for, it can stick around just in case.

def getMaxTTL(domain):
    ttls = []
    try:
        resp = subprocess.check_output(['dig', '+trace', domain], universal_newlines=True)
    except:
        print("Failed to run dig with trace!")
        exit(1)
    lines = resp.split('\n')
    cname_ttl = -1
    for line in lines:
        cname_match = re.match(domain+'.\s+(?P<ttl>[0-9]+)\s+IN\s+CNAME\s+(?P<cname>\S+)\.$', line)
        if cname_match:
            # If we get a CNAME, find the CNAME that the domain we searched for points to. The remaining lines should be A records for that CNAME.
            old_domain = domain
            domain = cname_match.groupdict()['cname']
            cname_ttl = cname_match.groupdict()['ttl']
            print("Old domain: " + old_domain + " - New domain: "+ domain)

        a_match = re.match(domain+'.\s+(?P<ttl>[0-9]+)\s+IN\s+A\s+[0-9]+[:\.][0-9]+[:\.][0-9]+[:\.][0-9]+', line)
        if a_match:
            ttls.append(int(a_match.groupdict()['ttl']))

    # If we didn't find any A records but did find CNAME records, record the CNAME ttl.
    if len(ttls) == 0 and cname_ttl != -1:
        ttls.append(cname_ttl)
    elif len(ttls) == 0:
        print("No records found - domain " + domain + " did not resolve.")
        return -1

    if len(set(ttls)) > 1:
        print('ERROR!! More than one maximum TTL was found for ' + domain + '!')
        print(ttls)
        return -1
    print(domain, ttls[0])
    return ttls[0]

def getAllMaxTTLs():
    with open('domain_lists/popular_domains.txt') as domains:
        for line in domains:
            getMaxTTL(line.rstrip())
    with open('domain_lists/stalkerware_domains.txt') as domains:
        for line in domains:
            getMaxTTL(line.rstrip())


def addressInNetwork(address, network):
    addr = ipaddress.ip_address(unicode(address, 'utf-8'))
    net = ipaddress.ip_network(unicode(network, 'utf-8'))
    return addr in net

def loadGooglePoPs():
    locs = {}
    with open('google_locations.txt') as all_google_pops:
        for line in all_google_pops:
            split = line.rstrip().split(' ')
            network = split[0]
            loc = split[1]
            locs[network] = loc
    self.google_locs = locs

def getPoPLocation(resolver):
    try:
        if resolver == '8.8.8.8':
            resp = subprocess.check_output(['dig', '@8.8.8.8', 'o-o.myaddr.l.google.com', '-t', 'txt', '+short'], universal_newlines=True)
            addr = resp.split('\n')[0].replace('"','')
            print(addr)
            for network in self.google_locs.keys():
                if addressInNetwork(addr, network):
                    return all_locs[network]
        elif resolver == '9.9.9.9':
            resp = subprocess.check_output(['dig', '@9.9.9.9', 'id.server', 'txt', 'chaos', '+short'], universal_newlines=True)
            return resp.split('.')[1]
        elif resolver == '1.1.1.1':
            resp = subprocess.check_output(['dig', '@1.1.1.1', 'id.server', 'txt', 'chaos', '+short'], universal_newlines=True)
            return resp.replace('"', '')
        elif resolver == '208.67.220.220':
            resp = subprocess.check_output(['dig', '@208.67.220.220', 'debug.opendns.com', '-t', 'txt', '+short'], universal_newlines=True)
            resp.split('\n')[0].split(' ')[1].split('.')[1]
        else:
            return 'UNKNOWN_RESOLVER_LOCATION_UNKNOWN'
    except subprocess.CalledProcessError:
        return 'DIG_FAILED_LOCATION_UNKNOWN'
    except AttributeError, KeyError:
        return 'PARSE_FAILED_' + resp.replace(',','-').replace('\n','-')
    except:
        return 'UNKNOW_ERROR_LOCATION_UNKNOWN'

def main():
    # all this is a bit broken, not being used.
    loadGooglePoPs()
    print('8.8.8.8: ' + getPoPLocation('8.8.8.8'))
    print('9.9.9.9: ' + getPoPLocation('9.9.9.9'))
    print('1.1.1.1: ' + getPoPLocation('1.1.1.1'))
    print('OpenDNS: ' + getPoPLocation('208.67.220.220'))

main()