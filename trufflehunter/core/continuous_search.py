from . import dns_lib
from . import location_finder
from . import config
from .utils import printAndLog
from .compare_results import estimateFilledCaches
from collections import defaultdict
from datetime import datetime
from datetime import timedelta
from traceback import print_exc
import threading
import time
import logging
import signal
import sys
import concurrent.futures
import os
import subprocess
import argparse
import random

my_logger = logging.getLogger('TrufferHunter')

class BaseSearcher:
    domains = []
    resolver = ''
    repeats = 10 # number of dig requests per domain

    # Dig or kdig?
    dig_cmd = ''

    # Name of this host
    hostname = ''

    # Location finder: finds out which PoPs this node is currently hitting (at a best guess)
    # Needs to be reinitialized to set the dig command in __init__
    location_finder = location_finder.LocationFinder('dig')

    # List of scripts for dig multi-domain on command line mode
    searcher_scripts = []

    # Script in a string for avoiding writing files
    scripts = {}

    def commandFileName(self, resolver):
        return resolver.replace('.','-') + '.sh'

    def detectDigCmd(self):
        try:
            resp = subprocess.check_output(['dig', '8.8.8.8'], universal_newlines=True)
            self.dig_cmd = 'dig'
        except OSError as err:
            my_logger.critical('No dig found on this machine.')
            exit(1)

    # def updateDomains(self):
    #     # Look for hostname.seldusaer.xyz subdomain to see which ISP each ark node is in (we can check our authoritative ns logs)
    #     # this part is not needed
    #     # self.domains.append(self.hostname + '.seldusaer.xyz')
    #     with open(self.domain_file) as f:
    #         for line in f:
    #             domain = line.rstrip()
    #             if domain not in self.domains:
    #                 self.domains.append(domain)
    
    # Generate commands to pass via command line to dig/kdig
    def generateCommands(self, resolver):
        cmds = []

        # Generate commands for dig's batch mode
        for d in self.domains:
            # d = line.rstrip()
            rd = '+recurse'
            if '.seldusaer.xyz' not in d or 'groundtruth' in d:
                rd = '+norecurse'
                
            cmd = ''
            if self.dig_cmd == 'dig':
                cmd = d + ' @' + resolver + ' ' + rd + ' +tries=1 +time=1 '
            else:
                cmd = d + ' @' + resolver + ' ' + rd + ' +noretry +time=1 '
            for i in range(0, self.repeats):
                cmds.append(cmd)

        # Shuffle the list so no domains are consistently last, 
        # in case timeouts cause them to be skipped
        random.shuffle(cmds)
        return cmds

    def createSearcherCommands(self, cmds):
        script = ''
        # script += '#!/bin/bash\n\n'
        script += self.dig_cmd + ' '
        for i, cmd in enumerate(cmds):
            script +=  ' ' + cmd
            # if i%sleep_interval == 0 and i < len(cmds)-1 and i > 0:
            #     # script += '\nsleep 0.1\n'
            #     script += ';\n' + self.dig_cmd + ' '
        return script

    '''
    Over some time interval smaller than a minute, request all domains from self.resolvers.
    '''
    def searchForDomains(self, shutdown_event=None):
        search_results = []
        unknown_resolvers = []
        for resolver in self.resolvers:
            cmd_file = self.commandFileName(resolver)
            
            # Find out which PoP this node currently hits
            loc = self.location_finder.getPoPLocation(resolver)
            if 'UNKNOWN' in loc:
                unknown_resolvers.append(resolver)
            #printAndLog("searchForDomains loc:",loc,level = "INFO")
            search_results += dns_lib.multipleDigRequests(self.scripts[resolver], self.hostname, resolver, loc=loc, dig_cmd=self.dig_cmd)
        if len(unknown_resolvers) > 0:
            print('WARNING: Erroneous responses were returned for the location queries to the following resolvers:', unknown_resolvers)
            print('These responses did not match the usual format of responses given by the public resolvers.')
            print('Your ISP may be transparently proxying some or all of your DNS queries. For more info, see https://github.com/ucsdsysnet/trufflehunter/blob/master/README.md#isp-interception-of-dns-queries')
        return search_results

    def __init__(self, resolvers, hostname, domains):
        self.detectDigCmd()
        self.location_finder = location_finder.LocationFinder(self.dig_cmd)
        self.resolvers = resolvers
        self.hostname = hostname
        self.domains = domains
        self.repeats = config.Config["search"]["number_of_attempts"]
        #self.updateDomains()

        for resolver in resolvers:
            cmds = self.generateCommands(resolver)
            # searcher_script = self.commandFileName(resolver)
            self.scripts[resolver] = self.createSearcherCommands(cmds)

class Searcher(BaseSearcher):
    # Todo: Determine how many iterations we want to probe
    iterations = 1
    threads = []
    hostname = ''
    dig_cmd = 'dig'
    start_time = datetime.now()

    def runBaseSearcher(self):
        self.start_time = datetime.now()

        base_searcher = BaseSearcher(self.resolvers, self.hostname, self.domains)
        start_time = datetime.now()
        all_search_results = []
        for i in range(0, self.iterations):
            # Search for domains
            search_results = base_searcher.searchForDomains()
            #print(len(search_results))
            all_search_results += search_results
            # Todo: dump search results to a database
            end_time = datetime.now()

            # On the last iteration, don't sleep: we need to rotate the result file out.
            if i == self.iterations-1:
                break
            
            # Sleep for the remainder of the minute, but calculate that minute using total start time so errors don't accumulate
            time_remaining = (self.start_time + timedelta(minutes=(i+1)) - end_time).total_seconds()
            if time_remaining <= 0:
                my_logger.debug("Negative time_remaining in runBaseSearcher:\n")
                my_logger.debug("\tself.start_time: "+str(self.start_time)+"\n")
                my_logger.debug("\ttimedelta(minutes=(i+1)): " + str(timedelta(minutes=(i+1))) + "\n")
                my_logger.debug("\ti: "+ str(i))
                my_logger.debug("\tend_time: " + str(end_time)+"\n")
                my_logger.debug("\ttime_remaining: "+ str(time_remaining) + "\n")
            elif time_remaining < 60 and time_remaining >= 0:
                time.sleep(time_remaining)
                # my_logger.debug("Time remaining: " + str(time_remaining))
            elif time_remaining > 60:
                my_logger.debug("time_remaining greater than 60 in runBaseSearcher: " + str(time_remaining) + "\n")
        
        # key for first dict: domain name
        # key for second dict: resolver
        # key for third dict: data entries
        # location is fixed for one resolver from one vantage point

        # construct initial state for all domains and all resolvers
        domain_to_pop_to_data_mapping = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))
        for requested_domain in self.domains:
            for requested_resolver in self.resolvers:
                _ = domain_to_pop_to_data_mapping[requested_domain][requested_resolver]["dig_ts"]
                _ = domain_to_pop_to_data_mapping[requested_domain][requested_resolver]["ttl"]
                _ = domain_to_pop_to_data_mapping[requested_domain][requested_resolver]["pop_location"]
        
        printAndLog("Raw Dig Results:")
        for r in all_search_results:
            printAndLog(r)
            if r["requested_domain"].strip(".").strip("\r\n") in self.domains and r["resolver"] in self.resolvers:
                resolver_to_data_mapping = domain_to_pop_to_data_mapping[r["requested_domain"].strip(".").strip("\r\n")]
                resolver_to_data_mapping[r["resolver"]]["dig_ts"].append(r["dig_ts"])
                resolver_to_data_mapping[r["resolver"]]["ttl"].append(r["ttl"])
                resolver_to_data_mapping[r["resolver"]]["pop_location"].append(r["pop_location"])

        for requested_domain in domain_to_pop_to_data_mapping.keys():
            resolver_to_data_mapping = domain_to_pop_to_data_mapping[requested_domain]
            for resolver in resolver_to_data_mapping.keys():
                if len(resolver_to_data_mapping[resolver]["ttl"]) == 0:
                    print("\nDomain:{}, Resolver:{}, ERROR_NO_DATA_AVAILABLE".format(requested_domain.rstrip("."), resolver))
                else:
                    #printAndLog(pop_to_data_mapping[key]["ttl"])
                    count = estimateFilledCaches(resolver_to_data_mapping[resolver],resolver)
                    resolver_location = all_search_results[0]['pop_location']
                    print("\nDomain:{}, Resolver:{}, Location: {}, Cache Count: {}, Last Probed: {}".format(requested_domain.rstrip("."), resolver, resolver_location, count, self.start_time.strftime("%Y-%m-%d %X %Z")))
        

    def __init__(self, resolvers, domains, hostname='UNKNOWN_HOST'):
        self.hostname = hostname
        self.domains = domains
        self.resolvers = resolvers
        
    
        

