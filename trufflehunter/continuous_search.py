import dns_lib
import threading
import time
import logging
import signal
import sys
import concurrent.futures
from traceback import print_exc
import os
import subprocess
import argparse
import random
import location_finder
from datetime import datetime
from datetime import timedelta

class BaseSearcher:
    domains = []
    resolver = ''
    _lock = threading.Lock()

    # This must be protected by _lock 
    # (or at least, it used to, and I don't want to introduce bugs by removing it when I'm not sure)
    domain_file = ''

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
            resp = subprocess.check_output(['kdig', '8.8.8.8'], universal_newlines=True)
            self.dig_cmd = 'kdig'
        except OSError as err:
            # If kdig wasn't found, try dig.
            try:
                resp = subprocess.check_output(['dig', '8.8.8.8'], universal_newlines=True)
                self.dig_cmd = 'dig'
            except OSError as err:
                logging.critical('Neither dig nor kdig found on this machine.')
                exit(1)

    def updateDomains(self):
        # Look for hostname.seldusaer.xyz subdomain to see which ISP each ark node is in (we can check our authoritative ns logs)
        self.domains.append(self.hostname + '.seldusaer.xyz')
        with open(self.domain_file) as f:
            for line in f:
                domain = line.rstrip()
                if domain not in self.domains:
                    self.domains.append(domain)
    
    # Generate commands to pass via command line to dig/kdig
    def generateCommands(self, resolver):
        cmds = []
        repeats = 5

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
            for i in range(0, repeats):
                cmds.append(cmd)

        # Shuffle the list so no domains are consistently last, 
        # in case timeouts cause them to be skipped
        random.shuffle(cmds)
        return cmds

    def createSearcherCommands(self, cmds):
        sleep_interval = 30
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
            
        for resolver in self.resolvers:
            cmd_file = self.commandFileName(resolver)
            
            # Find out which PoP this node currently hits
            loc = self.location_finder.getPoPLocation(resolver)

            dns_lib.multipleDigRequests(self.scripts[resolver], self.hostname, resolver, loc=loc, dig_cmd=self.dig_cmd)

    def __init__(self, resolvers, hostname, domain_file):
        self.detectDigCmd()
        self.location_finder = location_finder.LocationFinder(self.dig_cmd)
        # self.updateDomains()
        self.resolvers = resolvers
        self.hostname = hostname
        self.domain_file = domain_file
        self.updateDomains()

        for resolver in resolvers:
            cmds = self.generateCommands(resolver)
            # searcher_script = self.commandFileName(resolver)
            self.scripts[resolver] = self.createSearcherCommands(cmds)

class Searcher(BaseSearcher):
    iterations = 30
    threads = []
    hostname = ''
    dig_cmd = 'dig'
    start_time = datetime.now()

    def runBaseSearcher(self, resolvers, domain_file):
        base_searcher = BaseSearcher(resolvers, self.hostname, domain_file)
        start_time = datetime.now()
        for i in range(0, self.iterations):
            # Search for domains
            base_searcher.searchForDomains()
            end_time = datetime.now()

            # On the last iteration, don't sleep: we need to rotate the result file out.
            if i == self.iterations-1:
                break
            
            # Sleep for the remainder of the minute, but calculate that minute using total start time so errors don't accumulate
            time_remaining = (self.start_time + timedelta(minutes=(i+1)) - end_time).total_seconds()
            if time_remaining <= 0:
                with open(self.hostname+'_error.log', 'a') as logfile:
                    logfile.write("Negative time_remaining in runBaseSearcher:\n")
                    logfile.write("\tself.start_time: "+str(self.start_time)+"\n")
                    logfile.write("\ttimedelta(minutes=(i+1)): " + str(timedelta(minutes=(i+1))) + "\n")
                    logfile.write("\ti: "+ str(i))
                    logfile.write("\tend_time: " + str(end_time)+"\n")
                    logfile.write("\ttime_remaining: "+ str(time_remaining) + "\n")
            elif time_remaining < 60 and time_remaining >= 0:
                time.sleep(time_remaining)
                # logging.debug("Time remaining: " + str(time_remaining))
            elif time_remaining > 60:
                with open(self.hostname+'_error.log', 'a') as logfile:
                    logfile.write("time_remaining greater than 60 in runBaseSearcher: " + str(time_remaining) + "\n")

    def __init__(self, resolvers, hostname='UNKNOWN_HOST', domain_file='stalkerware_domains.txt'):
        self.hostname = hostname
        self.domain_file = domain_file

        # Record start time - measurements can't take longer than self.iterations minutes.
        self.start_time = datetime.now()

        self.runBaseSearcher(resolvers, domain_file)

def main():
    logging.basicConfig(
        format='%(asctime)s %(levelname)-8s %(message)s',
        level=logging.DEBUG,
        datefmt='%Y-%m-%d %H:%M:%S')

    parser = argparse.ArgumentParser()
    parser.add_argument("--input", "-i", help="File to read domains from")
    parser.add_argument("--log", "-l", help="Previous searcher failed to finish in time, so record start time in error log")
    args = parser.parse_args()

    default_resolvers = ['8.8.8.8', '9.9.9.9', '1.1.1.1', '208.67.220.220']
    # default_resolvers = ['8.8.8.8', '1.1.1.1', '208.67.220.220']
    

    try:
        hostname = subprocess.check_output(['hostname'], universal_newlines=True)
    except:
        print("Failed to get hostname")
        exit(1)
    hostname = str(hostname).rstrip()
    
    if not args.input:
        with open(hostname+'_error.log', 'a') as logfile:
            logfile.write('Input file must be specified with -i or --input. Exiting.')
        exit(1)

    if args.log:
        with open(hostname+'_error.log', 'a') as log:
            log.write("Parser started at " + str(datetime.now())+"\n") 
    
    searcher = Searcher(default_resolvers, hostname, args.input)

if __name__=="__main__":
    main()
    
        

