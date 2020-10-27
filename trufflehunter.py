from trufflehunter.core.continuous_search import Searcher
from trufflehunter.core.location_finder import LocationFinder
from trufflehunter.core.const import ALL_RESOLVER_IPS
from trufflehunter.core.utils import readDomainFile, parseDomains, printAndLog, checkPositive
import trufflehunter.core.config as config

from datetime import datetime
from os import path
import argparse
import subprocess
import logging

#from ..core import continuous_search
def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", "-d", help="Specify a single domain to probe")
    parser.add_argument("--file", "-f", help="Specify a list of domains to probe, one domain per line")
    parser.add_argument("--resolvers", "-r", nargs='+', default=config.Config["search"]["resolvers"], choices = ALL_RESOLVER_IPS, help="Resolvers to Probe")
    parser.add_argument("--verbose", "-v", default=False, action='store_true', help="Verbose Mode, extra output info")
    parser.add_argument("--num_of_attempts", "-n", type=checkPositive, default=config.Config["search"]["number_of_attempts"],help="number of dig queries sent to probe a domain")
    args = parser.parse_args()

    try:
        hostname = subprocess.check_output(['hostname'], universal_newlines=True)
    except:
        print("Error: Failed to get hostname")
        exit(1)

    hostname = str(hostname).rstrip()
    
    # setup logging
    my_logger = logging.getLogger('TrufferHunter')
    my_logger.setLevel(logging.DEBUG)
    if args.verbose == True:
        # update config
        config.Config["other"]["verbose"] = True
        # setup logging
        handler = logging.FileHandler(filename="{}.log".format(hostname))
        formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        handler.setFormatter(formatter)
        my_logger.addHandler(handler)
    else:
        my_logger.addHandler(logging.NullHandler())

    # sanity check 
    if not args.file and not args.domain:
        print("You need to specify a domain (--domain/-d) or a list of domains (--file/-f, one domain per line). Exiting.")
        exit(1)
    elif args.file and args.domain:
        print("You can't specify both a domain and a list of domains. Exiting.")
        exit(1)
    elif args.file:
        # check file exists
        if path.exists(args.file) == False:
            print("Please specify a valid file. Exiting.")
            exit(1)
            
        domains = readDomainFile(args.file)
        domains = parseDomains(domains)
    else:
        domains = parseDomains([args.domain])

    if args.num_of_attempts:
        config.Config["search"]["number_of_attempts"] = args.num_of_attempts
    

    if args.resolvers:
        config.Config["search"]["resolvers"] = args.resolvers

    if len(domains) == 0:
        print("Please specify a valid domain. Exiting.")
        exit(1)

    if len(args.resolvers) == 0:
        print("Specify at least 1 resolver to proceed. Exiting.")
        exit(1)

    # start service
    my_logger.info("TrufferHunter Started At " + str(datetime.now()))
    
    print("Runtime Configs: number_of_attempts_per_domain={}, resolvers_to_try={}, verbose={}\n"\
        .format(config.Config["search"]["number_of_attempts"],\
            " ".join(config.Config["search"]["resolvers"]),\
            config.Config["other"]["verbose"]))

    searcher = Searcher(args.resolvers, domains, hostname=hostname)
    # Todo: return data for front end
    _ = searcher.runBaseSearcher()

if __name__=="__main__":
    main()
    