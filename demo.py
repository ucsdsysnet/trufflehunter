from trufflehunter.core.continuous_search import Searcher
from trufflehunter.core.location_finder import LocationFinder
from trufflehunter.core.const import ALL_RESOLVER_IPS
from trufflehunter.core.utils import readDomainFile, parseDomains, printAndLog
import argparse
import subprocess
import logging
from datetime import datetime
#from ..core import continuous_search
def main():
    # a = LocationFinder()
    #print(a.getPoPLocation("1.1.1.1"))

    parser = argparse.ArgumentParser()
    parser.add_argument("--domain", "-d", help="Specify a single domain to probe")
    parser.add_argument("--file", "-f", help="Specify a list of domains to probe, one domain per line")
    parser.add_argument("--resolvers", "-r", nargs='+', default=["1.1.1.1"], choices = ALL_RESOLVER_IPS, help="Resolvers to Probe")
    parser.add_argument("--no_log", default=False, action='store_true', help="Disable logging")
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
    if args.no_log != True:
        handler = logging.FileHandler(filename="{}.log".format(hostname))
        formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
        handler.setFormatter(formatter)
        my_logger.addHandler(handler)
    else:
        my_logger.addHandler(logging.NullHandler())

    # start service
    my_logger.info("TrufferHunter Started At " + str(datetime.now()))

    # sanity check 
    if not args.file and not args.domain:
        printAndLog("ERROR", "You need to specify a domain (--domain/-d) or a list of domains (--file/-f, one domain per line). Exiting.")
        exit(1)
    elif args.file and args.domain:
        printAndLog("ERROR", "You can't specify both a domain and a list of domains. Exiting.")
        exit(1)
    elif args.file:
        # check file exists
        domains = readDomainFile(args.file)
        domains = parseDomains(domains)
    else:
        domains = parseDomains([args.domain])
    
    if len(domains) == 0:
        printAndLog("ERROR", "Please specify a valid domain. Exiting.")
        exit(1)

    if len(args.resolvers) == 0:
        printAndLog("ERROR", "Specify at least 1 resolver to proceed. Exiting.")
        exit(1)

    
    searcher = Searcher(args.resolvers, domains, hostname=hostname)

if __name__=="__main__":
    main()
    