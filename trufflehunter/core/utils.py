import tldextract
import logging
my_logger = logging.getLogger('TrufferHunter')

""" Read a file of domains, assuming it exists """
def readDomainFile(filename):
    domains = []
    with open(filename) as f:
        for line in f:
            line = line.strip()
            if line == '':
                continue
            domains.append(line)
    return domains

""" Skip invalid domain inputs """
def parseDomains(domains):
    legit_domains = []
    for domain in domains:
        try:
            tmp = tldextract.extract(domain)
            if tmp.fqdn == "":
                printAndLog("WARNING","{} is not a valid domain, we will skip it".format(domain))
                continue
        except:
            printAndLog("WARNING","{} is not a valid domain, we will skip it".format(domain))
            continue
        legit_domains.append(domain)
    return legit_domains

def printAndLog(level, msg):
    level = level.lower()
    print("{}: {}".format(level.capitalize(),msg))
    func = getattr(my_logger,level)
    func(msg)
