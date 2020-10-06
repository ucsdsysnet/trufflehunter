import logging
import re
my_logger = logging.getLogger('TrufferHunter')


""" Domain validation """
def isValidHostname(hostname):
    # https://stackoverflow.com/questions/2532053/validate-a-hostname-string
    if len(hostname) > 255:
        return False
    if hostname[-1] == ".":
        hostname = hostname[:-1] # strip exactly one dot from the right, if present
    allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
    return all(allowed.match(x) for x in hostname.split("."))

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
            tmp = isValidHostname(domain)
            if tmp == False:
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
