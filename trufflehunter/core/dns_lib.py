from . import config 
from datetime import datetime
import subprocess
import re
import time
import logging
'''
Records the relevant pieces of the output of dig or kdig.
'''
class DnsResponse:
    status = ''
    opcode = ''
    flags = []
    qtype = ''
    rtt = -1
    # The timestamp returned by Dig in the line starting with ';; WHEN:'
    dig_ts = datetime.now()
    # The time at which the response was received, at ms granularity
    ts = datetime.now()
    requested_domain = ''
    domain = ''
    ttl = -1
    # Can be CNAME, A, NS, or AAAA afaik
    r_type = ''
    ip = ''
    resolver = ''
    # Recursion Desired (RD) flag in request. Dig assumes true if not specified.
    rd = True

    def extractField(self, line, regex, variable):
        target = ''
        try:
            target = re.search(regex, line).groupdict()[variable]
        except AttributeError:
            logging.error('Regex did not find a match for ' + variable + '. Line = ' + line)
        except KeyError:
            logging.error('No value could be parsed for ' + variable + '. Line = ', line)
        return target

    def printSerialized(self):
        print('Domain: ' + self.domain)
        print('Status: ' + self.status)
        print('Opcode: ' + self.opcode)
        print('Query type: ' + self.qtype)
        print('RTT: ' + str(self.rtt) + 'ms')
        print('Dig timestamp: ' + str(self.dig_ts))
        print('TTL: ' + str(self.ttl))
        print('Response type: ' + self.r_type)
        print('IP: ' + self.ip)
        print('Deprecated timestamp: ' + str(self.ts))
        print('Resolver: ', self.resolver)

    def __init__(self, dig_output, ts, parser_type):
        if parser_type == 'dig':
            parser = DigParser(dig_output, ts)
            parser.parse(dig_output, ts)
        elif parser_type == 'kdig':
            parser = KdigParser(dig_output, ts)
            parser.parse(dig_output, ts)
        elif parser_type == 'csv':
            parser = CsvParser(dig_output)
            parser.parse()
        
        # self.printSerialized()

class DigParser(DnsResponse):

    def __getitem__(self, index):
        return getattr(self,index)

    def parse(self, dig_output, ts, pop_location):
        question_section = False
        answer_section = False
        authority_section = False

        # add loc info
        if pop_location != 'NO_LOCATION_SPECIFIED':
            self.pop_location = pop_location

        self.ts = ts
        lines = dig_output.splitlines()
        for i, line in enumerate(lines):
            line = str(line)  
            if '->>HEADER<<-' in line:
                try:
                    captures = re.search('opcode:\s+(?P<opcode>[A-Z]+)[,;]\s+status:\s+(?P<status>[A-Z]+)[,;]\s', line).groupdict()
                    self.opcode = captures['opcode']
                    self.status = captures['status']
                except AttributeError:
                    logging.error("Regex did not match in header section. Line = "+line)
                except KeyError:
                    logging.error("No value could be parsed for status and/or opcode. Line = ", line)
            if ';; flags:' in line:
                if ' rd' in line:
                    self.rd = True
                else:
                    self.rd = False
            if ';; QUESTION' in line:
                # This is the line before the question section
                question_section = True
                continue
            if question_section:
                try:
                    self.requested_domain = re.search('^;?(?P<domain>\S+)\s+', line).groupdict()['domain']
                except AttributeError:
                    logging.error("Regex did not match in question section. Line = "+line)
                except KeyError:
                    logging.error("No value could be parsed for requested_domain. Line = ", line)
                question_section = False
            if 'ANSWER SECTION' in line:
                # This is the line before the answer section.
                answer_section = True
                continue
            if answer_section and line == '':
                answer_section = False
            # Only record the answer if it's the first line, otherwise we miss the CNAMEs
            if answer_section and self.r_type == '':
                try:
                    captures = re.search("(?P<domain>\S*)\s+(?P<ttl>\d+)\s+IN\s+(?P<record_type>[A-Z]+)\s+(?P<ip>\S*)", line).groupdict()
                    self.ttl = int(captures['ttl'])
                    self.r_type = captures['record_type']
                    self.domain = captures['domain']
                    self.ip = captures['ip']
                except AttributeError:
                    logging.error("Regex did not match in answer section. Line = "+line)
                except KeyError:
                    logging.error("No value could be parsed for ttl, r_type, ip, and/or domain. Line = ", line)
            if ';; Query time:' in line:
                self.rtt = int(self.extractField(line, ';;\sQuery time: (?P<rtt>\d+).*', 'rtt')) 
            if ';; WHEN:' in line:
                try:
                    # Dates are of the form 'Tue Oct 15 16:18:32 DST 2019'
                    captures = re.search(';; WHEN: (?P<day>[a-zA-Z]+ [a-zA-Z]+ [0-9]+ [0-9]+:[0-9]+:[0-9]+) (?P<timezone>[A-Z]+) (?P<year>[0-9]+)', line).groupdict()
                    day = captures['day']
                    year = captures['year']
                    timezone = captures['timezone']
                    self.dig_ts = datetime.strptime(day + ' ' + year + ' ' + timezone, '%c %Z')
                except AttributeError as err:
                    logging.error("Regex did not match for timestamp. Line = " + line)
                except KeyError:
                    logging.error("No value could be parsed for day and/or year. Line = ", line)
            if ';; SERVER:' in line:
                self.resolver = self.extractField(line, ';; SERVER:\s(?P<resolver>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)#', 'resolver')
    
    def __init__(self, dig_output, ts, loc ='NO_LOCATION_SPECIFIED'):
        self.parse(dig_output, ts, loc)
        self.raw_dig_output = dig_output
    
    def __repr__(self):
        string = ""
        string += 'Domain: ' + self.domain + ", "
        string += 'Status: ' + self.status + ", "
        string += 'Opcode: ' + self.opcode + ", "
        string += 'Query type: ' + self.qtype + ", "
        string += 'RTT: ' + str(self.rtt) + 'ms' + ", "
        string += 'Dig timestamp: ' + str(self.dig_ts) + ", "
        string += 'TTL: ' + str(self.ttl) + ", "
        string += 'Response type: ' + self.r_type + ", "
        string += 'IP: ' + self.ip + ", "
        string += 'Deprecated timestamp: ' + str(self.ts) + ", "
        string += 'Resolver: ' + str(self.resolver) + ", "
        return string

class KdigParser(DnsResponse):
    # hostname, ts,                       resolver, requested_domain, recursion_desired, response_domain, status,  opcode, rtt, dig_ts,                     ttl, response_type, ip,           pop_location
    # atl3-us,  2020-03-18 17:20:20.260657,       , ;,                True,              pipe.thd.cc.,    NOERROR, QUERY,  -1,  2020-03-18 17:20:05.635520, 0 ,  A,             104.31.95.14, atl1,
    def parse(self, dig_output, ts):
        question_section = False
        answer_section = False
        authority_section = False

        self.ts = ts
        lines = dig_output.splitlines()
        for i, line in enumerate(lines):
            line = str(line)  
            if '->>HEADER<<-' in line:
                try:
                    captures = re.search('opcode:\s+(?P<opcode>[A-Z]+)[,;]\s+status:\s+(?P<status>[A-Z]+)[,;]\s', line).groupdict()
                    self.opcode = captures['opcode']
                    self.status = captures['status']
                except AttributeError:
                    logging.error("Regex did not match in header section. Line = "+line)
                except KeyError:
                    logging.error("No value could be parsed for status and/or opcode. Line = ", line)
            if ';; Flags:' in line:
                if ' rd' in line:
                    self.rd = True
                else:
                    self.rd = False
            if ';; QUESTION' in line:
                # This is the line before the question section
                question_section = True
                continue
            if question_section:
                try:
                    self.requested_domain = re.search('^;;\s(?P<domain>\S+)\s+', line).groupdict()['domain']
                except AttributeError:
                    logging.error("Regex did not match in question section. Line = "+line)
                except KeyError:
                    logging.error("No value could be parsed for requested_domain. Line = ", line)
                question_section = False
            if 'ANSWER SECTION' in line:
                # This is the line before the answer section.
                answer_section = True
                continue
            if answer_section and line == '':
                answer_section = False
            # Only record the answer if it's the first line, otherwise we miss the CNAMEs
            if answer_section and self.r_type == '':
                try:
                    captures = re.search("(?P<domain>\S*)\s+(?P<ttl>\d+)\s+IN\s+(?P<record_type>[A-Z]+)\s+(?P<ip>\S*)", line).groupdict()
                    self.ttl = int(captures['ttl'])
                    self.r_type = captures['record_type']
                    self.domain = captures['domain']
                    self.ip = captures['ip']
                except AttributeError:
                    logging.error("Regex did not match in answer section. Line = "+line)
                except KeyError:
                    logging.error("No value could be parsed for ttl, r_type, ip, and/or domain. Line = ", line)
            if ';; Query time:' in line:
                self.rtt = int(self.extractField(line, ';;\sQuery time: (?P<rtt>\d+).*', 'rtt')) 
            if ';; Time' in line:
                try:
                    # Dates are of the form '2020-03-18 17:20:54 UTC'
                    captures = re.search(';; Time (?P<time>.+)$', line).groupdict()
                    time = captures['time']
                    self.dig_ts = datetime.strptime(time, '%Y-%m-%d %X %Z')
                except AttributeError as err:
                    logging.error("Regex did not match for timestamp. Line = " + line)
                except KeyError:
                    logging.error("No value could be parsed for day and/or year. Line = ", line)
            if ';; From' in line:
                captures = re.search(';; From\s(?P<resolver>[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)@\S+\sin\s(?P<rtt>[0-9]+\.[0-9]+)\s(?P<units>[a-z]+)', line).groupdict()
                self.resolver = captures['resolver']
                rtt = float(captures['rtt'])
                units = captures['units']
                if units == 'ms':
                    rtt = rtt
                elif units == 'us':
                    rtt = rtt*1000
                elif units == 's':
                    rtt = rtt / 1000
                self.rtt = rtt

    def __init__(self, dig_output, ts):
        self.parse(dig_output, ts)

def splitResponses(resp):
    responses = []
    single_response = ''
    lines = resp.split('\n')
    for i, line in enumerate(lines):
        if ('->>HEADER<<-' in line  and i > 7):
            responses.append(single_response)
            single_response = ''
            single_response += line + '\n'

        else:
            single_response += line + '\n'
    # Append the last response too
    responses.append(single_response)
    return responses


# def makeDigRequest(resolver, target, recursion_desired, raw_result_filename='', dig_cmd='dig', loc='None', hostname='UNKNOWN_HOSTNAME'):
#     recurse_flag = '+recurse'
#     if resolver[0] != '@':
#         resolver = '@' + resolver
#     if not recursion_desired:
#         recurse_flag = '+norecurse'
#     try:
#         resp = subprocess.check_output([dig_cmd, resolver, target, recurse_flag], universal_newlines=True)
#         ts = datetime.utcnow()
#     except subprocess.CalledProcessError as err:
#         logging.error('Check_output failed for dig, err = ', err)
#         return
    
#     if raw_result_filename != '':
#         query = dig_cmd + ' ' + resolver + ' ' + target
#         if not recursion_desired:
#             query += ' ' + recurse_flag
#         dns_file = DnsFile(raw_result_filename)
#         dns_file.writeDigResults(ts, query, resp, raw_result_filename)

#     if config.Config["other"]["verbose"] == True:
#         # CSV file. Columns:
#         # hostname, ts, resolver, requested_domain, recursion_desired, response_domain, status, opcode, rtt, dig_ts, ttl, response_type, ip, pop_location
#         # Example: Taliesin,2020-02-05 00:33:35.342429,8.8.8.8,a.thd.cc,False,a.thd.cc.,NOERROR,QUERY,6,2020-02-04 16:33:35,172,A,104.31.95.14,lax,
#         # ts, resolver, requested_domain, and recursion_desired are request parameters. Everything else comes from the response.
#         # Note that ts is in UTC and dig_ts is in the local time of the machine running the code
#         r = DnsResponse(resp, ts)
#         # r.printSerialized()
#         row = hostname + ',' + str(r.ts) + ',' + resolver.replace('@','') + ',' + target + ',' + str(recursion_desired) + ',' + r.domain + ',' + r.status + ',' + r.opcode + ',' + str(r.rtt) + ',' + str(r.dig_ts) + ',' + str(r.ttl) + ',' + r.r_type + ',' + r.ip + ',' + loc + ','
#         printAndLog(row)
    
#     return DnsResponse(resp, ts)

'''
Make multiple dig requests. Return a list of parsed dig results
'''
def multipleDigRequests(cmd, hostname, resolver, loc='NO_LOCATION_SPECIFIED', dig_cmd='dig'):
    try:
        process = subprocess.Popen(cmd.split(), stdout=subprocess.PIPE, universal_newlines=True)
        resp, err = process.communicate()
        ts = datetime.utcnow()
        if err:
            logging.error('Subprocess.Popen failed for dig: ', err)
            return
    except subprocess.CalledProcessError as err:
        logging.error('Check_output failed for dig, err = ', err)
        return

    responses = splitResponses(resp)
    dig_results = []
    for response in responses:
        if dig_cmd == 'dig':
            r = DigParser(response, ts, loc)
        elif dig_cmd == 'kdig':
            r = KdigParser(response, ts, loc)
        dig_results.append(r)
    return dig_results
