from datetime import datetime
import subprocess
import re
import time

'''
Records the relevant pieces of the output of dig.
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
    domain = ''
    ttl = -1
    # Can be CNAME, A, NS, or AAAA afaik
    r_type = ''
    ip = ''

    def extractField(self, line, regex, variable):
        target = ''
        try:
            target = re.search(regex, line).groupdict()[variable]
        except AttributeError:
            print('Regex did not find a match for ' + variable + '. Line = ' + line)
        except KeyError:
            print('No value could be parsed for ' + variable + '. Line = ', line)
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
        print('Real timestamp: ' + str(self.ts))

    def __init__(self, dig_output, ts):
        answer_section = False
        authority_section = False

        if not ts:
            print('WARNING: ts was not set when this object was initialized. Falling back to the time' + 
            ' at which the object was created instead of the timestamp passed in.')
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
                    pass
                    #print("Regex did not match in header section. Line = "+line)
                except KeyError:
                    pass
                    #print("No value could be parsed for status and/or opcode. Line = ", line)
                # if self.status != 'NOERROR':
                #     return
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
                    pass
                    #print("Regex did not match in answer section. Line = "+line)
                except KeyError:
                    pass
                    #print("No value could be parsed for ttl, r_type, ip, and/or domain. Line = ", line)
            if ';; Query time:' in line:
                self.rtt = int(self.extractField(line, ';;\sQuery time: (?P<rtt>\d+).*', 'rtt')) 
            if ';; WHEN:' in line:
                try:
                    # Dates are of the form 'Tue Oct 15 16:18:32 DST 2019'
                    captures = re.search(';; WHEN: (?P<day>[a-zA-Z]+ [a-zA-Z]+ [0-9]+ [0-9]+:[0-9]+:[0-9]+) [A-Z]+ (?P<year>[0-9]+)', line).groupdict()
                    day = captures['day']
                    year = captures['year']
                    self.dig_ts = datetime.strptime(day + ' ' + year, '%c')
                except AttributeError as err:
                    pass
                    #print(err)
                    #print("Regex did not match for timestamp. Line = " + line)
                except KeyError:
                    pass
                    #print("No value could be parsed for day and/or year. Line = ", line)
                
        # self.printSerialized()

'''
This class writes queries and responses to files. It uses the format:

query_header
timestamp: query
response_header
response

and repeats this format starting again with the query_header.
'''
class DnsFile:
    ts_header = '***TIMESTAMP:\n'
    query_header = '***QUERY:\n'
    response_header = '***RESPONSE:\n'
    filename = ''

    '''
    Read all dig results into an array of DnsResponses. Assumes the file was written by 
    self.writeDigResults().
    '''
    def readDigResults(self):
        try:
            f = open(self.filename, 'r')
        except IOError as err:
            print(err)
            return

        current_response = ''
        responses = []
        section = 't'
        first_ts_section = True
        query = ''
        domain = ''
        ts = datetime.now()
        for line in f:
            if line == self.response_header:
                section = 'r'
                continue
            elif line == self.query_header:
                section = 'q'
                continue
            elif line == self.ts_header:
                section = 't'
                continue

            if section == 't' and not first_ts_section:
                # We just finished a response section. Turn the response into a DnsResponse.
                resp = DnsResponse(current_response, ts)
                if resp.domain == '':
                    resp.domain = domain
                responses.append(resp)
                current_response = ''
            if section == 'q':
                try:
                    domain = re.search('(?P<domain>\S+\.[a-z]+)', line).groupdict()['domain']
                except AttributeError as err:
                    pass
                    #print("Regex did not match for domain in query section. Line = " + line)
                except KeyError:
                    pass
                    #print("No value could be parsed for domain in query section. Line = ", line)
                #print('Domain: ' + domain)
            elif section == 'r':
                if first_ts_section:
                    first_ts_section = False
                current_response += line
            elif section == 't':
                # Ex: 2019-10-31 15:03:23.925634
                ts = datetime.strptime(line.rstrip(), '%Y-%m-%d %X.%f')
                # print(ts)
        
        # Last response won't get recorded without this line because it isn't followed by a timestamp section
        resp = DnsResponse(current_response, ts)
        if resp.domain == '':
            resp.domain = domain
        responses.append(resp)
        f.close()

        # print('Parsed ' + str(len(responses)) + ' response(s).')
        # for d in responses:
            # d.printSerialized()
        return responses

    '''
    Write a query, its response, and the time the response arrived to a file.
    '''
    def writeDigResults(self, ts, query, response, filename):
        try:
            f = open(filename, 'a+')
        except IOError as err:
            print(err)
            return
        f.write(self.ts_header)
        f.write(str(ts) + '\n')
        f.write(self.query_header)
        f.write(query + '\n')
        f.write(self.response_header)
        f.write(response)
        f.write('\n')
        f.close()

    def __init__(self, filename):
        self.filename = filename


def makeDigRequest(resolver, target, recursion_desired, raw_result_filename='', write_to_stdout=False, dig_cmd='dig', loc='None'):
    recurse_flag = '+recurse'
    if resolver[0] != '@':
        resolver = '@' + resolver
    if not recursion_desired:
        recurse_flag = '+norecurse'
    try:
        resp = subprocess.check_output([dig_cmd, resolver, target, recurse_flag], universal_newlines=True)
        ts = datetime.utcnow()
    except subprocess.CalledProcessError as err:
        print('Check_output failed for dig, err = ', err)
        return
    
    if raw_result_filename != '':
        query = dig_cmd + ' ' + resolver + ' ' + target
        if not recursion_desired:
            query += ' ' + recurse_flag
        dns_file = DnsFile(raw_result_filename)
        dns_file.writeDigResults(ts, query, resp, raw_result_filename)

    if write_to_stdout:
        # CSV file. Columns:
        # hostname, ts, resolver, requested_domain, recursion_desired, response_domain, status, opcode, rtt, dig_ts, ttl, response_type, ip, pop_location
        # Example: Taliesin,2020-02-05 00:33:35.342429,8.8.8.8,a.thd.cc,False,a.thd.cc.,NOERROR,QUERY,6,2020-02-04 16:33:35,172,A,104.31.95.14,lax,
        # ts, resolver, requested_domain, and recursion_desired are request parameters. Everything else comes from the response.
        # Note that ts is in UTC and dig_ts is in the local time of the machine running the code
        r = DnsResponse(resp, ts)
        # r.printSerialized()
        try:
            hostname = subprocess.check_output(['hostname'], universal_newlines=True)
        except subprocess.CalledProcessError as err:
            print("Failed to get hostname!", err)
            return DnsResponse(resp, ts)
        row = hostname.rstrip() + ',' + str(r.ts) + ',' + resolver.replace('@','') + ',' + target + ',' + str(recursion_desired) + ',' + r.domain + ',' + r.status + ',' + r.opcode + ',' + str(r.rtt) + ',' + str(r.dig_ts) + ',' + str(r.ttl) + ',' + r.r_type + ',' + r.ip + ',' + loc + ','
        print(row)
    
    return DnsResponse(resp, ts)

# makeDigRequest('9.9.9.9', 'google.com', False, write_to_stdout=True)