import subprocess
import ipaddress
import os 

class LocationFinder:
    # Locations of Google resolvers
    google_locs = {}

    def addressInNetwork(self, address, network):
        addr = ipaddress.ip_address(address)
        net = ipaddress.ip_network(network)
        return addr in net

    def loadGooglePoPs(self):
        dir_path = os.path.dirname(os.path.realpath(__file__))
        locs = {}
        with open('{}/../data/google_locations.txt'.format(dir_path)) as all_google_pops:
            for line in all_google_pops:
                split = line.rstrip().split(' ')
                network = split[0]
                loc = split[1]
                locs[network] = loc
        self.google_locs = locs

    def getPoPLocation(self, resolver):
        try:
            if resolver == '8.8.8.8':
                resp = subprocess.check_output([self.dig_cmd, '@8.8.8.8', 'o-o.myaddr.l.google.com', '-t', 'txt', '+short'], universal_newlines=True)
                # print(resp)
                addr = resp.split('\n')[0].replace('"','')
                # print(addr)
                for network in self.google_locs.keys():
                    # print(network)
                    if self.addressInNetwork(addr, network):
                        return self.google_locs[network].upper()
                return 'UNKNOWN_LOCATION_GOOGLE_NET_NOT_FOUND'
            elif resolver == '9.9.9.9':
                if self.dig_cmd == 'kdig':
                    chaos = 'CH'
                else:
                    chaos = 'CHAOS'
                resp = subprocess.check_output([self.dig_cmd, '@9.9.9.9', 'id.server', 'txt', chaos, '+short'], universal_newlines=True)
                if 'NXDOMAIN' in resp:
                    return 'NXDOMAIN_LOCATION_UNKNOWN'
                else:
                    code = resp.split('.')[1]
                    # Update: if not a 3-letter city code, return Error
                    if len(code) == 3:
                        return code.upper()
                    else:
                        return 'PARSE_ERROR_LOCATION_UNKNOWN'
            elif resolver == '1.1.1.1':
                if self.dig_cmd == 'kdig':
                    chaos = 'CH'
                else:
                    chaos = 'CHAOS'
                resp = subprocess.check_output([self.dig_cmd, '@1.1.1.1', 'id.server', 'txt', chaos, '+short'], universal_newlines=True)
                if 'NXDOMAIN' in resp:
                    return 'NXDOMAIN_LOCATION_UNKNOWN'
                else:
                    # Update: if not a 3-letter city code, return Error
                    code = resp.rstrip().replace('"', '')
                    if len(code) == 3:
                        return code.upper()
                    else:
                        return 'PARSE_ERROR_LOCATION_UNKNOWN'
            elif resolver == '208.67.220.220':
                resp = subprocess.check_output([self.dig_cmd, '@208.67.220.220', 'debug.opendns.com', '-t', 'txt', '+short'], universal_newlines=True)
                code = resp.split('\n')[0].split(' ')[1].split('.')[1].replace('"','')
                # Update: if not a 3-letter city code, return Error
                if len(code) == 3:
                    return code.upper()
                else:
                    return 'PARSE_ERROR_LOCATION_UNKNOWN' 
            else:
                return 'UNKNOWN_RESOLVER_LOCATION_UNKNOWN'
        except subprocess.CalledProcessError:
            return 'DIG_FAILED_LOCATION_UNKNOWN'
        except AttributeError as err:
            return 'ATTRIBUTE_ERROR_LOCATION_UNKNOWN'
        except KeyError:
            return 'KEY_ERROR_LOCATION_UNKNOWN'
        except Exception as err:
            return 'UNKNOWN_ERROR_LOCATION_UNKNOWN'

    def setDigCmd(self, dig_cmd):
        self.dig_cmd = dig_cmd

    def __init__(self, dig_cmd = 'dig'):
        # Set up the list of Google locations so we can tell which Google PoP this ark node hits
        self.loadGooglePoPs()
        self.setDigCmd(dig_cmd)
