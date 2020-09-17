import subprocess
import ipaddress

class LocationFinder:
    # Locations of Google resolvers
    google_locs = {}

    # Dig or kdig?
    dig_cmd = 'dig'

    def addressInNetwork(self, address, network):
        addr = ipaddress.ip_address(address)
        net = ipaddress.ip_network(network)
        return addr in net

    def loadGooglePoPs(self):
        locs = {}
        with open('google_locations.txt') as all_google_pops:
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
                        return self.google_locs[network]
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
                    return resp.split('.')[1]
            elif resolver == '1.1.1.1':
                if self.dig_cmd == 'kdig':
                    chaos = 'CH'
                else:
                    chaos = 'CHAOS'
                resp = subprocess.check_output([self.dig_cmd, '@1.1.1.1', 'id.server', 'txt', chaos, '+short'], universal_newlines=True)
                if 'NXDOMAIN' in resp:
                    return 'NXDOMAIN_LOCATION_UNKNOWN'
                else:
                    return resp.rstrip().replace('"', '')
            elif resolver == '208.67.220.220':
                resp = subprocess.check_output([self.dig_cmd, '@208.67.220.220', 'debug.opendns.com', '-t', 'txt', '+short'], universal_newlines=True)
                return resp.split('\n')[0].split(' ')[1].split('.')[1].replace('"','')
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

    def __init__(self, dig_cmd):
        # Set up the list of Google locations so we can tell which Google PoP this ark node hits
        self.loadGooglePoPs()
        self.setDigCmd(dig_cmd)


class RipeAtlasLocationFinder(LocationFinder):
    def getPoPLocation(self, resolver, dig_loc, status):
        try:
            if resolver == '8.8.8.8' or resolver == '8.8.4.4':
                addr = dig_loc.replace('"','')
                for network in self.google_locs.keys():
                    if self.addressInNetwork(dig_loc, network):
                        return self.google_locs[network]
                return 'UNKNOWN_LOCATION_GOOGLE_NET_NOT_FOUND'
            elif resolver == '9.9.9.9' or resolver == '149.112.112.112':
                if 'NXDOMAIN' in status:
                    return 'NXDOMAIN_LOCATION_UNKNOWN'
                else:
                    return dig_loc.split('.')[1]
            elif resolver == '1.1.1.1' or resolver == '1.0.0.1':
                if 'NXDOMAIN' in status:
                    return 'NXDOMAIN_LOCATION_UNKNOWN'
                else:
                    return dig_loc.rstrip().replace('"', '')
            elif resolver == '208.67.220.220':
                return dig_loc.split('\n')[0].split(' ')[1].split('.')[1].replace('"','')
            else:
                return 'UNKNOWN_RESOLVER_LOCATION_UNKNOWN'
        except AttributeError as err:
            return 'ATTRIBUTE_ERROR_LOCATION_UNKNOWN'
        except KeyError:
            return 'KEY_ERROR_LOCATION_UNKNOWN'
        except Exception as err:
            return 'UNKNOWN_ERROR_LOCATION_UNKNOWN'
    
    def loadGooglePoPs(self, filename):
        locs = {}
        with open(filename) as all_google_pops:
            for line in all_google_pops:
                split = line.rstrip().split(' ')
                network = split[0]
                loc = split[1]
                locs[network] = loc
        self.google_locs = locs

    def __init__(self, google_pops):
        self.loadGooglePoPs(google_pops)

# l = LocationFinder()
# print(l.detectDigCmd())