import csv
from datetime import datetime
from datetime import timedelta
import json


def numFilledTTLs(x_ints, max_ttl):
    # Any number of cache hits per TTL get counted as one cache hit. 
    # TTL "epochs" start at unix time 0.
    ttl_epochs = []
    for x in x_ints:
        ttl_epochs.append(int(int(x.timestamp()) / max_ttl) * max_ttl)
    return len(set(ttl_epochs))

def coalesce(x_ints):
    x_ints = sorted(set(x_ints))
    coalesced = []
    one = timedelta(seconds=1)
    two = timedelta(seconds=2)

    # if x_ints[0] == x_ints[1]-one and x_ints[1] == x_ints[2]-one:
    #     coalesced.append(x_ints[1])
    # elif x_ints[0] < x_ints[1]-one:
    #     coalesced.append(x_ints[0])
    

    for i in range(2, (len(x_ints)-2)):
        lolo = x_ints[i-2]
        lo = x_ints[i-1]
        mid = x_ints[i]
        hi = x_ints[i+1]
        hihi = x_ints[i+2]

        # If I'm a group of one, count me.
        if lo < mid-one and hi > mid+one:
            # print('group of 1')
            coalesced.append(mid)
        # If I'm first in a group of two, don't count me.
        elif lo < mid-one and mid+one == hi and mid+two < hihi:
            # print('first in two')
            continue
        # If I'm second in a group of two, append.
        elif lolo < mid-two and lo == mid-one and hi > mid+one:
            # print('second in group of two')
            coalesced.append(mid)
        # If I'm first in a group of more than two, don't count me.
        elif lo < mid-one and hi == mid+one and hihi == mid + two:
            # print('first in 3 or more')
            continue
        # If I'm part of a group that's at least 3 big, but not the first or last of the group, append.
        elif lo == mid-one and hi == mid + one:
            # print('middle in group of 3+')
            coalesced.append(mid)
        # If I'm the last in a group that's at least three big, don't count me.
        elif hi > mid+one and lo == mid - one:
            # print('last in three')
            continue
        # Otherwise, I'm not part of a group, count me.
        else:
            # print('group of 1 end case')
            coalesced.append(mid)
    # todo: deal with last two timestamps
    return coalesced

def analyzeArk(ark_data, resolver):
    x_ints = {}
    tss = {}
    ttls = {}
    ripe_tss = {}
    ripe_ttls = {}

    for (ts, ttl, pop) in zip(ark_data['dig_ts'], ark_data['ttl'], ark_data['pop_location']):
        # if ts < datetime(2020,4,29,4,0):
        #     continue
        if pop not in x_ints:
            x_ints[pop] = [ts + timedelta(seconds=ttl)]
            tss[pop] = [ts]
            ttls[pop] = [ttl]
        else:
            x_ints[pop].append(ts + timedelta(seconds=ttl))
            tss[pop].append(ts)
            ttls[pop].append(ttl)

    if resolver == '8.8.8.8':
        for (ts, ttl, pop) in zip(ark_data['dig_ts'], ark_data['ttl'], ark_data['pop_location']):
            if pop not in ripe_tss:
                ripe_tss[pop] = [ts]
                ripe_ttls[pop] = [ttl]
            else:
                ripe_tss[pop].append(ts)
                ripe_ttls[pop].append(ttl)
    
    for pop in sorted(x_ints.keys()):
        if resolver == '9.9.9.9':
            # So far, best strategy here is to count the x_ints
            return (pop, len(set(x_ints[pop])))
        elif resolver == 'OpenDNS':
            # "Randall method" (remove last from group)
            coalesced_x_ints = coalesce(x_ints[pop])
            return (pop, len(coalesced_x_ints))
        elif resolver == '1.1.1.1':
            # We can only see one cache hit per TTL
            return (pop, numFilledTTLs(x_ints[pop], 10800))
        else:
            raise Exception("8.8.8.8 Not Implemented")
    
    ttl_lines_by_pop = {}
    for pop in sorted(tss.keys()):
        if resolver == '8.8.8.8' and 'UNKNOWN' not in pop:
            ttl_lines = analyzeQuad8(tss[pop], ttls[pop], pop, ripe_tss[pop], ripe_ttls[pop])
            print(pop, len(coalesce(ttl_lines)))
            # print(pop, ttl_lines)
            ttl_lines_by_pop[pop] = ttl_lines
    return ttl_lines_by_pop

# Takes data from a single Quad8 PoP
def analyzeQuad8(ark_tss, ark_ttls, pop, ripe_tss, ripe_ttls):
    # Try discarding all TTL lines that begin at the same time as a measurement arriving.
    # First, make a dictionary of {x_int: [list of points on that line as (ts, ttl)]}
    valid_ttl_line = {}
    line_starts = []
    ts_to_line_start = {}

    known_correct_tss = []
    ripe_ts_without_max = []
    for ts, ttl in zip(ripe_tss, ripe_ttls):
        if ttl == 10799:
            known_correct_tss.append(ts)
        else:
            ripe_ts_without_max.append(ts)

    for ts, ttl in zip(ark_tss, ark_ttls):
        line_start = ts - timedelta(seconds=(10799 - ttl))
        ts_to_line_start[ts] = line_start
        line_starts.append(line_start)

    # Remove any line_starts that only have one data point. Then remove duplicates of the remainder.
    # line_starts.sort()
    # new_line_starts = []
    # i = 0
    # while i < len(line_starts):
    #     current_line_start = line_starts[i]
    #     num_copies = 0
    #     while i+1 < len(line_starts) and line_starts[i+1] == current_line_start:
    #         i += 1
    #         num_copies += 1
    #     if num_copies > 0:
    #         new_line_starts.append(current_line_start)
    #     i += 1
    # line_starts = new_line_starts

    # Remove duplicates and sort
    line_starts = sorted(set(line_starts))

    for l in line_starts:
        valid_ttl_line[l] = True

    # Originally, I tried to eliminate TTL lines generated by the ripe probes' cache hits:
    # for ts in sorted(ripe_ts_without_max):
    #     for line_start in line_starts:
    #         diff = timedelta(seconds=0)
    #         if ts > line_start:
    #             diff = ts - line_start
    #         else:
    #             diff = line_start - ts
    #         if diff < timedelta(seconds=1):
    #             valid_ttl_line[line_start] = False

    # But now we think it's actually better to count those as real cache lines, so we don't remove them.

    # Now eliminate TTL lines generated by ark nodes' cache hits
    for ts in sorted(ark_tss):
        for line_start in line_starts:
            diff = timedelta(seconds=0)
            if ts > line_start:
                diff = ts - line_start
            else:
                diff = line_start - ts
            if diff <= timedelta(seconds=0):
                valid_ttl_line[line_start] = False
    
    # Count all valid TTL lines
    valid_lines = []
    for line_start in valid_ttl_line:
        if valid_ttl_line[line_start]:
            valid_lines.append(line_start)

    return set(valid_lines)
