# Trufflehunter
[![Python 3.5](https://img.shields.io/badge/python-3.5-blue.svg)](https://www.python.org/downloads/release/python-360/)
[![Python 3.6](https://img.shields.io/badge/python-3.6-blue.svg)](https://www.python.org/downloads/release/python-360/)
[![Python 3.7](https://img.shields.io/badge/python-3.7-blue.svg)](https://www.python.org/downloads/release/python-360/)
[![Python 3.8](https://img.shields.io/badge/python-3.8-blue.svg)](https://www.python.org/downloads/release/python-360/)

Trufflehunter is a tool that uses DNS cache snooping on public DNS resolvers to measure the prevalence of rare applications and domains on the Internet.

## Installation
```
git clone https://github.com/ucsdsysnet/trufflehunter.git
cd trufflehunter
```

## Dependencies
We support Python 3 (3.5+). Additionally, you need to have `dig` (a command-line tool for querying the Domain Name System) installed in order to run our tool properly. We tested our tool with `dig` version `9.10.6` and `9.10.3` on Mac and Ubuntu respectively. 


## Usage
To probe a domain with default settings, run the following command:
```bash
python3 trufflehunter.py --domain=github.com
```

Arguments supported:
```
-n: number of dig requests per domain per PoP. Default: 10
-v: verbose mode. Default: False.
-r: resolvers, you can only specify a set of IPs. Use -h to see all the IPs available. Default: 1.1.1.1 9.9.9.9
```

Probing with customized args:
```
python3 trufflehunter.py --domain=github.com -v -n 5 -r 1.1.1.1 9.9.9.9 8.8.8.8
```

## Link to the Original Paper
Here's the [link](https://cseweb.ucsd.edu/~schulman/docs/imc20-trufflehunter.pdf) to our paper.

## Cite Our Paper
```
@inproceedings{10.1145/3419394.3423640,
author = {Randall, Audrey and Liu, Enze and Akiwate, Gautam and Padmanabhan, Ramakrishna and Voelker, Geoffrey M. and Savage, Stefan and Schulman, Aaron},
title = {Trufflehunter: Cache Snooping Rare Domains at Large Public DNS Resolvers},
year = {2020},
isbn = {9781450381383},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
url = {https://doi.org/10.1145/3419394.3423640},
doi = {10.1145/3419394.3423640},
abstract = {This paper presents and evaluates Trufflehunter, a DNS cache snooping tool for estimating the prevalence of rare and sensitive Internet applications. Unlike previous efforts that have focused on small, misconfigured open DNS resolvers, Trufflehunter models the complex behavior of large multi-layer distributed caching infrastructures (e.g., such as Google Public DNS). In particular, using controlled experiments, we have inferred the caching strategies of the four most popular public DNS resolvers (Google Public DNS, Cloudflare Quad1, OpenDNS and Quad9). The large footprint of such resolvers presents an opportunity to observe rare domain usage, while preserving the privacy of the users accessing them. Using a controlled testbed, we evaluate how accurately Trufflehunter can estimate domain name usage across the U.S. Applying this technique in the wild, we provide a lower-bound estimate of the popularity of several rare and sensitive applications (most notably smartphone stalkerware) which are otherwise challenging to survey.},
booktitle = {Proceedings of the ACM Internet Measurement Conference},
pages = {50–64},
numpages = {15},
location = {Virtual Event, USA},
series = {IMC '20}
}
```


## Bugs and Issues
This software is used and maintained for a research project and likely will have many bugs and issues. If you want to report any bugs or issues, please do it through the [Github Issue Page](https://github.com/ucsdsysnet/trufflehunter/issues).

## Known Issues

### ISP Interception of DNS Queries

We have run into several cases where public DNS resolvers are inaccessible on certain networks, because the ISP serving that network is transparently hijacking some or all DNS queries. If you receive a warning that location queries for some or all resolvers are returning responses in an incorrect format, your ISP may be hijacking your queries. You can confirm in one of two ways that we know of:

1. We've seen Spectrum replace some (but not all) NXDOMAIN DNS responses with a search page entitled "Level3." To confirm, type a few nonexistent domains with TLDs into your address bar. Note that we don't see this injected page every time we make a request for a nonexistent domain.
2. In certain locations, Comcast does not appear to replace NXDOMAIN responses, but does resolve all queries itself. We confirmed this by querying the public resolvers for the domain that we own. When we checked our authoritative nameserver's logs, they revealed that none of the queries had come from the public resolvers: all came from Comcast's address space. However, the responses we saw with Dig claimed to be from the public resolver we had queried. You can check this case by asking dig to query a nonexistent nameserver. If your ISP is transparently proxying your queries, you will get a resolved response (NOERROR). If not, you should get an error saying the resolver can't be found. Example command:
> dig @1.2.3.4 example.com

Please feel free to contact us (report as bug or email us) if this is happening to you. We'd like to see how widespread of a problem it is.
