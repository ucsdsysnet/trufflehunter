# Trufflehunter
Trufflehunter is a tool that uses DNS cache snooping on public DNS resolvers to measure the prevalence of rare applications and domains on the Internet.

## Usage
To probe a domain with default settings, run the following command:
```bash
python3 trufflehunter.py --domain=github.com
```

Arguments supported:
```
-n: number of dig requests per domain per PoP. Default: 10
-v: verbose mode. Default: False.
-r: resolvers, you can only specify a set of IPs. Use -h to see the all the IPs available. Default: 1.1.1.1 9.9.9.9
```

Probing with customized args:
```
python3 trufflehunter.py --domain=github.com -v -n 5 -r 1.1.1.1 9.9.9.9 8.8.8.8
```

# Cite Our Paper
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
