# trufflehunter
Trufflehunter is a tool that uses DNS cache snooping on public DNS resolvers to measure the prevalence of rare applications and domains on the Internet.

## Usage
To probe a domain with default settings, run the following command:
```bash
python3 demo.py --domain=github.com
```

Arguments supported:
```
-n: number of dig requests per domain per PoP. Default: 10
-v: verbose mode. Default: False.
-r: resolvers, you can only specify a set of IPs. Use -h to see the all the IPs available. Default: 1.1.1.1 9.9.9.9
```

Probing with customized args:
```
python3 demo.py --domain=github.com -v -n 5 -r 1.1.1.1 9.9.9.9 8.8.8.8
```


