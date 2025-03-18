# HTTP(S) Web Service Recon Tool

Httprev is a tool designed for security researchers and bug bounty hunters to assist in mapping potential attack surfaces in network services that use HTTP.

The tool takes a URL or list of URLs as input, connects to the URLs, gathering basic information such as:

- Response status code
- Title
- HTTP Response headers
- Linked resources eg. script source, link/anchor href URLs
- text content snippets
- HTML Form actions and input parameter names
- Certificate info for TLS/SSL

The output is a JSON file containing the above information. The JSON can be parsed and fed into other tools.

## Install

### Requirements

- Python3.7+
- (Recommended) Python virtual environment eg. virtualenv or venv
- pip
- Packages:
```
beautifulsoup4 lxml mmh3 cryptography
```

### Installation steps

- Clone this repo
```
cd httprev
python3 -m virtualenv .
source bin/activate
pip install -r requirements.txt
```

## Usage

### Scan a single URL

```
python3 httprev.py -u https://test.nonexistent.com:8443 -od /path/to/output/folder
```

### Scan a file with a list of URLs

The input file should contain one URL per line...

```
https://test.nonexistent.com:8443
https://test.nonexistent.com
http://test.nonexistent.com
http://test2.nonexistent.com:8080
```

Use the file as input to httprev:

```
python3 httprev.py -fu /path/to/urlfile.txt -od /path/to/output/folder
```

### Scan an Nmap XML file containing HTTP service results

The input file should be Nmap XML format, generated from a service fingerprinting scan, eg.

```
nmap -sV --top-ports 200 -oX /path/to/nmap.xml 123.45.67.0/27
```

Use the file as input to httprev:

```
python3 httprev.py -fn /path/to/nmap.xml -od /path/to/output/folder
```

### Follow Redirects

By default any 3xx HTTP redirects are ignored and httprev will record the raw 3xx response and headers. If you want to follow redirects use the `-r` option:

```
python3 httprev.py -u https://test.nonexistent.com:8443 -od /path/to/output/folder -r
```


### Capture HTML response text

By default httprev will record the first 500 characters of text in a HTML response, stripped of tags, scripts, CSS etc. If you want to change the number of characters captured (or disable capture) use the `-tl` option:

```
python3 httprev.py -u https://test.nonexistent.com:8443 -od /path/to/output/folder -tl 50
```

**Setting `-tl 0` will disable text capture**


