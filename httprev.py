from bs4 import BeautifulSoup, Comment
import sys
import json
import re
import urllib.request
import socket
import mmh3
import base64
from urllib.parse import urlparse

import ssl
from datetime import datetime

from lxml import etree
import argparse

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import ExtensionOID


TXT_MAX_LEN = 500


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def load_single_url(url):
    return [url]


def load_urls_from_file(file_path):
    try:
        with open(file_path, "r") as file:
            urls = [line.strip() for line in file.readlines() if line.strip()]
            return urls
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return []


def get_hostname(host_element):
    hostname_str = None
    hostnames = host_element.find("hostnames")
    if hostnames is not None:
        for hostname in hostnames.findall("hostname"):
            hostname_src = hostname.get("type")
            hostname_val = hostname.get("name")
            if hostname_src == "user":
                hostname_str = hostname_val
            elif hostname_str is None and hostname_src == "PTR":
                hostname_str = hostname_val
    if hostname_str is None:
        address = host_element.find("address")
        if address is not None:
            hostname_str = address.get("addr")
    return hostname_str


def load_urls_from_xml(xml_file):
    try:
        # Parse the XML
        tree = etree.parse(xml_file)
        root = tree.getroot() #<nmaprun>
        urls = []

        for host in root.findall("host"):
            hostname = get_hostname(host)
            ports = host.find("ports")
            if ports is None:
                continue
            for port in ports.findall("port"):
                if port.get("protocol") != "tcp":
                    continue
                state = port.find("state")
                if state is not None:
                    port_state = state.get("state")
                    if port_state != "open":
                        continue
                    service = port.find("service")
                    if service is None:
                        continue
                    service_name = service.get("name")
                    if service_name == "http" or service_name == "https":
                        scheme = service_name
                        if service_name == "http":
                            tunnel = service.get("tunnel")
                            if tunnel == "ssl":
                                scheme = "https"
                        url = f'{scheme}://{hostname}'
                        portnum = port.get("portid")
                        if portnum not in ["80","443"]:
                            url += f':{portnum}'
                        urls.append(url)
        return urls
    except Exception as e:
        print(f"Error reading XML file {xml_file}: {e}")
        return []



def parse_cert(der_cert):
    cert = x509.load_der_x509_certificate(der_cert, default_backend())
    ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    # Get the dNSName entries from the SAN extension
    sans = ext.value.get_values_for_type(x509.DNSName)
    return {
        "subject":str(cert.subject.rfc4514_string()),
        "issuer":str(cert.issuer.rfc4514_string()),
        "san":sans,
        "from":str(cert.not_valid_before_utc),
        "until":str(cert.not_valid_after_utc),
        "serial":str(cert.serial_number)
    }


def get_https_certificate_info(hostname, portstr="443"):
    try:
        context = ssl._create_unverified_context()
        # Connect to the host and retrieve the certificate
        with socket.create_connection((hostname, int(portstr))) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert(True)
                '''
                Need to get the binary DER format, because according to the official doco for getpeercert():
                If the binary_form parameter is False, and a certificate was received from the peer, this method returns a dict instance. If the certificate was not validated, the dict is empty.
                '''
        return parse_cert(cert)
    except Exception as e:
        print(f'error getting cert: {e}')
        return None

def extract_a_href(s):
    links = set()
    for a in s.find_all('a'):
        link = a.get('href')
        if link is not None and not link.startswith('#') and link != "" and link != "/":
            links.add(link)
    return sorted(links)


def extract_link_href(s):
    links = set()
    for a in s.find_all('link'):
        link = a.get('href')
        if link is not None and not link.startswith('#') and link != "" and link != "/":
            links.add(link)
    return sorted(links)


def extract_script_src(s):
    links = set()
    for a in s.find_all('script'):
        link = a.get('src')
        if link is not None and not link.startswith('#') and link != "" and link != "/":
            links.add(link)
    return sorted(links)


def extract_meta(s):
    metas = []
    for a in s.find_all('meta'):
        mname = a.get('name')
        if mname is not None:
            m = {'name':mname}
            mcontent = a.get('content')
            if mcontent is not None:
                m['content'] = mcontent
            metas.append(m)
    return metas


def extract_form(s):
    forms = []
    for a in s.find_all('form'):
        f = {}
        faction = a.get('action')
        if faction is not None:
            f['action'] = faction
            inputs = []
            for i in a.find_all('input'):
                iname = i.get('name')
                if iname is not None:
                    inputs.append(iname)
            if len(inputs) > 0:
                f['inputs'] = inputs
        if len(f.keys()) > 0:
            forms.append(f)
    return forms


def extract_comment(s):
    c_list = []
    comments = s.find_all(string=lambda text: isinstance(text, Comment))
    for comment in comments:
        c = comment.strip()
        if c != "":
            c_list.append(c)
    return c_list


def extract_text(s):
    body = s.find('body')
    txtraw = ' '.join(body.strings)
    txt = re.sub(r"\s+", " ", txtraw)
    if txt is not None and txt != "":
        txt = txt if len(txt) < TXT_MAX_LEN else txt[:TXT_MAX_LEN]
    return txt


def build_request(url):
    return urllib.request.Request(url=url, headers={'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/133.0.0.0 Safari/537.36'}, method='GET')


def fetch_favicon_mmh3_hash(url):
        favicon_url = f"{url}/favicon.ico"
        try:
            with urllib.request.urlopen(build_request(favicon_url), timeout=10) as response:
                favicon_data = response.read()
                hash_value = mmh3.hash(base64.b64encode(favicon_data))
                return hash_value
        except Exception as e:
            print(f"{favicon_url} - Error fetching favicon: {e}")
            return None



def extract_stuff_from_html(content):
    try:
        soup = BeautifulSoup(content, 'html.parser')

        stuff = {}

        if len(soup.find_all('html')) < 1:
            stuff['raw'] = content
            return stuff

        stuff['title'] = soup.title.string if soup.title else ""
        stuff['a_hrefs'] = extract_a_href(soup)
        stuff['link_hrefs'] = extract_link_href(soup)
        stuff['script_src'] = extract_script_src(soup)
        stuff['metas'] = extract_meta(soup)
        stuff['forms'] = extract_form(soup)
        stuff['comments'] = extract_comment(soup)
        if TXT_MAX_LEN > 0:
            t = extract_text(soup)
            if t is not None:
                stuff['text'] = t

        return stuff

    except Exception as e:
        print(str(e))
        return stuff



def fetch_and_analyse_url(url):
    result = {}
    try:
        # important: dont use a context, as it prevents the NoRedirect opener from working

        response = urllib.request.urlopen(build_request(url), timeout=10)
        headers = {}
        for hdr,val in response.getheaders():
            headers[hdr] = val

        content = response.read().decode('utf-8')
        result = extract_stuff_from_html(content)
        result['headers'] = headers
        result['statuscode'] = response.status
    except urllib.error.HTTPError as e:
        result['statuscode'] = e.code
        print(f"{url} - HTTP Error {e.code}: {e.reason}")
        try:
            content = e.read().decode('utf-8')
            result = extract_stuff_from_html(content)
        except Exception:
            print(f"{url} - Could not read error page response body.")
            pass
        result['statuscode'] = e.code
        headers = {}
        for header, value in e.headers.items():
            headers[header] = value
        result['headers'] = headers

    except Exception as e:
        print(f'{url} - Fatal exception, {e}')
        return result

    parsed_url = urlparse(url)
    result['url_scheme'] = parsed_url.scheme
    result['url_host'] = parsed_url.hostname
    result['url_port'] = str(parsed_url.port) if parsed_url.port else ('80' if parsed_url.scheme == 'http' else '443')
    favhash = fetch_favicon_mmh3_hash(f'{result["url_scheme"]}://{result["url_host"]}:{result["url_port"]}')
    if favhash is not None:
        result['favicon_mmh3'] = favhash

    try:
        ip_address = socket.gethostbyname(parsed_url.hostname)
        result['ipv4'] = ip_address
    except socket.gaierror:
        pass

    if result['url_scheme'] == 'https':
        try:
            cert = get_https_certificate_info(result['url_host'], result['url_port'])
            if cert is not None:
                result['tlscert'] = cert
        except:
            pass
    return result


def main():
    global TXT_MAX_LEN

    ssl._create_default_https_context = ssl._create_unverified_context

    parser = argparse.ArgumentParser(description="Scan URLs and obtain basic info.")
    parser.add_argument("-u", "--url", help="A single URL to process, eg. https://foo.bar.com:8443")
    parser.add_argument("-fu", "--file-urls", help="File containing a list of URLs (one per line)")
    parser.add_argument("-fn", "--file-nmapxml", help="Nmap XML file containing http(s) services, output from nmap -sV -oX")
    parser.add_argument("-od", "--output-dir", help="Path to save output files, eg. /path/to/outputfiles")
    parser.add_argument("-r", "--redirect", help="follow redirects, eg. --redirect=true OR -r 1", action='store_true')
    parser.add_argument("-tl", "--textlen", help=f"max length of text to extract from html (default {TXT_MAX_LEN} chars), eg. -tl 50")

    args = parser.parse_args()

    if not args.redirect:
        opener = urllib.request.build_opener(NoRedirect)
        urllib.request.install_opener(opener)

    if args.textlen:
        try:
            TXT_MAX_LEN = int(args.textlen)
            if TXT_MAX_LEN < 0:
                TXT_MAX_LEN = 0
        except:
            pass

    urls_to_analyse = []
    if args.url:
        urls_to_analyse = load_single_url(args.url)
    elif args.file_urls:
        urls_to_analyse = load_urls_from_file(args.file_urls)
    elif args.file_nmapxml:
        urls_to_analyse = load_urls_from_xml(args.file_nmapxml)
    else:
        print("No valid option provided. Use -h for help.")
        sys.exit(1)

    outputpath = args.output_dir
    if outputpath is None or outputpath == '':
        outputpath = '.'
    outputpath = outputpath.rstrip('/')

    for url in urls_to_analyse:
        print(f'fetching: {url}')
        s = fetch_and_analyse_url(url)
        if s:
            tmpname1 = re.sub(r"[^0-9a-zA-Z\._-]", "_", url)
            outfilename = re.sub(r"[_]+", "_", tmpname1)
            with open(f"{outputpath}/{outfilename}.json", "w") as outf:
                outf.write(json.dumps(s))


if __name__ == "__main__":
    main()
