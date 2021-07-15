# This is the initial commit of project_x
import socket
import urllib.request
import urllib.parse
import re
import requests
from urllib.request import urlparse,urljoin
from bs4 import BeautifulSoup
import colorama
import queue
import threading
import urllib3
import urllib.parse as U
import urllib.error as E
import streamlit as st

st.title('Project X')
st.sidebar.title('Settings')

#st.markdown('<style>body{background-color: black;}</style>',unsafe_allow_html=True)
check_box_port=st.sidebar.checkbox(label='Port Scanner')
check_box_subs=st.sidebar.checkbox(label='Subdomain Scanner')
check_box_URL=st.sidebar.checkbox(label='URL Extractor')
check_box_brute=st.sidebar.checkbox(label='Brute Force')
if(check_box_port):
    st.title('Port Scanner')

    name = st.text_input("Enter URL")
    # print(type(name))
    remote_server = str(name)
    print(remote_server)

    if (st.button("Scan Ports")):
        remoteServerIP = socket.gethostbyname(remote_server)
        try:
            for port in range(1, 1000):
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                result = sock.connect_ex((remoteServerIP, port))
                if (result == 0):
                    print('{} is open'.format(port))
                    st.text("IP is {} and {} is open".format(remoteServerIP, port))

                # else:
                #   print('{} is Closed'.format(port))
                #  st.text('IP is {} and {} is closed'.format(remoteServerIP,port))

                sock.close()


        except KeyboardInterrupt:
            st.text("You pressed Ctrl+C")
            # sys.exit()

        except socket.gaierror:
            st.text('Hostname could not be resolved. Exiting')
            # sys.exit()

        except socket.error:
            st.text("Couldn't connect to server")
            # sys.exit()

if(check_box_subs):
    target = st.text_input('Enter a URL')
    if (st.button("Scan Subdomains")):
        domains = set()
        # print((i, arg))
        with urllib.request.urlopen('https://crt.sh/?q=' + urllib.parse.quote('%.' + target)) as f:
            code = f.read().decode('utf-8')
            # print(code)
            for cert, domain in re.findall(
                    '<tr>(?:\s|\S)*?href="\?id=([0-9]+?)"(?:\s|\S)*?<td>([*_a-zA-Z0-9.-]+?\.' + re.escape(
                            target) + ')</td>(?:\s|\S)*?</tr>', code, re.IGNORECASE):
                # print((cert,domain))
                domain = domain.split('@')[-1]
                # print(domain)
                if not domain in domains:
                    domains.add(domain)
                    #print(domain)

                    st.text('{}'.format(domain))

if(check_box_URL):
    st.title('URL Extractor')
    url = st.text_input("Enter an URL")
    if(st.button("Extract URL")):

        colorama.init()

        GREEN = colorama.Fore.GREEN
        GRAY = colorama.Fore.LIGHTBLACK_EX
        RESET = colorama.Fore.RESET

        # initialize the set of links (unique links)
        internal_urls = set()
        external_urls = set()

        total_urls_visited = 0


        def is_valid(url):
            """
            Checks whether `url` is a valid URL.
            """
            parsed = urlparse(url)
            # print(parsed)
            return bool(parsed.netloc) and bool(parsed.scheme)


        def get_all_website_links(url):
            """
            Returns all URLs that is found on `url` in which it belongs to the same website
            """
            # all URLs of `url`
            urls = set()
            # domain name of the URL without the protocol
            domain_name = urlparse(url).netloc
            soup = BeautifulSoup(requests.get(url).content, "html.parser")
            for a_tag in soup.findAll("a"):
                href = a_tag.attrs.get("href")
                if href == "" or href is None:
                    # href empty tag
                    continue
                # join the URL if it's relative (not absolute link)
                href = urljoin(url, href)
                parsed_href = urlparse(href)
                # remove URL GET parameters, URL fragments, etc.
                href = parsed_href.scheme + "://" + parsed_href.netloc + parsed_href.path
                if not is_valid(href):
                    # not a valid URL
                    continue
                if href in internal_urls:
                    # already in the set
                    continue
                if domain_name not in href:
                    # external link
                    if href not in external_urls:
                        st.text(f"{GRAY}[!] External link: {href}{RESET}")
                        external_urls.add(href)
                    continue
                st.text(f"{GREEN}[*] Internal link: {href}{RESET}")
                urls.add(href)
                internal_urls.add(href)
            return urls


        def crawl(url, max_urls=50):
            """
            Crawls a web page and extracts all links.
            You'll find all links in `external_urls` and `internal_urls` global set variables.
            params:
                max_urls (int): number of max urls to crawl, default is 30.
            """
            global total_urls_visited
            total_urls_visited += 1
            links = get_all_website_links(url)
            for link in links:
                if total_urls_visited > max_urls:
                    break
                crawl(link, max_urls=max_urls)


        crawl(str(url))

if(check_box_brute):
    st.title('Brute Force Attack')
    needed_url = st.text_input("Enter url")

    if (st.button("Start Attack")):
        # threads = 5
        filepath = r'/home/xcriminal/PycharmProjects/combined.py/dicc.txt'
        ext = [".php"]
        user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36"
        # is_resume = False
        words = queue.Queue()

        with open(filepath) as fp:
            raw = fp.readline()
            while raw:
                word = raw.strip()
                words.put(word)
                raw = fp.readline()

        fp.close()

        while not words.empty():
            try_this = words.get()
            try_list = []

            if "." not in try_this:
                try_list.append("/{}/".format(try_this))
            else:
                try_list.append("/{}".format(try_this))

            if ext:
                for extension in ext:
                    try_list.append("/{}{}".format(try_this, extension))

            for brute in try_list:
                url = "{}{}".format(str(needed_url), U.quote(brute))

                try:
                    http = urllib3.PoolManager()
                    head = {}
                    head["User-Agent"] = user_agent
                    response = http.request("GET", headers=head, url=url)

                    if len(response.data):
                        if response.status != 404:
                            st.text("[{}] ==> {}".format(response.status, url))

                except (E.URLError, E.HTTPError):
                    if hasattr(E.HTTPError, 'code') and E.HTTPError.code != 404:
                        st.text("!!!!! [{}] ==> {}".format(E.HTTPError.code, url))
                    pass













