
from lib.functions import *
import csv
import os, tempfile, numpy as np, pandas as pd
from urllib.parse import urlparse

# 23 features
feature_names = [
    "url_length",
    "url_num_special_chars",
    "url_ratio_digit_letter",
    "domain_level",
    "domain_contains_ip",
    "domain_length",
    "domain_num_digits",
    "domain_num_nonletter",
    "domain_num_hyphen",
    "domain_num_at",
    "domain_top",
    "sub_num_dots",
    "sub_num_subdomains",
    "path_num_slash",
    "path_num_subdirectories",
    "path_presence",                   
    "path_presence_upper_directories",
    "path_presence_single_directories",
    "path_num_special_chars",
    "path_num_zeros",
    "path_ratio_upper_lower",
    "param_query_length",
    "query_num_params"
]


def extract_url_features(url_series: pd.Series) -> np.ndarray:
    with tempfile.TemporaryDirectory() as td:
        urls_txt = os.path.join(td, "urls.txt")
        out_csv  = os.path.join(td, "features.csv")
        pd.Series(url_series.astype(str)).to_csv(urls_txt, index=False, header=False)

        main(urls_txt, out_csv)

        df = pd.read_csv(out_csv).replace("?", np.nan).fillna(0)
        if "phishing" in df.columns:
            df = df.drop(columns=["phishing"])
        df = df.reindex(columns=feature_names)
        df = df.apply(pd.to_numeric, errors="coerce").fillna(0).astype(np.float32)

        return df.to_numpy(dtype=np.float32)


def attributes():
    feats = feature_names[:]
    return feats + ["phishing"]


def main(urls, dataset):
    with open(dataset, "w") as output:
        writer = csv.writer(output)
        writer.writerow(attributes())
        for url in read_file(urls):
            d = start_url(url)
            u = d['url']
            h = d['host'] or ""
            p = d['path'] or ""
            q = d['query'] or ""

            url_length        = len(u)
            url_num_special_chars = sum(not c.isalnum() for c in u)
            url_ratio_digit_letter = (sum(c.isdigit() for c in u) / (sum(c.isalpha() for c in u)+1e-6))

            # domain
            domain_contains_ip = 1 if valid_ip(h) else 0
            domain_length      = len(h)
            domain_num_digits  = sum(c.isdigit() for c in h)
            domain_num_nonletter = sum(not c.isalnum() for c in h)
            domain_num_hyphen  = h.count("-")
            domain_num_at      = h.count("@")
            domain_top         = 1 if h in ALEXA_TOP100 else 0  
            domain_level    = tld_flag_from_url(url)

            # subdomain
            parts = h.split(".")
            sub_num_dots       = h.count(".")
            sub_num_subdomains = max(len(parts)-2, 0)

            # path
            path_num_slash     = p.count("/")
            path_num_subdirectories = len([seg for seg in p.split("/") if seg])
            path_presence      = 1 if "%20" in p else 0
            path_presence_upper_directories = 1 if any(seg.isupper() for seg in p.split("/") if seg) else 0
            path_presence_single_directories = 1 if any(len(seg)==1 for seg in p.split("/") if seg) else 0
            path_num_special_chars = sum(not c.isalnum() for c in p)
            path_num_zeros     = p.count("0")
            num_upper = sum(c.isupper() for c in p)
            #print("num_upper=",num_upper)
            num_lower = sum(c.islower() for c in p)
            #print("num_lower=",num_lower)
            if num_lower > 0:
                path_ratio_upper_lower = num_upper / num_lower
            elif num_upper > 0:
                path_ratio_upper_lower = 1
            else:
                path_ratio_upper_lower = 0
            #path_ratio_upper_lower = (sum(c.isupper() for c in p) / (sum(c.islower() for c in p)+1e-6))

            # parameters
            param_query_length = len(q)
            query_num_params   = count_params(q) if q else 0

            row = [
                url_length, url_num_special_chars, url_ratio_digit_letter,
                domain_level, domain_contains_ip, domain_length,
                domain_num_digits, domain_num_nonletter, domain_num_hyphen,
                domain_num_at, domain_top, sub_num_dots, sub_num_subdomains,
                path_num_slash, path_num_subdirectories, path_presence,
                path_presence_upper_directories, path_presence_single_directories,
                path_num_special_chars, path_num_zeros, path_ratio_upper_lower,
                param_query_length, query_num_params,
                0  # phishing
            ]
            writer.writerow(row)


# chek IP 
def valid_ip(host: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(host)
        return True
    except:
        return False

# chek TLD
def tld_flag_from_url(url: str) -> int:
    try:
        host = urlparse(url).netloc.lower()
        if "." not in host:
            return 0
        tld = "." + host.split(".")[-1]
        return 1 if tld in TLDS_LIST else 0
    except Exception:
        return 0


# Tranco Top100  https://tranco-list.eu/list/7NNNX/1000000
ALEXA_TOP100 = {"google.com","microsoft.com","facebook.com","amazonaws.com","googleapis.com","apple.com",
    "youtube.com","ax-msedge.net","cloudflare.com","mail.ru","instagram.com","akamai.net",
    "gstatic.com","twitter.com","akamaiedge.net","office.com","dual-s-msedge.net","dzen.ru",
    "live.com","t-msedge.net","linkedin.com","azure.com","fbcdn.net","ln-msedge.net",
    "googletagmanager.com","googlevideo.com","amazon.com","windowsupdate.com","a-msedge.net","akadns.net",
    "wikipedia.org","microsoftonline.com","doubleclick.net","e2ro.com","office.net","github.com","appsflyersdk.com","googleusercontent.com",
    "gtld-servers.net","sharepoint.com","whatsapp.net","bing.com","fastly.net","netflix.com","trafficmanager.net","wordpress.org","windows.net",
    "workers.dev","icloud.com","aaplimg.com","youtu.be","pinterest.com","googlesyndication.com","apple-dns.net","digicert.com",
    "yahoo.com","skype.com","domaincontrol.com","tiktokcdn.com","cloudfront.net","msn.com","whatsapp.com","ntp.org","goo.gl",
    "adobe.com","vimeo.com","spotify.com",
    "aiv-cdn.net","gvt2.com","roblox.com","x.com","tiktok.com","cloudflare.net","office365.com","tiktokv.com",
    "msedge.net","bit.ly","wac-msedge.net","zoom.us","ytimg.com","gvt1.com","qq.com","edgekey.net","intuit.com","wordpress.com","a2z.com",
    "l-msedge.net","gandi.net","samsung.com","mozilla.org","cdn77.org","google-analytics.com","cloudflare-dns.com","pv-cdn.net",
    "googleadservices.com","nist.gov","googledomains.com","baidu.com","nginx.org","windows.com",
    }


# TLDS https://trends.netcraft.com/cybercrime/tlds
TLDS_LIST = {".black",".shop",".monster",".green",".fan",".baby",".cm",
    ".blue",".red",".hair",".pink",".ren",".skin",".bid",".wiki",".edu", 
    ".makeup",".ink",".fit",".motorcycles",".quest",".shopping",".ltd", 
    ".kim",".beauty",".wang",".gdn",".qpon",".xin",".pet",".cc",".homes", 
    ".yachts",".vip",".help",".loan",".lol",".autos",".lat",".boats", 
    ".college",".icu",".ooo",".top",".cyou",".click",".trade",".town", 
    ".pictures", ".mobi",
}
