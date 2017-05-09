import urllib.request
import whois
import datetime
from urllib.parse import urlparse


def load_urls4check(path):
    checksite = {}
    with open(path) as fileurl:
        for url in fileurl.read().split():
            isserverrespond = is_server_respond_with_200(url)
            isdomainexpire = get_domain_expiration_date(urlparse(url).netloc)
            if isserverrespond and isdomainexpire:
                checksite[urlparse(url).netloc] = 'OK'
            else:
                checksite[urlparse(url).netloc] = 'BAD'
    return checksite


def is_server_respond_with_200(url):
    response = urllib.request.urlopen(url)
    if response.getcode() == 200:
        healthsites = True
    else:
        healthsites = False
    return healthsites


def get_domain_expiration_date(domain_name):
    domain = whois.query(domain_name)
    countdays = 30
    daytoexpire = (domain.expiration_date - datetime.datetime.today()).days
    if daytoexpire > countdays:
        domainnoexpire = True
    else:
        domainnoexpire = False

    return domainnoexpire

if __name__ == '__main__':
    checksite = load_urls4check('domain.txt')
    for k,v in checksite.items():
        print(k, v)
