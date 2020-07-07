# -*- coding: utf-8 -*-
"""
Created on Sat Jul  4 15:54:18 2020

@author: OMMIE
"""
import requests as req
import json

input_ = input("enter domain = ")
subdomain_list = []

class subdomain_finder:
    def __init__(self, url):
        self.crtsh(url)
        #self.certspotter(url) #Ada Limit
        self.threat_crowd(url)
        self.urlscan(url)
        print("===============Extend Wildcard==============")
        self.ext_wildcard()
        print("====================Hasil===================")
        print("url input = ", url)
    
    def crtsh(self,url):
        get_url = req.get(f"https://crt.sh/?q={url}&output=json")
        #print("crtsh url = ", url)
        parse_json = json.loads(get_url.text)
        for i in parse_json:
            url_name = i['name_value']
            subdomain_list.append(url_name)
        # 36
    def certspotter(self,url): #Ada Limit
        get_url = req.get(f"https://certspotter.com/api/v0/certs?domain={url}")
        #print("certspotter = ", url)
        parse_json = json.loads(get_url.text)
        for i in parse_json:
            dns_name = i['dns_names']
            #print(type(dns_name))
            #dumps_dns_name = json.dumps(dns_name)
            for j in dns_name:
                subdomain_list.append(j)
    def urlscan(self,url):
        get_url = req.get(f"https://urlscan.io/api/v1/search/?q={url}")
        #print("urlscan = ", url)
        parse_json = json.loads(get_url.text)
        if len(parse_json['results']) > 0:
            for i in parse_json['results']:
                page_url = i['page']['url']
                task_url = i['page']['url']
                subdomain_list.append(page_url)
                subdomain_list.append(task_url)      
    def threat_crowd(self,url):
        get_url = req.get(f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={url}")
        #print("threat crowd = ", url)
        parse_json = json.loads(get_url.text)
        if parse_json['response_code'] == '1':
            for i in parse_json['subdomains']:
                subdomain_list.append(i)
    def ext_wildcard(self):
        unique_subdomain = set(subdomain_list)
        for i in unique_subdomain:
            if i[:1] == '*':
                modified_string = i[2:]
                self.crtsh(modified_string)
                #self.certspotter(modified_string) #Ada Limit
                self.threat_crowd(modified_string)
                self.urlscan(modified_string)
    
subdomain_finder(input_)
#print(len(subdomain_list)) 139
#print(subdomain_list)
#print("not unique = ",len(subdomain_list))            
#print(input_[2:])
unique_subdomain = set(subdomain_list)
print("unique = ",len(unique_subdomain))
for i in unique_subdomain:
    print(i)

#traveolka 424
#tokopedia 296
    