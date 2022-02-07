import os
import yaml
from typing import Optional
from array import array
import re
import tweepy
import time
from pycti import OpenCTIStix2Utils
from datetime import datetime
from hash_identifier import *
from stix2 import  Indicator, Bundle, Relationship
from pycti import (
    OpenCTIConnectorHelper,
    get_config_variable,
    SimpleObservable,
    OpenCTIStix2Utils,
)


hashes = []
urls = []
ipv4_addrs = []
hostnames = [] #begin with www.
domain_names = [] #just site name
bundleobj=[]

class IOCTweet:


    def __init__(self):
        # Instantiate the connector helper from config
        config_file_path = os.path.dirname(os.path.abspath(__file__)) + "/config.yml"
        config = (
            yaml.load(open(config_file_path), Loader=yaml.FullLoader)
            if os.path.isfile(config_file_path)
            else {}
        )
        self.helper = OpenCTIConnectorHelper(config)
        # Extra config
        self.ioctweet_interval = get_config_variable(
        "IOCTweet_INTERVAL", ["ioctweet", "interval"], config, True
        )
        self.consumer_key = get_config_variable(
            "IOCTweet_Consumer_Key", ["ioctweet", "consumer_key"], config
        )
        self.consumer_secret = get_config_variable(
            "IOCTweet_Consumer_Secret", ["ioctweet", "consumer_secret"], config
        )
        self.access_token = get_config_variable(
            "IOCTweet_Acess_Token", ["ioctweet", "access_token"], config
        )
        self.access_token_secret = get_config_variable(
            "IOCTweet_Acess_Token_Secret", ["ioctweet", "access_token_secret"], config
        )
        







    def clean_ip_url(self,stringa):
        new_stringa = stringa.replace("]","").replace("[","").replace("hxxp","http").replace("-&gt;","").replace("&gt;","")
        return new_stringa

    #verify if a string is an hash
    def verify_hash(self, stringa):
        for s in stringa:
            value = 0   
            if s.isnumeric() or s.isalpha():
                value=1
            else:
                value=0
                break
        if value == 1 and stringa not in hashes and not re.search(u'[\u4e00-\u9fff]', stringa):
            val = find_hash(stringa)
            if val == 1:
                hashes.append(stringa)

    #Function to verify if a string is a ip address or a url
    def verify_ip_url(self,stringa):
        for s in stringa:
            value = 0
            if s.isnumeric() or s == "." or s == "]" or s == "[":
                value = 0
            else:
                value=1
                break
        if value == 1:
            stringa = self.clean_ip_url(stringa)
            if stringa[0:4] == "www.":
                hostnames.append(stringa)
            elif stringa[0:4] == "http":
                urls.append(stringa)
            else:
                domain_names.append(stringa)
        elif value==0 and stringa not in ipv4_addrs:
            stringa = self.clean_ip_url(stringa)
            ipv4_addrs.append(stringa)

    #find the IOC type
    def find_IOC(self,string):
        array_strings = string.split(None)
        for s in array_strings:
            if ".]" in s or "[." in s or s[0:4]=="hxxp":
                #print("Stampa url presa:" +s)
                self.verify_ip_url(s)
            elif len(s)>30:
                self.verify_hash(s)


    def take_top(self,array_string):
        topten_array = []
        for string in array_string:
            for s in string:
                if s[0] == "#":
                    topten_array.append(string)
                if len(topten_array)>10:
                    res = topten_array[::-1] 
                    topten_array = res[:10]
        return topten_array



    def send_bundle(self,melf_key):
        global bundleobj
        if len(urls) !=0 :
            for patter in urls:
                url_stix = SimpleObservable(
                id=OpenCTIStix2Utils.generate_random_stix_id(
                    "x-opencti-simple-observable"
                ),
                labels=[melf_key],
                key="Url.value",
                value=patter,
                )
                bundleobj.append(url_stix)
                indicator_url = Indicator(
                    id=OpenCTIStix2Utils.generate_random_stix_id("indicator"),
                    labels=[melf_key],
                    pattern_type="stix",
                    name=patter,
                    pattern="[url:value = '"+patter+"']",
                    custom_properties={
                                "x_opencti_main_observable_type": "Url"
                    }
                )
                bundleobj.append(indicator_url)
                relation_url=Relationship(
                    id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
                    relationship_type="based-on",
                    source_ref=indicator_url.id,
                    target_ref=url_stix.id,
                    allow_custom=True,
                )
                bundleobj.append(relation_url)

        if len(hashes) !=0 :
            for filename in hashes:

                if len(filename) == 32:
                    file_stix_MD5 = SimpleObservable(
                    id=OpenCTIStix2Utils.generate_random_stix_id(
                        "x-opencti-simple-observable"
                    ),
                    labels=[melf_key],
                    key="File.hashes.MD5",
                    value=filename,
                    )
                    bundleobj.append(file_stix_MD5)
                   
                    indicator_MD5 = Indicator(
                    id=OpenCTIStix2Utils.generate_random_stix_id("indicator"),
                    pattern_type="stix",
                    name=filename,
                    labels=[melf_key],
                    pattern="[file:hashes.'MD5' = '"+filename+"']",
                    custom_properties={
                                "x_opencti_main_observable_type": "File"
                    }
                    )
                    bundleobj.append(indicator_MD5) 
                    relation_MD5 = Relationship(
                        id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
                        relationship_type="based-on",
                        source_ref=indicator_MD5.id,
                        target_ref=file_stix_MD5.id,
                        allow_custom=True,

                    )
                    bundleobj.append(relation_MD5)
                    
               
                elif len(filename) == 40:
                    file_stix_SHA1 = SimpleObservable(
                    id=OpenCTIStix2Utils.generate_random_stix_id(
                        "x-opencti-simple-observable"
                    ),
                    labels=[melf_key],
                    key="File.hashes.SHA-1",
                    value=filename,
                    )
                    bundleobj.append(file_stix_SHA1)
                    indicator_SHA1 = Indicator(
                    id=OpenCTIStix2Utils.generate_random_stix_id("indicator"),
                    pattern_type="stix",
                    name=filename,
                    labels=[melf_key],
                    pattern="[file:hashes.'SHA-1' = '"+filename+"']",
                    custom_properties={
                                "x_opencti_main_observable_type": "File"
                    }
                    )
                    bundleobj.append(indicator_SHA1)
                    relation_SHA1 = Relationship(
                        id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
                        relationship_type="based-on",
                        source_ref=indicator_SHA1.id,
                        target_ref=file_stix_SHA1.id,
                        allow_custom=True,

                    )
                    bundleobj.append(relation_SHA1)

                    
                elif len(filename) == 64:

                    file_stix_SHA256 = SimpleObservable(

                        id=OpenCTIStix2Utils.generate_random_stix_id(
                            "x-opencti-simple-observable"
                        ),
                        labels=[melf_key],
                        key="File.hashes.SHA-256",
                        value=filename,
                        ) 
                    bundleobj.append(file_stix_SHA256)

                    indicator_SHA256 = Indicator(

                        id=OpenCTIStix2Utils.generate_random_stix_id("indicator"),
                        pattern_type="stix",
                        name=filename,
                        labels=[melf_key],
                        pattern="[file:hashes.'SHA-256' = '"+filename+"']",
                        custom_properties={
                                    "x_opencti_main_observable_type": "File"
                        }
                        ) 
                    bundleobj.append(indicator_SHA256)
                    relation_SHA256 = Relationship(
                        id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
                        relationship_type="based-on",
                        source_ref=indicator_SHA256.id,
                        target_ref=file_stix_SHA256.id,
                        allow_custom=True,

                        )
                    bundleobj.append(relation_SHA256)    
                     
            
            
        
        if len(ipv4_addrs) !=0 :
            for ip in ipv4_addrs:
                ip_stix = SimpleObservable(
                id=OpenCTIStix2Utils.generate_random_stix_id(
                    "x-opencti-simple-observable"
                ),
                labels=[melf_key],
                key="IPv4-Addr.value",
                value=ip,
                )              
                bundleobj.append(ip_stix)
                
                indicator_ip = Indicator(
                id=OpenCTIStix2Utils.generate_random_stix_id("indicator"),
                pattern_type="stix",
                labels=[melf_key],
                name=ip,
                pattern="[ipv4-addr:value = '"+ip+"']",
                custom_properties={
                            "x_opencti_main_observable_type": "IPv4-Addr"
                }
                )
                bundleobj.append(indicator_ip)
                relation_ip = Relationship(
                        id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
                        relationship_type="based-on",
                        source_ref=indicator_ip.id,
                        target_ref=ip_stix.id,
                        allow_custom=True,

                        )
                bundleobj.append(relation_ip)    

                
               
        if len(hostnames) !=0 :
            for host in hostnames :
                hostaname_stix = SimpleObservable(
                id=OpenCTIStix2Utils.generate_random_stix_id(
                    "x-opencti-simple-observable"
                ),
                labels=[melf_key],
                key="X-OpenCTI-Hostname.value",
                value=host,
                )
                bundleobj.append(hostaname_stix)
                indicator_hostname = Indicator(
                id=OpenCTIStix2Utils.generate_random_stix_id("indicator"),
                labels=[melf_key],
                pattern_type="stix",
                name=host,
                pattern="[x-opencti-hostname:value ='"+host+"']",
                custom_properties={
                            "x_opencti_main_observable_type": "X-OpenCTI-Hostname"
                }
                )
                bundleobj.append(indicator_hostname)
                relation_hostname = Relationship(
                        id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
                        relationship_type="based-on",
                        source_ref=indicator_hostname.id,
                        target_ref=hostaname_stix.id,
                        allow_custom=True,

                        )
                bundleobj.append(relation_hostname) 
               
        if len(domain_names) != 0 :
            for dominio  in domain_names:
                domain_stix = SimpleObservable(
                id=OpenCTIStix2Utils.generate_random_stix_id(
                    "x-opencti-simple-observable"
                ),
                labels=[melf_key],
                key="Domain-Name.value",
                value=dominio,
                )
                bundleobj.append(domain_stix)

                indicator_domain_name = Indicator(
                id=OpenCTIStix2Utils.generate_random_stix_id("indicator"),
                labels=[melf_key],
                pattern_type="stix",
                name=dominio,
                pattern="[domain-name:value ='"+dominio+"']",
                custom_properties={
                            "x_opencti_main_observable_type": "Domain-Name"
                }
                )
                bundleobj.append(indicator_domain_name)
                relation_domain_name = Relationship(
                        id=OpenCTIStix2Utils.generate_random_stix_id("relationship"),
                        relationship_type="based-on",
                        source_ref=indicator_domain_name.id,
                        target_ref=domain_stix.id,
                        allow_custom=True,

                        )
                bundleobj.append(relation_domain_name) 


    def find_tweet(self,work_id):
      

        global hashes
        global urls
        global ipv4_addrs
        global hostnames  #begin with www.
        global domain_names  #just site name

        
        auth = tweepy.OAuthHandler(self.consumer_key, self.consumer_secret)
        auth.set_access_token(self.access_token, self.access_token_secret)
        api = tweepy.API(auth)

        print ("**************************************************************************")
        try:
            api.verify_credentials()
            print ("Verification of credentials with SUCCESS")
        except:
            print ("Check your credentials")

        print ("**************************************************************************")

        key="TOP10 ANYRUN"

        public_tweets = tweepy.Cursor(api.search_tweets, q=key, result_type="recent", tweet_mode="extended").items(100)
        array_strings = []
        i=0
        for tweet in public_tweets:
            if tweet.user.screen_name == "anyrun_app" and i==0:  
                i = i + 1
                tweet_text = tweet.full_text
                print(tweet_text)
                array_strings = tweet_text.split(None)
                #print(array_strings)
                topten_malware = self.take_top(array_strings)
        print(topten_malware)

        for mlw_key in topten_malware:

            print(mlw_key)
            public_tweets = tweepy.Cursor(api.search_tweets, q=mlw_key, result_type="recent", tweet_mode="extended").items(100)

            for tweet in public_tweets:
                #print("@" + tweet.user.screen_name)
                tweet_text = tweet.full_text
                string = str(tweet_text)
                self.find_IOC(string)
                #print(tweet_text)
                #print("**************************************************************************")

            print("URLS:")
            urls =  list(dict.fromkeys(urls))
            print(urls)
            print("HOSTNAMES:")
            hostnames =  list(dict.fromkeys(hostnames))
            print(hostnames)
            print("DOMAIN_NAMES:")
            domain_names =  list(dict.fromkeys(domain_names))
            print(domain_names)
            print("IP:")
            ipv4_addrs =  list(dict.fromkeys(ipv4_addrs))
            print(ipv4_addrs)
            print("HASH: ")
            hashes =  list(dict.fromkeys(hashes))
            print(hashes)
            print("**************************************************************************")
        
            self.send_bundle(mlw_key)
            
            hashes.clear()
            urls.clear()
            ipv4_addrs.clear()
            hostnames.clear
            domain_names.clear()


        bundle = Bundle(objects=bundleobj, allow_custom=True).serialize()
        self.helper.send_stix2_bundle(bundle, work_id=work_id)    




    def process_data(self):

        try:
            timestamp = int(time.time())
            current_state = self.helper.get_state()

            if current_state is not None and "last_run" in current_state:
                last_run = current_state["last_run"]
                self.helper.log_info(
                        "Template last run: "
                        + datetime.utcfromtimestamp(last_run).strftime("%Y-%m-%d %H:%M:%S")
                )
            else:
                last_run = None
                self.helper.log_info("Connector has never run")

            if last_run is None or ((timestamp - last_run) > ((int(self.ioctweet_interval) - 1) * 60 *60 * 24 )):
                timestamp = int(time.time())
                now = datetime.utcfromtimestamp(timestamp)
                friendly_name = "Template run @ " + now.strftime("%Y-%m-%d %H:%M:%S")
                work_id = self.helper.api.work.initiate_work(
                    self.helper.connect_id, friendly_name
                )

                self.helper.log_info(
                f"Connector successfully run, storing last_run as {str(timestamp)}"
                )
                self.find_tweet(work_id)
                message = "Last_run stored"
                self.helper.set_state({"last_run": timestamp})
                self.helper.api.work.to_processed(work_id, message)
                self.helper.log_info(message)
            else:
                self.helper.log_info("Connector is not working")

        except Exception as e:
            self.helper.log_error(str(e))

    def run(self):
        self.helper.log_info("Inizio connettore : ")
        while True:
            self.process_data()
            time.sleep(60*2)


if __name__ == "__main__":
    try:
        IOCTweetConnector = IOCTweet()
        IOCTweetConnector.run()
    except Exception as e:
        print(e)
        time.sleep(10)
        exit(0)
