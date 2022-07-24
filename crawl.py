# coding=utf-8
import requests
import re
import json
import time
import random
import ipaddress
import math
from environs import Env

env = Env()
env.read_env()
page_size = env.int('FEED_PAGE_SIZE', 10)  # set PageSize to 10 by default
delay = env.bool('IS_DELAY', False)  # set Delay to True to delay the reques
cookie_rememberme = env.str('COOKIE_REMEMBERME')
cookie_csrf_token = env.str('COOKIE_CSRF_TOKEN')

if len(cookie_rememberme) == 0 or len(cookie_csrf_token) == 0:
    print("Please set cookie_rememberme and cookie_csrf_token in .env file")
    exit(1)

url = 'https://x.threatbook.com/'
headers = {'Host': 'x.threatbook.com',
           'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.114 Safari/537.36 Edg/103.0.1264.51',
           'Accept': '*/*',
           'Accept-Language': 'accept-language: zh-CN,zh-TW;q=0.9,zh;q=0.8,en-US;q=0.7,en;q=0.6',
           'Accept-Encoding': 'gzip, deflate, br',
           'referer': 'https://x.threatbook.com/'}

cookies = {'csrfToken': cookie_csrf_token,
           'rememberme': cookie_rememberme,
           'sajssdk_2015_cross_new_user': '1',
           'day_first_activity': 'true',
           'day_first': 'true'
           }


class item:
    def __init__(self, ip, threat_id_info, domain_count, tag_count, itel_count, judge, poc, ctime, source):
        self.ip = ip
        self.threat_id_info = threat_id_info
        self.domain_count = domain_count
        self.tag_count = tag_count
        self.itel_count = itel_count
        self.judge = judge
        self.poc = poc
        self.ctime = ctime
        self.source = source

    def __repr__(self):
        return "ip:%s, threat_id_info: %s, domain_count: %s, tag_count: %s, itel_count: %s, judge: %s, poc: %s, ctime: %s, source: %s" % (
            self.ip, self.threat_id_info, self.domain_count, self.tag_count, self.itel_count, self.judge, self.poc,
            self.ctime, self.source)


def get_post_by_page(item_list, start_page, page_count):
    counter = 1
    last_threat_id = 0
    param = "v5/node/community/infoFlow/page?classify=all&page=%s&pageSize=%s" % (start_page, page_size)
    first_url = url + param
    # print(first_url)
    res = requests.get(first_url, headers=headers, cookies=cookies)
    # print(res.text)
    payload = json.loads(res.text)
    while counter <= page_count:
        if counter == 1:
            # print("page: %s" % counter)
            last_threat_id, modify_counter = parse_payload(item_list, counter, payload)
            counter = modify_counter
            # print("page: %s" % counter)
        if last_threat_id:
            sequence_param = "v5/node/community/infoFlow/page?classify=all&page=%s&pageSize=%s&lastThreatId=%s" % (
                start_page + 1, page_size, last_threat_id)
            start_page += 1
            sequence_url = url + sequence_param
            # print(sequence_url)
            sequence_res = requests.get(sequence_url, headers=headers, cookies=cookies)
            # print(sequence_res.text)
            sequence_payload = json.loads(sequence_res.text)
            last_threat_id, modify_counter = parse_payload(item_list, counter, sequence_payload)
            counter = modify_counter
            # print("page: %s" % counter)
        else:
            break
    return item_list


def parse_payload(item_list, counter, payload):
    if payload:
        response_code = payload['response_code']
        if response_code == 0 and 'data' in payload:
            if delay:
                time.sleep(random.uniform(0, 3))
            data = payload['data']
            if data:
                for idx, item in enumerate(data):
                    find_ip_from_content(item['articleInfo']['content'], item_list,
                                         item['articleInfo']['threatId'], item['articleInfo']['lastUtime'])
                    counter += 1
                    if item['articleInfo']['iocCount'] > 0:
                        threat_id = item['articleInfo']['threatId']
                        ioc_count = item['articleInfo']['iocCount']
                        print('ioc_count: %s' % ioc_count)
                        print('threat_id: %s' % threat_id)
                        parse_ioc(int(item['articleInfo']['threatId']), item['articleInfo']['lastUtime'],
                                  item['articleInfo']['iocCount'], item_list)
                    if idx == len(data) - 1:
                        counter += 1
                        last_threat_id = item['articleInfo']['bid']
                        # print(last_threat_id)
                        return last_threat_id, counter


def parse_ioc(threat_id, ctime, ioc_count, item_list):
    # print("total_ioc_page:%s"%math.ceil(ioc_count / 5))
    for i in range(1, math.ceil(ioc_count / 5) + 1):
        ioc_url = url + "v5/node/user/article/getIocInfo?page=%s&pagesize=5&type=ip&shortMessageId=%s" % (i, threat_id)
        # print ("threat_id:%s, page:%s" % (threat_id, i))
        if delay:
            time.sleep(random.uniform(0, 3))
        ioc_res = requests.get(ioc_url, headers=headers, cookies=cookies)
        ioc_payload = json.loads(ioc_res.text)
        # print(ioc_payload)
        if ioc_payload:
            response_code = ioc_payload['response_code']
            if response_code == 0 and 'data' in ioc_payload:
                details = ioc_payload['data']['details']
                if details:
                    for detail in details:
                        item_list.append(
                            item(detail['ioc'], threat_id, parse_to_int(detail['domainCount']),
                                 parse_to_int(detail['tagCount']),
                                 parse_to_int(detail['itelCount']), int(detail['judge']), detail['poc'], ctime, 1))


def find_ip_from_content(content, item_list, threat_id, ctime):
    ip_list = re.findall(r'[0-9]+(?:\.[0-9]+){3}', content)
    if ip_list:
        for ip in ip_list:
            item_list.append(item(ip, threat_id, -1, -1, -1, -1, False, ctime, -1))
    for separate_ip in item_list:
        if is_lan(separate_ip.ip) or not check_ip_valid(separate_ip.ip) or is_loopback(separate_ip.ip):
            item_list.remove(separate_ip)


def check_ip_valid(ip):
    try:
        ipaddress.ip_address(ip.strip())
        return True
    except Exception as e:
        return False


def is_lan(ip):
    try:
        return ipaddress.ip_address(ip.strip()).is_private
    except Exception as e:
        return False


def parse_to_int(string):
    try:
        return int(string)
    except Exception as e:
        return 1000


def is_loopback(ip):
    try:
        return ipaddress.ip_address(ip.strip()).is_loopback
    except Exception as e:
        return False
