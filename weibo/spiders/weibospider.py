#coding=utf-8
__author__ = 'lyb-mac'
from scrapy.spiders import CrawlSpider,Rule
from scrapy.selector import Selector
from scrapy.http import FormRequest,Request
from weibo.items import WeiboItem
from scrapy.contrib.linkextractors import LinkExtractor
from PIL import Image
import time
import base64
import rsa
import binascii
from urllib import quote_plus
import requests
import random
import re

class weibospider(CrawlSpider):
    session = requests.session()
    name = 'weibo'
    allow_domains = ['weibo.com']
    start_urls = ['http://weibo.com/u/2550172405/home?wvr=5']
    agent = 'Mozilla/5.0 (Windows NT 5.1; rv:33.0) Gecko/20100101 Firefox/33.0'
    headers = {
    "User-Agent": agent,
}
    rules = (
        Rule(LinkExtractor(allow=(r'http://weibo.cn/?since_id=.8?')),callback='parse_item'),
    )

    def get_su(self,username):
        su_quote = quote_plus(username)
        su_base64 = base64.b64encode(su_quote.encode('utf-8'))
        su = su_base64.decode('utf-8')
        return su

    def get_passwd(self,servertime, nonce, pubkey,password):
        key = rsa.PublicKey(int(pubkey,16),65537)
        message = str(servertime) + '\t' + str(nonce) + '\n' + str(password)
        message = message.encode('utf-8')
        passwd = rsa.encrypt(message,key)
        passwd = binascii.b2a_hex(passwd)
        return passwd

    def start_requests(self):
        pre_url = "http://login.sina.com.cn/sso/prelogin.php?entry=weibo&callback=sinaSSOController.preloginCallBack&su="
        su = self.get_su('1428260548@qq.com')
        pre_url = pre_url + su + "&rsakt=mod&checkpin=1&client=ssologin.js(v1.4.18)&_="
        pre_url = pre_url + str(int(time.time() * 1000))
        return [Request(pre_url, headers=self.headers,callback=self.login)]

    def get_captcha(self,pcid):
        cha_url = "http://login.sina.com.cn/cgi/pin.php?r="
        cha_url = cha_url + str(int(random.random() * 100000000)) + "&s=0&p="
        cha_url = cha_url + pcid
        cha_page = self.session.get(cha_url, headers=self.headers)
        with open("cha.jpg", 'wb') as f:
            f.write(cha_page.content)
            f.close()
        try:
            im = Image.open("cha.jpg")
            im.show()
            im.close()
        except:
            print(u"请到当前目录下，找到验证码后输入")

    def login(self,response):
        sever_data = eval(response.body.decode("utf-8").replace("sinaSSOController.preloginCallBack", ''))
        severtime = sever_data["servertime"]
        nonce = sever_data['nonce']
        rsakv = sever_data["rsakv"]
        pubkey = sever_data["pubkey"]
        showpin = sever_data["showpin"]
        password_secret = self.get_passwd(severtime, nonce, pubkey,'lyb1993')
        postdata = {
        'entry': 'weibo',
        'gateway': '1',
        'from': '',
        'savestate': '7',
        'useticket': '1',
        'pagerefer': "http://login.sina.com.cn/sso/logout.php?entry=miniblog&r=http%3A%2F%2Fweibo.com%2Flogout.php%3Fbackurl",
        'vsnf': '1',
        'su': self.get_su('1428260548@qq.com'),
        'service': 'miniblog',
        'servertime': str(severtime),
        'nonce': nonce,
        'pwencode': 'rsa2',
        'rsakv': rsakv,
        'sp': password_secret,
        'sr': '1366*768',
        'encoding': 'UTF-8',
        'prelt': '115',
        'url': 'http://weibo.com/ajaxlogin.php?framelogin=1&callback=parent.sinaSSOController.feedBackUrlCallBack',
        'returntype': 'META'
        }
        login_url = 'http://login.sina.com.cn/sso/login.php?client=ssologin.js(v1.4.18)'
        if showpin == 0:
            login_page = self.session.post(url=login_url, data=postdata, headers=self.headers)
        else:
            pcid = sever_data["pcid"]
            self.get_captcha(pcid)
            postdata['door'] = raw_input(u"请输入验证码")
            login_page =  self.session.post(login_url,data=postdata,headers=self.headers)
        login_loop = (login_page.content.decode("GBK"))
        pa = r'location\.replace\([\'"](.*?)[\'"]\)'
        loop_url = re.findall(pa, login_loop)[0]
        return [Request(loop_url, headers=self.headers,callback=self.after_login)]

    def after_login(self,response):
        for i in self.start_urls:
            return [Request(url=i, method='get', callback=self.parse)]
    def parse_item(self,response):
        print response
