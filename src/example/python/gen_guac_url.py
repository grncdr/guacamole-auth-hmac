#!/user/bin/python
#-*- coding:utf-8 -*-

import hashlib
import hmac
import random
import time
import urllib
import sys


SECRET_KEY = "secret_key"
def gen_guac_conn(server, host, protocol):
    conn_id = random.randint(1, 20000)
    singedParams = ['guac.username', 'guac.password', 'guac.hostname', 'guac.port']
    qs = dict()
    qs["id"] = "c/" + str(conn_id)
    qs["guac.hostname"] = host
    qs['timestamp'] = int(round(time.time() * 1000))
    if protocol == 'ssh':
        qs["guac.username"] = "ssh_user"
        qs["guac.password"] = "ssh_password"
        qs["guac.protocol"] = "ssh"
        qs["guac.port"] = 22
        message = str(qs["timestamp"]) + qs["guac.protocol"]
        for key in singedParams:
            if key in qs.keys():
                message += str(key[5:])
                message += str(qs[key])
        hashed = hmac.new(SECRET_KEY, message, hashlib.sha1)
        qs['signature'] = hashed.digest().encode("base64").rstrip('\n')
        uri = urllib.urlencode(qs)
    else:
        qs['guac.password'] = "vnc_password"
        qs["guac.protocol"] = "vnc"
        qs["guac.port"] = 5901
        message = str(qs["timestamp"]) + qs["guac.protocol"]
        for key in singedParams:
            if key in qs.keys():
                message += str(key[5:])
                message += str(qs[key])
        hashed = hmac.new(SECRET_KEY, message, hashlib.sha1)
        qs['signature'] = hashed.digest().encode("base64").rstrip('\n')
        uri = urllib.urlencode(qs)

    guac_conn = 'http://' + str(server).strip() + '/#/client/' + str(conn_id) + '?' + uri
    return guac_conn

if __name__ == "__main__":
    server = 'localhost'
    protocol = 'vnc'
    host = sys.argv[1]
    print gen_guac_conn(server, host, protocol)


