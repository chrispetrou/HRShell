#### Version 1.3 (_In progress_)

*   More features!

#### Version 1.2

*   Python 2.x compatibility removed since there were some bugs regarding some present and future features.

#### Version 1.1

*   It's stealthy
*   __TLS__ support 🔑
    -   Either using _on-the-fly_ certificates or
    -   By specifying a cert/key pair (_more details below..._)
*   Proxy 🦊 support on client.
*   Directory navigation (`cd` command and variants).
*   `download/upload/screenshot` commands available.
*   shellcode injection 💉 (_for the time it is available only for windows x86 systems but support for other OSs and ARCHs will be added soon!_)
    -   Either shellcode injection into another process by specifying its PID
    -   or shellcode injection in the current running process
*   Pipelining (`|`) & chained commands (`;`) are supported
*   Support for every non-interactive (_like gdb, top etc..._) command
*   Server is both HTTP & HTTPS capable.
*   It comes with two built-in servers 🌐 so far... _flask built-in_ & _tornado-WSGI_ while it's also compatible with other production servers like [`gunicorn`](http://gunicorn.org/) and [`Nginx`](https://www.nginx.com/).
*   Both `server.py` and `client.py` are easily extensible.
*   Since the most functionality comes from server's endpoint-design it's very easy to write a client in any other language _e.g. java, GO etc..._