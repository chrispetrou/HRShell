#### Version 1.8 (_TBA_)

*   More features & bug fixes!

#### Version 1.7 (_11-10-2019_)

*   Implemented interactive `history` command available when `server.py` runs on Unix systems.
*   Also on __unix__ systems, the `inject shellcode` command, instead of spawning a new thread will spawn a new process. In this way even if e.g. the meterpreter session closes the HTTP(S) connection remains intact. On windows systems there was no such problem...
*   `hex <(path to) file>` command added!
*   Comments are supported... 

#### Version 1.6 (_09-10-2019_)

*   `screenshot` command __doesn't__ store the screenshot captured on the client and then trasmits it to server, __but__ directly transmits it to the server avoiding to touch the disk on client.
*   Direct browser connections are not allowed.
*   `help` command added.

#### Version 1.5 (_28-09-2019_)

*   Now shellcode can be set or modified on the fly from the server using the `set shellcode <id>` command.

#### Version 1.4 (_22-09-2019_)

*   `migrate <PID>` command now works for both x86 and x64 Windows systems!

#### Version 1.3 (_22-09-2019_)

*   Shellcode injection into the current process now works for more platforms. The platforms supported are:
    *   __Unix x86__
    *   __Unix x64__
    *   __Windows x86__   
Also now instead of injecting directly into the current process the shellcode injection takes place into the memory space of a current's process thread. As a result the HTTP(S) shell does not gets affected in any wat by the shellcode injection!

#### Version 1.2 (_20-09-2019_)

*   Python 2.x compatibility removed since there were some bugs regarding some present and future features.

#### Version 1.1 (_20-08-2019_)

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