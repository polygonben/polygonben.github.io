---
title: "Try Hack Me: Chill Hack - Detailed Writeup"
categories:
  - CTF Writeups
toc: true
---

## Reconnaissance
### Nmap

I always start my challenges with a thorough nmap scanning covering all of the ports. So let's begin with that :)

[![1](/assets/images/ChillHack/1.png)](/assets/images/ChillHack/1.png){: .full}

Let's explain each switch of the command as well the results.

- `-p-` : This switch scans all TCP ports to check if they're open

- `-sV` : Service enumeration / Version enumeration, this tries to confirm the service which is running on an open port, as well as the version of said service. Without the `-sV`, nmap which just take a guess from the most common service on that port number

- `-sC` : Default script scan. Uses the 'default' NSE scripts to retrieve more interesting information about each service.

- `-T4` : Increases the speed of the scan from the default `-T3`, `-T5` can give unreliable results , I've found `-T4` to be the 'sweet spot' 

- `-o thorough_tcp.txt` : Output to a text file for later reference.

#### Nmap results breakdown

Our nmap scan covering all the ports discovers 3 ports to be open on this box: `21` , `22` and `80`.

- `21/tcp` : FTP, `vsftpd 3.0.3` 
  - Interesting NSE results:
      - `ftp-anon` : Anonymous FTP login allowed!, this means we can succesfully login to the `ftp` service with username `anonymous` and any password of choice.
- `22/tcp` : SSH `OpenSSH 7.6p1 Ubuntu`
- `80/tcp` : HTTP `Apache/2.4.29 (Ubuntu)`

We've found a big weakness from our nmap scan alone, anonymous FTP access is allowed, let's investigate this further!

### FTP

Using our previous found knowledge we can logon view the file, `note.txt`, hosted on the box.

[![2](/assets/images/ChillHack/2.png)](/assets/images/ChillHack/2.png){: .full}

After downloading the file locally with `get note.txt` we can view it's contents with `cat note.txt`.

[![3](/assets/images/ChillHack/3.PNG)](/assets/images/ChillHack/3.PNG){: .full}

Interesting, I'm guessing this information will become useful later on in the challenge.

Let's move onto to enumerating the web service.

### HTTP 

At first glance of the webpage it looks like sport blog.

[![5](/assets/images/ChillHack/5.png)](/assets/images/ChillHack/5.png){: .full}


#### Web technologies
Let's begin with some basic technology enumeration to view the web-stack with the `whatweb` command.

[![4](/assets/images/ChillHack/4.png)](/assets/images/ChillHack/4.png){: .full}

Nothing too interesting here, we just have confirmation that this is running on a `Apache 2.4.29` webserver with `JQuery 1.1.1`. 

I always check `robots.txt` to see if the developer is trying to hide any webpages from a browser, in this case we get a 404 response code when looking for this. Let's continue our web recon by fuzzing for hidden pages and directories. 

#### Fuzzing

[![6](/assets/images/ChillHack/6.png)](/assets/images/ChillHack/6.png){: .full}

I'll be using the `ffuf` tool with SecLists wordlist `directory-list-2.3-small.txt` to search for directories. I'm using the switch `-fc 404` to not return any directories which return HTTP response code `404`.

##### Fuzzing results

[![7](/assets/images/ChillHack/7.png)](/assets/images/ChillHack/7.png){: .full}

The output of `ffuf_dir_small.log` was messy so I used a combination of `grep` and `cut` to parse & clean the output into a semi-nice output of valid directories. The one that stands out me is `/secret`. Let's check it out!

Visiting this endpoint I was prompted with a **Command** text input box with a button **Execute**. Perhaps this is a web-interface to execute remote commands on the computer?

[![8](/assets/images/ChillHack/8.png)](/assets/images/ChillHack/8.png){: .full}

## Initial Foothold

After playing around for a while I figured their was filtering on certain commands that could be ran. If the input contained strings like `nc`, `php`, or `python` (and probably more) - the program wouldn't execute.

[![9](/assets/images/ChillHack/9.png)](/assets/images/ChillHack/9.png){: .full}

However, there was not filtering on `wget`, let's see if I can download files onto the box.

[![10](/assets/images/ChillHack/10.png)](/assets/images/ChillHack/10.png){: .full}

[![11](/assets/images/ChillHack/11.png)](/assets/images/ChillHack/11.png){: .full}

Okay, that command ran and we got a request from my python HTTP server. Let's verify if this succesfully downloaded into the `/tmp` directory.

[![12](/assets/images/ChillHack/12.png)](/assets/images/ChillHack/12.png){: .full}

Great! It worked. We should be able to upload a reverse-shell and execute it now!

### Crafting payload

Although, at this point, there is lots of freedom of how to gain a reverse-shell, I went with the classic. 

[![13](/assets/images/ChillHack/13.png)](/assets/images/ChillHack/13.png){: .full}

### Downloading payload

Let's download this onto the box.

[![14](/assets/images/ChillHack/14.png)](/assets/images/ChillHack/14.png){: .full}

### Executing payload

I tried to make the `revshell.sh` executable with `chmod`, however, for some reason - this didn't work. Instead I restored to the below for execution.

[![15](/assets/images/ChillHack/15.png)](/assets/images/ChillHack/15.png){: .full}

Going back to the the reverse-shell listener I can see I now have an initial foothold as `www-data` :) 

[![16](/assets/images/ChillHack/16.png)](/assets/images/ChillHack/16.png){: .full}

## Privilege Escalation

### www-data -> Apaar

#### sudo -l 

I started off by viewing the sudo capabilities I have as the `www-data` with the `sudo -l` command.

[![17](/assets/images/ChillHack/17.png)](/assets/images/ChillHack/17.png){: .full}

Interesting, I can execute this `/home/apaar/.helpline.sh` script as the `apaar` user. Let's inspect this script!

[![18](/assets/images/ChillHack/18.png)](/assets/images/ChillHack/18.png){: .full}

The line `$msg 2>/dev/null` stood out to me. The `$msg` variable was set as user input on line `read -p "Hello... " msg`, meaning that our 2nd user input will be executed. Let's test this out.

[![19](/assets/images/ChillHack/19.png)](/assets/images/ChillHack/19.png){: .full}

Great! If we set our 2nd input to `id` we consquently get the output of the `id` command as the user `apaar`. Let's now input `/bin/bash` to get a shell as `apaar`.

[![20](/assets/images/ChillHack/20.png)](/assets/images/ChillHack/20.png){: .full}

Fantastic! This worked and we were able to recover the User flag which is stored as `local.txt`.

### Apaar -> Aurick 

First, I used the command `python3 -c "import pty;pty.spawn('/bin/bash')"` to convert this ugly shell into a tty shell!

[![21](/assets/images/ChillHack/21.png)](/assets/images/ChillHack/21.png){: .full}

#### Further enum

After looking around for a while I discovered `/var/www/files`, interesting?

These contained the following files:

[![21](/assets/images/ChillHack/21-1.png)](/assets/images/ChillHack/21-1.png){: .full}

The file which really stood out to me at first glance was `index.php` which contained the below lines of code:

[![22](/assets/images/ChillHack/22.png)](/assets/images/ChillHack/22.png){: .full}

##### MySQL database dumping

The line highlighted in red looks like a connection via MySQL to the `webportal` database on localhost. Let's see if we can use these credentials to connect and extract the data via the shell.

[![23](/assets/images/ChillHack/23.png)](/assets/images/ChillHack/23.png){: .full}

[![24](/assets/images/ChillHack/24.png)](/assets/images/ChillHack/24.png){: .full}

Cool, we've got two hashes now for usernames `aurick` and `cullapaar`! Let's see if we can crack them :)

##### Hash Cracking

[![25](/assets/images/ChillHack/25.png)](/assets/images/ChillHack/25.png){: .full}

[![26](/assets/images/ChillHack/26.png)](/assets/images/ChillHack/26.png){: .full}

Nice, we've succesfully uncovered two passwords. But can we use them anywhere? No, unfortunately not :( I tried both these passwords for users: `aurick`, `anurodh` and `root` - none worked. Back to further enum!

#### Stego

After looking through contents of further files I saw this note on `hacker.php`

[![27](/assets/images/ChillHack/26-1.png)](/assets/images/ChillHack/26-1.png){: .full}

`Look in the dark! You will find your answer`, Hmmmm... this gave me the hint to consider steganography on the two files in the `/images` directory. 

[![28](/assets/images/ChillHack/26-2.png)](/assets/images/ChillHack/26-2.png){: .full}

I transferred said files by doing `cat hacker-...41.jpg | base64` and manually copying them over to my Kali machine. On my Kali machine I converted them back into real images with `echo "AADF...base64_here...adsf= | base64 --decode > photo1.jpg`

I first used `strings` & `exiftool` to see if any metadata or strings were left behind, they weren't. Then, I tried `steghide` with an empty password!

[![29](/assets/images/ChillHack/29.png)](/assets/images/ChillHack/29.png){: .full}

So... a `backup.zip` is hidden inside this photo. Attempting to unzip it reveals it's password protected, let's crack this!

[![30](/assets/images/ChillHack/30.png)](/assets/images/ChillHack/30.png){: .full}
