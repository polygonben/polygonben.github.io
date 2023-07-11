---
title: "Try Hack Me: Chill Hack, detailed writeup"
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

[![3](/assets/images/ChillHack/3.png)](/assets/images/ChillHack/3.png){: .full}

Interesting, I'm guessing this information will become useful later on in the challenge.

Let's move onto to enumerating the web service.

### HTTP 