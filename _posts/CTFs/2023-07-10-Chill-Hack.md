---
title: "Try Hack Me: Chill Hack - detailed writeup"
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

## Initial Foothold