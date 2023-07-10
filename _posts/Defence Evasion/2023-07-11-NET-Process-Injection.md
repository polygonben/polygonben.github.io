---
title: "Unmasking Defence Evasion: .NET process injection"
categories:
  - Defence Evasion
---

Over the past few days, I have been engrossed in researching various defence evasion techniques used by red team operators and APT groups. Specifically, I have been focused on finding methods to uncover the forensic artefacts left behind. This blog post will delve into the findings of my most recent endeavour: injecting processes with PowerShell and .NET assemblies to evade detection.

## Fundementals

What is managed / unmanaged code? Managed code is code that is executed in a runtime. With .NET this runtime is CLR, or the Common Language Runtime. The managed code, in a bytecode format, is then loaded into the CLR which processes and executes the program.

You can compare this to unmanaged code like C & C++ which are typically compiled and loaded into memory as a binary, which is then executed. We can use **Process Hacker 2** to locate the managed processes, highlighted in green. All the other processes will be unmanaged.

[![1](/assets/images/NETProcessInjection/1.png)](/assets/images/NETProcessInjection/1.png){: .full}

We can click & hover over this process to see more details.

[![2](/assets/images/NETProcessInjection/2.png)](/assets/images/NETProcessInjection/2.png){: .full}

The above screenshot shows ‘Process is managed (.NET)’. Let’s have a look in more detail at the DLL loaded by this managed process.

[![3](/assets/images/NETProcessInjection/3.png)](/assets/images/NETProcessInjection/3.png){: .full}

`clr.dll`  and `clrjit.dll` are the two processes that are responsible for the .NET Common Language Runtime. All managed .NET processes will load these DLLs.

## Injecting the CLR into unmanaged processes

Before I jump into this, let’s quickly go over why we should care and how this evades defences. Code executing from unmanaged Windows processes like `svchost.exe` , `WmiPrvSE.exe` , `spoolsv.exe` , `chrome.exe` ect ect, are less likely to be alerted by AVs or even EDRs as they are seen as ‘normal’ processes that will be running in a production environment. If we can inject a CLR, and the corresponding bytecode to be executed into the memory of any one of these processes we could possibly execute commands in-their-memory, without being detected as no files were ever dropped on the system. This technique of using another process to execute .NET assemblies was given the name Bring Your Own Land (BYOL) by [Nathan Kirk from Mandiant](https://www.mandiant.com/resources/blog/bring-your-own-land-novel-red-teaming-technique)

Cobalt Strike offers this post-exploitation capability with it’s `execute-assembly` feature, CLR runtime DLLs are loaded into an unmanaged processes memory along with malicious .NET assemblies to be executed. Cobalt Strike also has the `powerpick` command, this also loads a CLR into a unmanaged process and will execute a PowerShell command of the operators choice — without ever running from powershell.exe! As you will know, in Enterprise environments powershell.exe will often be restricted by application whitelisting, or monitored carefully, being able to run PowerShell commands in memory of an unmanaged process without powershell.exe ever being run becomes very powerful defence evasion mechanism.

Although I will not be demonstrating and analysing this Cobalt Strike command, the same DLLs will be loaded with both the `execute-assembly` and `powerpick` commands. Instead I will be using [EmpireProject’s PSInject](https://github.com/EmpireProject/PSInject) to inject PowerShell into an unmanaged process memory.

Before injecting, it’s important to note I am already running Sysmon with Event ID 7 ImageLoad enabled. This is one of the ways forensics artefacts can be gathered. Now let’s choose as process to inject.

[![4](/assets/images/NETProcessInjection/4.png)](/assets/images/NETProcessInjection/4.png){: .full}

Let’s inject into PID 1680, svchost.exe. Let’s use the below command from the Invoke-PSInject script.

[![5](/assets/images/NETProcessInjection/5.png)](/assets/images/NETProcessInjection/5.png){: .full}

We supply the command to be executed with Base64 encoding.

[![6](/assets/images/NETProcessInjection/6.png)](/assets/images/NETProcessInjection/6.png){: .full}

After waiting a few seconds we can notice below that svchost.exe has changed colour. Hovering over it we can now see that this process has been injected and is now a managed .NET process.

[![7](/assets/images/NETProcessInjection/7.png)](/assets/images/NETProcessInjection/7.png){: .full}

