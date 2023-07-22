---
title: "Cloaked in Pixels: Concealing Your Payloads with Steganography"
categories:
  - Defence Evasion
toc: true
---

Steganography, the art of concealing information within another photograph, video, or even a physical object, has always intrigued me. As someone deeply passionate about unique and creative defense evasion techniques, an idea sparked in my mind: Could I hide shellcode within a seemingly benign image, and then use an external script to read & execute the payload? This blog post embarks on a thrilling journey detailing the steps I took to create a POC for this very purpose.

# LSB Stego

Although there is many individual technqiues for concealing information, I choose Least Significant Bit (LSB) steganography to conceal the text from within an image. 

As you will all know, digital images are just a collection of a large number of pixels. The colour of each individual pixels is represented as a combination of different strengths of Red, Green and Blue (RGB) colours. The strength of each of the Red, Green & Blue colours is decided by a number between 0 - 255, with 255 being the strongest. In computers, these numbers are represented as 8-digit binary number.

[![1](/assets/images/PyStegMalz/1.png)](/assets/images/PyStegMalz/1.png){: .full}
[_PyStegMalz_](#https://medium.com/swlh/lsb-image-steganography-using-python-2bbbee2c69a2){: .align-caption}



