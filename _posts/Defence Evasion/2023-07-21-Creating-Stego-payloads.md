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
[_PyStegMalz_](https://medium.com/swlh/lsb-image-steganography-using-python-2bbbee2c69a2){: .align-caption}

The above shows the Least Significant Bit is the last bit in the 8-digit long binary number. This is called the LSB because changing it has little impact on the colour of each pixel. For example let's say we have an individual pixel with the following RGB representation. R = 11110110 (246), G = 00110111 (55), B = 10110101 (181). This gives the below colour.

[![2](/assets/images/PyStegMalz/2.png)](/assets/images/PyStegMalz/2.png){: .full}

Now let's see the impact on the colour if we change the LSB on each of the colour representations of RGB. It can now be defined like: R = 11110111 (247), G = 00110110 (54), B = 10110100 (180).

[![3](/assets/images/PyStegMalz/3.png)](/assets/images/PyStegMalz/3.png){: .full}

We can now see they are practically indistinguishable from each other. LSB stego works by encoding your text in binary, by using the last digit of the each RGB representation for however many pixels is required.   




