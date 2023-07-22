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

We can now see they are practically indistinguishable from each other. LSB stego works by encoding your text in binary, by using the last digit of the each RGB representation for however many pixels is required. This will have a barely noticeable affect on the image, although it will secretly contain a message. An astute reader may have noticed that the length of the binary plaintext encoded using LSB must be <= width (in pixels) * height (in pixels) * 3, otherwise there would simply not enough space to encode it. For this reason, it is good practice to choose an image which has fairly large dimensions.


## Python implementation   

Before getting into the encoding & execution of our payloads through steganography, let's quickly go over how to encode a plaintext message.

### Encoding

```python 
from PIL import Image
import numpy as np

def text_to_binary(text_data):
    # Convert text data to binary format
    return ''.join(format(ord(char), '08b') for char in text_data)

def encode_lsb(image_path, plaintext_data, output_path):
    image = Image.open(image_path)
    
    # Convert the image to RGB mode (if it's not already)
    image = image.convert("RGB")

    width, height = image.size
    max_data_length = (width * height) * 3  # 3 channels (RGB) per pixel

    # Convert plaintext to binary format
    binary_data = text_to_binary(plaintext_data)

    # Append a special character to mark the end of the data
    binary_data += "00000000"  # Null character '\0'

    # Check if the data can fit into the image
    data_length = len(binary_data)
    if data_length > max_data_length:
        raise ValueError("Data too large for the image.")

    # Copy image
    encoded_image = image.copy()
    binary_index = 0

    # Embed binary data into the image using LSB steganography
    for y in range(height):
        for x in range(width):
            pixel = list(image.getpixel((x, y)))
            for channel in range(3):  # 3 channels (RGB)
                if binary_index < len(binary_data):
                    # Modify the least significant bit of the pixel
                    pixel[channel] = pixel[channel] & ~1 | int(binary_data[binary_index])
                    binary_index += 1
                else:
                    break
            encoded_image.putpixel((x, y), tuple(pixel))

    # Output
    encoded_image.save(output_path)
    print("Payload encoded and image saved successfully.")
```

#### encode_lsb()

* This function takes three parameters: `image_path` (the path to the input image), `plaintext_data` (the plaintext message to be hidden), and `output_path` (the path where the encoded image will be saved).

* The next line opens the input image using the [PIL library](https://pypi.org/project/Pillow/)

