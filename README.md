lsbsteg
=======
[![License: MIT](http://img.shields.io/badge/license-MIT-red.svg?style=flat-square)](http://opensource.org/licenses/MIT)

lsbsteg is a small Python 3 application which embeds text messages into images
using the Least Significant Bit steganographic algorithm.

The basic idea of the algorithm is to take each individual bit of the message
and set it as the least significant bit of each component of each pixel of
the image. Usually, a pixel has Red, Green, Blue components and sometimes
an Alpha component. Because the values of these components change very little
if the least significant bit is changed, the color difference is not
particularly noticeable, if at all.

## Requirements
- **pillow**
- **pycrypto** (optional)

If you are on a Linux system, you most likely have the required dependencies
already. If you don't, they can be easily installed using pip.

```bash
sudo pip3 install -U pillow
sudo pip3 install -U pycrypto
```

If you get 'decoder not available' errors when running the application make
sure you have all the pillow dependencies installed:

```bash
sudo apt-get install libjpeg-dev zlib1g-dev
sudo pip3 install -I pillow
```

## Usage
```bash
lsbsteg.py [-h] [-v] {embed,extract} ...
```

The application can both embed messages into images and extract them.

### Embedding messages into images
```bash
lsbsteg.py embed [-h] [-o OUT] [-k KEY] IMAGE MESSAGE

positional arguments:
    IMAGE      source image
    MESSAGE    message to embed into the image

optional arguments:
    -o OUT, --output OUT    generated output image containing the specified message
    -k KEY, --key KEY       key used to encrypt the message before embedding it
```

* Note: if the output image is not provided, the message is saved in the input image.

**Without encryption**
```bash
lsbsteg.py embed -o output.png input.png "message to embed"
```

**With encryption**
```bash
lsbsteg.py embed -o output.png -k passphraze input.png "message to embed"
```

Because JPEG uses lossy compression, it cannot be specified as an output image
format.  Instead, it can be converted to a lossless compression format like
PNG even if the input image is a JPEG image.

```bash
lsbsteg.py embed -o output.png input.jpg "the message you want to embed"
```

* Note: if pycrypto is not installed, the application does not have encryption support.

### Extracting messages from images
```bash
lsbsteg.py extract [-h] [-k KEY] IMAGE

positional arguments:
    IMAGE    image containing message

optional arguments:
    -k KEY, --key KEY    key to decrypt the extracted message
```

**Without encryption**
```bash
lsbsteg.py extract output.png
```

**With encryption**
```bash
lsbsteg.py extract -k passphraze output.png
```

## License
Copyright (c) 2015 Adrian-George Bostan.

This project is licensed under the [MIT license](http://opensource.org/licenses/MIT). See LICENSE for more details.
