#!/usr/bin/env python3
import sys
import argparse
import hashlib
from PIL import Image

# check if encryption module is available
encryption_support = True
try:
    from Crypto import Random
    from Crypto.Cipher import AES
except ImportError:
    encryption_support = False

# size of hash in bytes
HASH_SIZE = 32
# length of field storing size information
SIZE_FIELD_LEN = 64


# function to convert an integer to a list of bits
def bits_from_int(i, width=1):
    bits = bin(i)[2:].zfill(width)
    return [int(b) for b in bits]


# function to convert a string to a list of bits
def bits_from_str(s):
    return bits_from_bytes(s.encode('utf-8'))


# function to convert a list of bytes to a list of bits
def bits_from_bytes(bytes):
    bits = []
    for b in bytes:
        bits.extend([((b >> i) & 1) for i in range(7, -1, -1)])

    return bits


# function to convert a list of bits to a list of bytes
def bytes_from_bits(bits):
    bytes = []

    lenBits = len(bits)
    for i in range(0, lenBits, 8):
        byte = bits[i:i+8]
        bytes.append(sum([(byte[8-b-1] << b) for b in range(7, -1, -1)]))

    return bytes


# function to set a specific bit in a target integer to a given value
def set_bit(target, index, value):
    mask = 1 << index
    target &= ~mask
    return target | mask if value else target


# function to pad a message for use with AES encryption
def aes_pad(msg):
    pad_len = AES.block_size - (len(msg) % AES.block_size)
    return msg + pad_len * chr(pad_len)


# function to remove padding from an AES encrypted message
def aes_unpad(msg):
    return msg[:-msg[-1]]


# function to encrypt a message using AES with a given passphrase
def encrypt(msg, passphraze):
    passphraze = hashlib.sha256(bytes(passphraze, 'utf-8')).digest()

    hash = hashlib.sha256(bytes(msg, 'utf-8')).digest()
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(passphraze, AES.MODE_CBC, iv)

    return hash + iv + cipher.encrypt(aes_pad(msg))


# function to decrypt a message using AES with a given passphrase
def decrypt(msg, passphraze):
    passphraze = hashlib.sha256(bytes(passphraze, 'utf-8')).digest()

    hash = msg[:HASH_SIZE]
    iv = msg[HASH_SIZE:HASH_SIZE+AES.block_size]

    cipher = AES.new(passphraze, AES.MODE_CBC, iv)
    msg = aes_unpad(cipher.decrypt(msg[HASH_SIZE+AES.block_size:]))

    return msg, hash == hashlib.sha256(msg).digest()


def embed_message(bits, img):
    # get image pixels, size, and number of pixel components
    pixels = img.load()
    width, height = img.size
    pixel_comps = len(pixels[0, 0])

    # add padding to the size field if necessary
    padding = []
    if SIZE_FIELD_LEN % pixel_comps != 0:
        padding = (pixel_comps - SIZE_FIELD_LEN % pixel_comps) * [0]

    # add size field and padding to the message bits
    bits = bits_from_int(len(bits), SIZE_FIELD_LEN) + padding + bits
    # check if message is too long to be embedded in the image
    if len(bits) > width * height * pixel_comps:
        raise Exception('The message you are trying to embed is too long')

    # iterate through image pixels and embed message bits
    bits = iter(bits)
    for x in range(width):
        for y in range(height):
            pixel = list(pixels[x, y])
            for i, b in enumerate(pixel):
                bit = next(bits, None)
                if bit is None:
                    # set modified pixel values and return
                    pixels[x, y] = tuple(pixel)
                    return

                # set least significant bit of pixel component to message bit
                pixel[i] = set_bit(b, 0, bit)

            # set modified pixel values
            pixels[x, y] = tuple(pixel)


def extract_length(pixels, width, height):
    # initialize list of bits
    bits = []
    # iterate through image pixels
    for x in range(width):
        for y in range(height):
            # check if size field is complete
            if len(bits) >= SIZE_FIELD_LEN:
                # convert size field to integer and return with current pixel coordinates
                return int(''.join(map(str, bits[:SIZE_FIELD_LEN])), 2), x, y

            # add least significant bits of pixel components to list of bits
            pixel = list(pixels[x, y])
            bits.extend([(b & 1) for b in pixel])


def extract_message(img):
    # get image pixels, size, and message length
    pixels = img.load()
    width, height = img.size
    length, offset_x, offset_y = extract_length(pixels, width, height)

    # initialize list of bits
    bits = []
    # iterate through image pixels starting at the offset
    for x in range(offset_x, width):
        for y in range(offset_y, height):
            # add least significant bits of pixel components to list of bits
            pixel = list(pixels[x, y])
            for b in pixel:
                if len(bits) == length:
                    # convert bits to bytes and return as message
                    return bytes(bytes_from_bits(bits))

                bits.append(b & 1)


def embed(args, image):
    # initialize list of message bits
    bits = []
    if hasattr(args, 'key'):
        # encrypt message if key is provided
        bits = bits_from_bytes(encrypt(args.message, args.key))
    else:
        # otherwise, convert message string to bits
        bits = bits_from_str(args.message)

    # embed message bits in the image
    embed_message(bits, image)
    # save modified image
    image.save(args.output if args.output else args.image)


def extract(args, image):
    # extract message from the image
    message = extract_message(image)

    if hasattr(args, 'key'):
        # decrypt message if key is provided
        message, ok = decrypt(message, args.key)
        if not ok:
            raise Exception('Could not decrypt message with the provided key')

    # print decrypted message
    print(message.decode('utf-8'))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog=sys.argv[0])
    subparsers = parser.add_subparsers(help='actions')
    parser.add_argument('-v', '--version', help='show version info and exit',
                        version='%(prog)s 0.1', action='version')

    # embed subparser
    em = subparsers.add_parser('embed', help='embed message into image')
    em.add_argument('image', metavar='IMAGE', help='source image')
    em.add_argument('message', metavar='MESSAGE', help='message to embed')
    em.add_argument('-o', '--output', metavar='OUT', help='output image')
    em.set_defaults(func=embed)

    # extract subparser
    ex = subparsers.add_parser('extract', help='extract message from image')
    ex.add_argument('image', metavar='IMAGE', help='image containing message')
    ex.set_defaults(func=extract)

    if encryption_support:
        em.add_argument('-k', '--key', metavar='KEY', help='encryption key')
        ex.add_argument('-k', '--key', metavar='KEY', help='decryption key')

    args = parser.parse_args()

    try:
        image = Image.open(args.image)
    except:
        sys.exit('Could not open source image')

    if image.mode in ['1', '1;I', '1;R']:
        sys.exit('Cannot embed messages in black and white images')
    if image.mode == 'P':
        sys.exit('Cannot embed messages in palette-mapped image')

    try:
        args.func(args, image)
    except Exception as e:
        sys.exit(e)
