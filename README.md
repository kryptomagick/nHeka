# nHeka

A small A-Z Ciphering tool written in Python3

# Ciphers

Orias - Modern A-Z SPN block cipher (26 letter block size)
- Written to be somewhat similar to AES in overall layered design
- 26 number S-Box
- 4 letter A-Box (Affine multiplicative box)
- 26 number M-Box (Additive mixing box)

# KDF

OriasKDF - produces a 26 letter hash based on input up to 26 letters
- Based off the Orias primitive
- 
