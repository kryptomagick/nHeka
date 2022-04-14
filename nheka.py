from common.common import readmsgFile, readmsgEncFile, writemsgFile, writeFile, genIV, stripNonAlpha
from ciphers.orias import Orias
from ciphers.kdf import OriasKDF
from sys import argv

algorithm = argv[1]
mode = argv[2]
infile = argv[3]
outfile = argv[4]
passphrase = argv[5]

oriaskdf = OriasKDF()

key = oriaskdf.kdf(passphrase)

orias = Orias()

if algorithm == "orias-cbc":
    if mode == "-e":
        iv = genIV(orias.ivlen)
        contents = readmsgFile(infile)
        strippedContents = stripNonAlpha(contents)
        msgEnc = orias.encryptCBC(strippedContents, key, iv)
        writemsgFile(outfile, msgEnc, iv)

    elif mode == "-d":
        iv, msg = readmsgEncFile(infile, orias.ivlen)
        strippedMsg = stripNonAlpha(msg)
        msgDec = orias.decryptCBC(strippedMsg, key, iv)
        writeFile(outfile, msgDec)

elif algorithm == "orias-ofb":
    if mode == "-e":
        iv = genIV(orias.ivlen)
        contents = readmsgFile(infile)
        strippedContents = stripNonAlpha(contents)
        msgEnc = orias.encryptOFB(strippedContents, key, iv)
        writemsgFile(outfile, msgEnc, iv)

    elif mode == "-d":
        iv, msg = readmsgEncFile(infile, orias.ivlen)
        strippedMsg = stripNonAlpha(msg)
        msgDec = orias.decryptCBC(strippedMsg, key, iv)
        writeFile(outfile, msgDec)
