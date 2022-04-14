from os import path, urandom

def readmsgFile(filename):
    with open(filename, "r") as f:
        contents = f.read()
    return contents

def readmsgEncFile(filename, ivlen):
    fsize = path.getsize(filename)
    contentLen = fsize - ivlen
    with open(filename, "r") as f:
        iv = f.read(ivlen)
        contents = f.read(contentLen)
    return iv, contents

def writeFile(filename, contents):
    with open(filename, "w") as f:
        f.write(contents)

def writemsgFile(filename, contents, iv):
    with open(filename, "w") as f:
        f.write(iv)
        f.write(contents)

def stripNonAlpha(contents):
    c = []
    for x in range(len(contents)):
        char = ord(contents[x]) - 65
        if char >= 0 and char <= 25:
            c.append(chr(char + 65))
    return "".join(c)

def genIV(ivlen):
    buf = []
    while len(buf) != ivlen:
        b = ord(urandom(1))
        if (b >= 65 and b <= 90):
            buf.append(chr(b))
    return "".join(buf)
