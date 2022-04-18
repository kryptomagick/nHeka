''' Orias Cipher by Karl Zander '''

class Orias:
    s0 = [11, 0, 15, 4, 19, 8, 23, 12, 1, 16, 5, 20, 9, 24, 13, 2, 17, 6, 21, 10, 25, 14, 3, 18, 7, 22]
    s0i = [1, 8, 15, 22, 3, 10, 17, 24, 5, 12, 19, 0, 7, 14, 21, 2, 9, 16, 23, 4, 11, 18, 25, 6, 13, 20]
    a0 = [21, 9, 3, 7]
    a0i = [5, 3, 9, 15]
    m0 = [16, 18, 20, 22, 24, 14, 13, 15, 17, 19, 21, 23, 25, 3, 5, 7, 9, 11, 1, 0, 2, 4, 6, 8, 10, 12]
    poly26 = (4, 23, 11)
    rk = []
    rounds = 10
    blocklen = 26
    halflen = 13
    alen = 4
    keylen = 26
    ivlen = 26
    rot = 2

    def ksa(self, key, keylen):
        ''' Load Key '''
        keys = []
        k = [0] * keylen
        for x in range(keylen):
            k[x] = ord(key[x]) - 65
        ''' Generate Round Keys '''
        for x in range(self.rounds):
            rk = [0] * self.blocklen
            for y in range(self.blocklen):
                p = ((k[y] * self.poly26[1]) * self.poly26[2] + self.poly26[1]) % 26
                rk[y] = (rk[y] + p + k[y]) % 26
                k[y] = (k[y] + rk[y]) % 26
            keys.append(rk)
        return keys

    def rotateBlock(self, block, rot):
        ''' Cyclically rotates the block '''
        for x in range(rot):
            block.append(block.pop(0))
        return block
    
    def rotateBlockBack(self, block, rot):
        ''' Cyclically rotates the block in reverse '''
        block.reverse()
        for x in range(rot):
            block.append(block.pop(0))
        block.reverse()
        return block

    def encryptBlock(self, block, keys):
        for x in range(self.rounds):
            ''' Substitute the block through the S-Box '''
            for y in range(self.blocklen):
                block[y] = self.s0[block[y]]
            ''' Rotate the block '''
            block = self.rotateBlock(block, self.rot)
            ''' Mix the block by affine multiplication '''
            for y in range(self.blocklen):
                block[y] = (block[y] * self.a0[y % self.alen]) % 26
            ''' Mix the block by a fix mix permutation '''
            for y in range(self.blocklen):
                block[y] = (block[y] + block[self.m0[y]]) % 26
            ''' Add the round key '''
            for y in range(self.blocklen):
                block[y] = (block[y] + keys[x][y]) % 26
        return block
    
    def decryptBlock(self, block, keys):
        for x in reversed(range(self.rounds)):
            ''' Subtract the round key '''
            for y in range(self.blocklen):
                block[y] = (block[y] - keys[x][y]) % 26
            ''' Apply the inverse mix permutation '''
            for y in reversed(range(self.blocklen)):
                block[y] = (block[y] - block[self.m0[y]]) % 26
            ''' Apply the inverse affine permutation '''
            for y in range(self.blocklen):
                block[y] = (block[y] * self.a0i[y % self.alen]) % 26
            ''' Rotate the block in an inverse manner '''
            block = self.rotateBlockBack(block, self.rot)
            ''' Substitute the block through the inverse S-Box '''
            for y in range(self.blocklen):
                block[y] = self.s0i[block[y]]
        return block

    def encryptCBC(self, msg, key, iv):
        ''' Count number of plaintext blocks and last block remainder '''
        blocks = int(len(msg) / self.blocklen)
        blockExtra = len(msg) % self.blocklen
        ''' Get last block padding value '''
        padding = self.blocklen - (len(msg) % self.blocklen)
        ''' Add an extra block if plaintext is not divisble by block length '''
        if padding != 0:
            blocks += 1
        c = 0
        ''' Generate round keys '''
        keys = self.ksa(key, self.keylen)
        ''' Setup numeric blank blocks to handle plaintext/ciphertext/CBC '''
        block = [0] * self.blocklen
        msgEnc = []
        lastBlock = [0] * self.ivlen
        blocklen = int(self.blocklen)
        ''' Load Initialization Vector '''
        for x in range(self.ivlen):
            lastBlock[x] = ord(iv[x]) - 65

        ''' Process plaintext blocks '''
        for x in range(blocks):
            ''' Handle Padding '''
            if x == (blocks - 1) and padding != 0:
                blocklen = blockExtra
                for z in reversed(range(blockExtra, self.blocklen)):
                    block[z] = padding

            ''' Load plaintext into block and convert to numbers '''
            for y in range(blocklen):
                block[y] = ord(msg[c]) - 65
                c += 1
            ''' Add CBC block to plaintext '''
            for y in range(self.blocklen):
                block[y] = (block[y] + lastBlock[y]) % 26
            ''' Encrypt plaintext block '''
            block = self.encryptBlock(block, keys)
            ''' Pass ciphertext block to next block encryption '''
            for y in range(self.blocklen):
                lastBlock[y] = block[y]
                msgEnc.append(chr(block[y] + 65))

        return "".join(msgEnc)
    
    def decryptCBC(self, msg, key, iv):
        ''' Count the number of ciphertext blocks '''
        blocks = int(len(msg) / self.blocklen)
        ''' Generate round keys '''
        keys = self.ksa(key, self.keylen)
        c = 0
        ''' Setup numeric blank blocks to handle plaintext/ciphertext/cbc '''
        block = [0] * self.blocklen
        msgDec = []
        lastBlock = [0] * self.ivlen
        nextBlock = [0] * self.ivlen
        blocklen = self.blocklen

        ''' Load initialization vector '''
        for x in range(self.ivlen):
            lastBlock[x] = ord(iv[x]) - 65
        
        ''' Process ciphertext blocks '''
        for x in range(blocks):
            ''' Load ciphertext block and copy it for use in next block '''
            for y in range(self.blocklen):
                block[y] = ord(msg[c]) - 65
                nextBlock[y] = block[y]
                c += 1
            ''' Decrypt ciphertext block '''
            block = self.decryptBlock(block, keys)

            ''' Subtract CBC block from plaintext '''
            for y in range(self.blocklen):
                block[y] = (block[y] - lastBlock[y]) % 26
                lastBlock[y] = nextBlock[y]

            ''' Subtract padding '''
            if x == (blocks - 1):
                pos = self.blocklen - 1
                pad = block[pos]
                padcheck = 1
                goal = self.blocklen - pad
                z = pos
                while z != goal:
                    if block[z] == pad:
                        padcheck += 1
                    z -= 1

                if padcheck == pad:
                    blocklen -= padcheck

            ''' Convert plaintext numbers to letters '''
            for y in range(blocklen):
                msgDec.append(chr(block[y] + 65))

        return "".join(msgDec)
    
    def encryptOFB(self, msg, key, iv):
        ''' Count number of plaintext blocks '''
        blocks = int(len(msg) / self.blocklen)
        ''' Count number of plaintext letters in last block '''
        blockExtra = len(msg) % self.blocklen
        ''' Generate round keys '''
        keys = self.ksa(key, keylen)
        c = 0
        ''' Setup numeric blocks for plaintext/ciphertext '''
        block = [0] * self.blocklen
        ofbBlock = [0] * self.blocklen
        msgEnc = []
        blocklen = self.blocklen
        ''' Load initialization vector '''
        for x in range(self.ivlen):
            ofbBlock[x] = ord(iv[x]) - 65

        ''' Process plaintext blocks '''
        for x in range(blocks):
            ''' Handle number of letters in last block '''
            if x == (blocks - 1) and blockExtra != 0:
                blocklen = blockExtra

            ''' Load plaintext letters as numbers '''
            for y in range(blocklen):
                block[y] = ord(msg[c]) - 65
                c += 1

            ''' Encrypt IV/OFB block '''
            ofbBlock = self.encryptBlock(ofbBlock, keys)

            ''' Add OFB block to plaintext and convert to letters '''
            for y in range(blocklen):
                block[y] = (block[y] + ofbBlock[y]) % 26
                msgEnc.append(chr(block[y] + 65))

        return "".join(msgEnc)
    
    def decryptOFB(self, msg, key, iv):
        ''' Count number of ciphertext blocks '''
        blocks = int(len(msg) / self.blocklen)
        ''' Count number of plaintext letters in last block '''
        blockExtra = len(msg) % self.blocklen
        ''' Generate round keys '''
        keys = self.ksa(key, self.keylen)
        c = 0
        ''' Setup numeric blocks for plaintext/ciphertext '''
        block = [0] * self.blocklen
        ofbBlock = [0] * self.blocklen
        msgEnc = []
        blocklen = self.blocklen
        ''' Load initialization vector into OFB block ''' 
        for x in range(self.ivlen):
            ofbBlock[x] = ord(iv[x]) - 65
 
        ''' Process ciphertext blocks '''
        for x in range(blocks):
            ''' Handle number of letters in last block '''
            if x == (blocks - 1) and blockExtra != 0:
                blocklen = blockExtra

            ''' Load ciphertext letters as numbers '''
            for y in range(blocklen):
                block[y] = ord(msg[c]) - 65
                c += 1

            ''' Encrypt IV/OFB block '''
            ofbBlock = self.encryptBlock(ofbBlock, keys)

            ''' Subtract OFB block from plaintext and convert to letters '''
            for y in range(blocklen):
                block[y] = (block[y] - ofbBlock[y]) % 26
                msgEnc.append(chr(block[y] + 65))
        return "".join(msgEnc)
