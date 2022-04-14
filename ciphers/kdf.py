from ciphers.orias import Orias

''' Orias Key Derivation function '''
''' Produces a 26 letter hash '''

class OriasKDF:
    hashlen = 26
    orias = Orias()
    iterations = 100
    
    def kdf(self, key):
        ''' Setup blank hash blocks '''
        h = [0] * self.hashlen
        t = [0] * self.hashlen
        k = []
        ''' Generate initial and temporary hash blocks '''
        for x in range(len(key)):
            tmp = ord(key[x]) - 65
            h[x] = (h[x] + tmp) % 26
            t[x] = h[x]

        ''' Convert initial hash block to letters to generate round keys '''
        for y in range(self.hashlen):
            k.append(chr(h[y] + 65))

        keys = self.orias.ksa(k, len(k))

        ''' Apply number of iterations encrypting and adding with previous block '''
        for x in range(self.iterations):
            h = self.orias.encryptBlock(h, keys)
            for y in range(self.hashlen):
                h[y] = (h[y] + t[y]) % 26
                t[y] = h[y]

        ''' Convert hash to letters '''
        ahash = []
        for y in range(self.hashlen):
            ahash.append(chr(h[y] + 65))
        return "".join(ahash)
