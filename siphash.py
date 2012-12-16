#!/usr/bin/evn python


class SipHash:
    def __init__(self, c=2, d=4):
        self.__c = c
        self.__d = d

    def __process_message(self, message):
        self.__message = []

        length = len(message)
        for start in xrange(0, length - 8, 8):
            state = ord(message[start]) \
                | (ord(message[start + 1]) << 8)  \
                | (ord(message[start + 2]) << 16) \
                | (ord(message[start + 3]) << 24) \
                | (ord(message[start + 4]) << 32) \
                | (ord(message[start + 5]) << 40) \
                | (ord(message[start + 6]) << 48) \
                | (ord(message[start + 7]) << 56)
            self.__message.append(state)

        start = (length // 8) * 8
        state = (length % 256) << 56
        for i in range(length - start):
            state |= (ord(message[start + i]) << (i * 8))
        self.__message.append(state)

    def __SipRound(self):
        assert 0 <= self.__v0 and self.__v0 < 1 << 64
        assert 0 <= self.__v1 and self.__v1 < 1 << 64
        assert 0 <= self.__v2 and self.__v2 < 1 << 64
        assert 0 <= self.__v3 and self.__v3 < 1 << 64

        self.__v0 += self.__v1  # no need to mod 2^64 now
        self.__v2 += self.__v3
        self.__v1 = (self.__v1 << 13) | (self.__v1 >> 51)
        self.__v3 = (self.__v3 << 16) | (self.__v3 >> 48)
        self.__v1 ^= self.__v0
        self.__v3 ^= self.__v2
        self.__v0 = (self.__v0 << 32) | ((self.__v0 >> 32) & 0xffffffff)
        self.__v2 += self.__v1
        self.__v0 += self.__v3
        self.__v0 &= 0xffffffffffffffff
        self.__v1 = (self.__v1 << 17) | ((self.__v1 >> 47) & 0x1ffff)
        self.__v3 = ((self.__v3 & 0x7ffffffffff) << 21) \
            | ((self.__v3 >> 43) & 0x1fffff)
        self.__v1 ^= self.__v2
        self.__v1 &= 0xffffffffffffffff
        self.__v3 ^= self.__v0
        self.__v2 = ((self.__v2 & 0xffffffff) << 32) \
            | ((self.__v2 >> 32) & 0xffffffff)

        assert 0 <= self.__v0 and self.__v0 < 1 << 64
        assert 0 <= self.__v1 and self.__v1 < 1 << 64
        assert 0 <= self.__v2 and self.__v2 < 1 << 64
        assert 0 <= self.__v3 and self.__v3 < 1 << 64

    def auth(self, key, message):
        k0 = key & 0xffffffffffffffff
        k1 = (key >> 64) & 0xffffffffffffffff

        # initialization
        self.__v0 = k0 ^ 0x736f6d6570736575
        self.__v1 = k1 ^ 0x646f72616e646f6d
        self.__v2 = k0 ^ 0x6c7967656e657261
        self.__v3 = k1 ^ 0x7465646279746573

        self.__process_message(message)

        # compression
        for m in self.__message:
            assert 0 <= m and m < 1 << 64
            self.__v3 ^= m
            for i in range(self.__c):
                self.__SipRound()
            self.__v0 ^= m
            # print 'v', hex(self.__v0), hex(self.__v1), \
            #    hex(self.__v2), hex(self.__v3)

        # finalization
        self.__v2 ^= 0xff
        for i in range(self.__d):
            self.__SipRound()
        return self.__v0 ^ self.__v1 ^ self.__v2 ^ self.__v3


if __name__ == '__main__':
    k = 0x0f0e0d0c0b0a09080706050403020100
    m = '\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e'

    my_siphash = SipHash()

    print hex(my_siphash.auth(k, m))[2:-1]
