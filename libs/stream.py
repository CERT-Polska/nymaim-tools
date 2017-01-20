import StringIO
from struct import unpack


class S(StringIO.StringIO):

    
    def string(self):
        r=[]
        c=''
        while c != "\x00":
            c = self.read(1)
            r.append(c)
        return ''.join(r).strip("\x00")

    def dword(self):
        return unpack('I',self.read(4))[0]

    def word(self):
        return unpack('H',self.read(2))[0]

    def byte(self):
        return unpack('=B',self.read(1))[0]
