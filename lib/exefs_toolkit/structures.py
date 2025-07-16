from ctypes import Structure, c_char, c_uint32, c_uint8

class ExeFSFileHdr(Structure):
    _fields_ = [
        ('name', c_char * 8),
        ('offset', c_uint32),
        ('size', c_uint32),
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)
    
    def __init__(self, data):
        pass

class ExeFSHdr(Structure):
    _pack_ = 1

    _fields_ = [
        ('file_headers', ExeFSFileHdr * 10),
        ('reserved', c_uint8 * 0x20),
        ('file_hashes', c_uint8 * 0x140),
    ]

    def __new__(cls, buf):
        return cls.from_buffer_copy(buf)
    
    def __init__(self, data):
        pass
