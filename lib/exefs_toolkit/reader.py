import os
from ..common import read_chunks, Crypto
from .structures import ExeFSHdr
from .compression import BLZ

class ExeFSReader:
    def __init__(self, file):
        self.file = file

        with open(file, 'rb') as f:
            self.hdr = ExeFSHdr(f.read(0x200))
        
        files = {}
        for i in range(10):
            file_hdr = self.hdr.file_headers[i]
            if file_hdr.size:
                files[f'{file_hdr.name.decode("utf-8")}.bin'] = {
                    'size': file_hdr.size,
                    'offset': 0x200 + file_hdr.offset
                }
        self.files = files

    def extract(self, code_compressed=0):
        f = open(self.file, 'rb')
        for name, info in self.files.items():
            f.seek(info['offset'])
            g = open(name, 'wb')
            
            for data in read_chunks(f, info['size']):
                g.write(data)
            
            print(f'Extracted {name}')
            g.close()

            if name == '.code.bin' and code_compressed:
                try:
                    # Read the compressed .code.bin file
                    with open('.code.bin', 'rb') as code_file:
                        compressed_data = code_file.read()
                    
                    # Decompress using pure Python BLZ
                    decompressed_data = BLZ.decompress(compressed_data)
                    
                    # Write decompressed data
                    with open('code-decompressed.bin', 'wb') as out_file:
                        out_file.write(decompressed_data)
                    
                    print('Decompressed to code-decompressed.bin')
                except Exception as e:
                    print(f'Decompression failed: {e}')
        f.close()

    def verify(self):
        f = open(self.file, 'rb')

        hash_check = []
        hashes = [bytes(self.hdr.file_hashes[i * 0x20:(i + 1) * 0x20]) for i in range(10)]
        hashes.reverse()

        for i, (name, info) in enumerate(self.files.items()):
            f.seek(info['offset'])
            hash_check.append((name.replace('.bin', ''), Crypto.sha256(f, info['size']) == hashes[i]))

        f.close()
        print("Hashes:")
        for i in hash_check:
            print(' > {0:15} {1:4}'.format(i[0] + ':', 'GOOD' if i[1] else 'FAIL'))
