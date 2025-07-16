import os
from ctypes import c_uint8, sizeof
from ..common import read_chunks, Crypto, roundup, align
from .structures import ExeFSHdr
from .compression import BLZ

block_size = 0x200

class ExeFSBuilder:
    def __init__(self, exefs_dir='', code_compress=0, out='exefs.bin'):
        '''
        exefs_dir: path to directory containing files to be added to exefs (files must be named '.code.bin', 'banner.bin', 'icon.bin', 'logo.bin')
        code_compress: 0 or 1
        out: path to output file
        '''

        files = os.listdir(exefs_dir)  # Contains filenames, not paths
        files.sort()
        hdr = ExeFSHdr(b'\x00' * 0x200)

        if files[0] == '.code.bin' and code_compress == 1:
            try:
                # Read the .code.bin file
                with open(os.path.join(exefs_dir, '.code.bin'), 'rb') as code_file:
                    code_data = code_file.read()
                
                # Compress using pure Python BLZ
                compressed_data = BLZ.compress(code_data)
                
                # Write compressed data
                compressed_path = os.path.join(exefs_dir, 'code-compressed.bin')
                with open(compressed_path, 'wb') as out_file:
                    out_file.write(compressed_data)
                
                files[0] = 'code-compressed.bin'
                print('Compressed .code.bin to code-compressed.bin')
            except Exception as e:
                print(f'Compression failed: {e}')
        
        # Create ExeFS header
        hashes = []
        for i in range(len(files)):
            if files[i] == 'code-compressed.bin':
                hdr.file_headers[i].name = '.code'.encode('utf-8')
            else:
                hdr.file_headers[i].name = files[i].replace('.bin', '').encode('utf-8')
            hdr.file_headers[i].size = os.path.getsize(os.path.join(exefs_dir, files[i]))
            if i == 0:
                hdr.file_headers[i].offset = 0
            else:
                hdr.file_headers[i].offset = roundup(hdr.file_headers[i - 1].offset + hdr.file_headers[i - 1].size, block_size)
            
            f = open(os.path.join(exefs_dir, files[i]), 'rb')
            hashes.append(Crypto.sha256(f, hdr.file_headers[i].size))
            f.close()
        
        for _ in range(len(files), 10):
            hashes.append(b'\x00' * 0x20)
        hashes.reverse()
        hashes_all = b''.join(hashes)
        hdr.file_hashes = (c_uint8 * sizeof(hdr.file_hashes))(*hashes_all)

        # Write ExeFS
        f = open(out, 'wb')
        f.write(bytes(hdr))
        curr = 0x200
        for i in range(len(files)):
            g = open(os.path.join(exefs_dir, files[i]), 'rb')
            if curr < (hdr.file_headers[i].offset + 0x200):
                pad_size = hdr.file_headers[i].offset + 0x200 - curr
                f.write(b'\x00' * pad_size)
                curr += pad_size
            
            for data in read_chunks(g, hdr.file_headers[i].size):
                f.write(data)
            
            curr += hdr.file_headers[i].size
            g.close()
        
        f.write(b'\x00' * align(curr, block_size))
        f.close()
        if os.path.isfile(os.path.join(exefs_dir, 'code-compressed.bin')):
            os.remove(os.path.join(exefs_dir, 'code-compressed.bin'))
        print(f'Wrote to {out}')
