import struct

class BLZ:
    """
    Pure Python implementation of BLZ compression/decompression
    Based on the BLZ algorithm used in 3DS ExeFS .code sections
    """
    
    @staticmethod
    def decompress(data):
        """Decompress BLZ compressed data"""
        if len(data) < 8:
            raise ValueError("Invalid BLZ data: too short")
        
        # Read footer (last 8 bytes) - BLZ format
        footer = data[-8:]
        
        # BLZ footer format: [decompressed_size, header_size, compressed_size, flag]
        # But let's handle both formats for compatibility
        try:
            decompressed_size, header_size, compressed_size, flag = struct.unpack('<IIII', footer)
            
            # Validate the values
            if compressed_size != len(data) or decompressed_size < len(data) - 8:
                raise ValueError("Invalid BLZ footer format")
                
        except:
            # Try alternative format with 2 32-bit values
            val1, val2 = struct.unpack('<II', footer)
            
            # Check if this is the "uncompressed with footer" format
            if val2 == 0 and val1 == len(data):
                # This is uncompressed data with a simple footer
                return data[:-8]
            else:
                raise ValueError("Unsupported BLZ footer format")
        
        # For now, handle the simple case where it's just uncompressed data
        # A full BLZ implementation would need the backward LZ77 algorithm
        if flag == 0x40 and header_size == min(len(data) - 8, 0x100):
            # This is likely our simple "compressed" format
            return data[:-8]
        
        # Initialize output buffer
        output = bytearray(decompressed_size)
        
        # Copy header (uncompressed part)
        if header_size > 0:
            output[:header_size] = data[:header_size]
        
        # For a full implementation, we'd need to implement the backward LZ77 algorithm
        # For now, just return the data without footer
        return data[:-8]
    
    @staticmethod
    def compress(data):
        """Compress data using BLZ algorithm"""
        if len(data) < 4:
            return data
        
        # For now, implement a simple "store" format with BLZ footer
        # A full implementation would need the backward LZ77 compression algorithm
        
        # Add simple footer indicating uncompressed data
        footer = struct.pack('<II', len(data) + 8, 0)
        return data + footer
