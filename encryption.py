"""
Custom AES Implementation for Educational Purposes
This module provides a basic AES encryption implementation from scratch.
"""

import os
from typing import Union, List


class AESCipher:
    """
    Custom AES encryption implementation.
    This is a simplified version for educational purposes.
    """
    
    # AES S-box (substitution box)
    S_BOX = [
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    ]
    
    # Inverse S-box for decryption
    INV_S_BOX = [
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    ]
    
    # Round constants for key expansion
    RCON = [
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
    ]
    
    def __init__(self, key: bytes):
        """
        Initialize AES cipher with a key.
        
        Args:
            key: 16, 24, or 32 byte key for AES-128, AES-192, or AES-256
        """
        if len(key) not in [16, 24, 32]:
            raise ValueError("Key must be 16, 24, or 32 bytes long")
        
        self.key = key
        self.key_size = len(key)
        self.rounds = {16: 10, 24: 12, 32: 14}[self.key_size]
        self.round_keys = self._key_expansion(key)
    
    def _sub_bytes(self, state: List[List[int]]) -> List[List[int]]:
        """Apply S-box substitution to state."""
        for i in range(4):
            for j in range(4):
                state[i][j] = self.S_BOX[state[i][j]]
        return state
    
    def _inv_sub_bytes(self, state: List[List[int]]) -> List[List[int]]:
        """Apply inverse S-box substitution to state."""
        for i in range(4):
            for j in range(4):
                state[i][j] = self.INV_S_BOX[state[i][j]]
        return state
    
    def _shift_rows(self, state: List[List[int]]) -> List[List[int]]:
        """Shift rows in the state."""
        state[1] = state[1][1:] + state[1][:1]  # Shift 1 left
        state[2] = state[2][2:] + state[2][:2]  # Shift 2 left
        state[3] = state[3][3:] + state[3][:3]  # Shift 3 left
        return state
    
    def _inv_shift_rows(self, state: List[List[int]]) -> List[List[int]]:
        """Inverse shift rows in the state."""
        state[1] = state[1][-1:] + state[1][:-1]  # Shift 1 right
        state[2] = state[2][-2:] + state[2][:-2]  # Shift 2 right
        state[3] = state[3][-3:] + state[3][:-3]  # Shift 3 right
        return state
    
    def _galois_multiply(self, a: int, b: int) -> int:
        """Multiply two numbers in GF(2^8)."""
        result = 0
        for _ in range(8):
            if b & 1:
                result ^= a
            high_bit = a & 0x80
            a <<= 1
            if high_bit:
                a ^= 0x1b
            b >>= 1
        return result & 0xff
    
    def _mix_columns(self, state: List[List[int]]) -> List[List[int]]:
        """Mix columns transformation."""
        for j in range(4):
            a = [state[i][j] for i in range(4)]
            state[0][j] = self._galois_multiply(2, a[0]) ^ self._galois_multiply(3, a[1]) ^ a[2] ^ a[3]
            state[1][j] = a[0] ^ self._galois_multiply(2, a[1]) ^ self._galois_multiply(3, a[2]) ^ a[3]
            state[2][j] = a[0] ^ a[1] ^ self._galois_multiply(2, a[2]) ^ self._galois_multiply(3, a[3])
            state[3][j] = self._galois_multiply(3, a[0]) ^ a[1] ^ a[2] ^ self._galois_multiply(2, a[3])
        return state
    
    def _inv_mix_columns(self, state: List[List[int]]) -> List[List[int]]:
        """Inverse mix columns transformation."""
        for j in range(4):
            a = [state[i][j] for i in range(4)]
            state[0][j] = (self._galois_multiply(14, a[0]) ^ self._galois_multiply(11, a[1]) ^ 
                          self._galois_multiply(13, a[2]) ^ self._galois_multiply(9, a[3]))
            state[1][j] = (self._galois_multiply(9, a[0]) ^ self._galois_multiply(14, a[1]) ^ 
                          self._galois_multiply(11, a[2]) ^ self._galois_multiply(13, a[3]))
            state[2][j] = (self._galois_multiply(13, a[0]) ^ self._galois_multiply(9, a[1]) ^ 
                          self._galois_multiply(14, a[2]) ^ self._galois_multiply(11, a[3]))
            state[3][j] = (self._galois_multiply(11, a[0]) ^ self._galois_multiply(13, a[1]) ^ 
                          self._galois_multiply(9, a[2]) ^ self._galois_multiply(14, a[3]))
        return state
    
    def _add_round_key(self, state: List[List[int]], round_key: List[int]) -> List[List[int]]:
        """Add round key to state."""
        for i in range(4):
            for j in range(4):
                state[i][j] ^= round_key[i * 4 + j]
        return state
    
    def _key_expansion(self, key: bytes) -> List[List[int]]:
        """Expand the cipher key into round keys."""
        key_words = []
        # Convert key to words
        for i in range(0, len(key), 4):
            word = list(key[i:i+4])
            key_words.append(word)
        
        # Expand key
        for i in range(len(key_words), 4 * (self.rounds + 1)):
            word = key_words[i - 1][:]
            
            if i % (self.key_size // 4) == 0:
                # Rotate word
                word = word[1:] + [word[0]]
                # Apply S-box
                word = [self.S_BOX[b] for b in word]
                # XOR with round constant
                word[0] ^= self.RCON[(i // (self.key_size // 4)) - 1]
            elif self.key_size == 32 and i % 8 == 4:
                # Additional transformation for AES-256
                word = [self.S_BOX[b] for b in word]
            
            # XOR with word from previous position
            new_word = []
            for j in range(4):
                new_word.append(word[j] ^ key_words[i - (self.key_size // 4)][j])
            key_words.append(new_word)
        
        # Convert to round keys
        round_keys = []
        for i in range(0, len(key_words), 4):
            round_key = []
            for j in range(4):
                round_key.extend(key_words[i + j])
            round_keys.append(round_key)
        
        return round_keys
    
    def _bytes_to_state(self, data: bytes) -> List[List[int]]:
        """Convert bytes to 4x4 state matrix."""
        state = [[0] * 4 for _ in range(4)]
        for i in range(16):
            state[i % 4][i // 4] = data[i]
        return state
    
    def _state_to_bytes(self, state: List[List[int]]) -> bytes:
        """Convert 4x4 state matrix to bytes."""
        data = []
        for j in range(4):
            for i in range(4):
                data.append(state[i][j])
        return bytes(data)
    
    def _pkcs7_pad(self, data: bytes, block_size: int = 16) -> bytes:
        """Apply PKCS7 padding."""
        padding_length = block_size - (len(data) % block_size)
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _pkcs7_unpad(self, data: bytes) -> bytes:
        """Remove PKCS7 padding."""
        padding_length = data[-1]
        return data[:-padding_length]
    
    def encrypt_block(self, plaintext_block: bytes) -> bytes:
        """Encrypt a single 16-byte block."""
        if len(plaintext_block) != 16:
            raise ValueError("Block must be exactly 16 bytes")
        
        state = self._bytes_to_state(plaintext_block)
        
        # Initial round key addition
        state = self._add_round_key(state, self.round_keys[0])
        
        # Main rounds
        for round_num in range(1, self.rounds):
            state = self._sub_bytes(state)
            state = self._shift_rows(state)
            state = self._mix_columns(state)
            state = self._add_round_key(state, self.round_keys[round_num])
        
        # Final round (no mix columns)
        state = self._sub_bytes(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, self.round_keys[self.rounds])
        
        return self._state_to_bytes(state)
    
    def decrypt_block(self, ciphertext_block: bytes) -> bytes:
        """Decrypt a single 16-byte block."""
        if len(ciphertext_block) != 16:
            raise ValueError("Block must be exactly 16 bytes")
        
        state = self._bytes_to_state(ciphertext_block)
        
        # Initial round key addition
        state = self._add_round_key(state, self.round_keys[self.rounds])
        
        # Main rounds (in reverse)
        for round_num in range(self.rounds - 1, 0, -1):
            state = self._inv_shift_rows(state)
            state = self._inv_sub_bytes(state)
            state = self._add_round_key(state, self.round_keys[round_num])
            state = self._inv_mix_columns(state)
        
        # Final round
        state = self._inv_shift_rows(state)
        state = self._inv_sub_bytes(state)
        state = self._add_round_key(state, self.round_keys[0])
        
        return self._state_to_bytes(state)
    
    def encrypt(self, plaintext: Union[str, bytes]) -> bytes:
        """Encrypt plaintext using CBC mode."""
        if isinstance(plaintext, str):
            plaintext = plaintext.encode('utf-8')
        
        # Generate random IV
        iv = os.urandom(16)
        
        # Pad plaintext
        padded_plaintext = self._pkcs7_pad(plaintext)
        
        # Encrypt blocks using CBC mode
        ciphertext = iv  # Prepend IV to ciphertext
        previous_block = iv
        
        for i in range(0, len(padded_plaintext), 16):
            block = padded_plaintext[i:i+16]
            # XOR with previous ciphertext block (CBC mode)
            xor_block = bytes(a ^ b for a, b in zip(block, previous_block))
            encrypted_block = self.encrypt_block(xor_block)
            ciphertext += encrypted_block
            previous_block = encrypted_block
        
        return ciphertext
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext using CBC mode."""
        if len(ciphertext) < 16:
            raise ValueError("Ciphertext too short")
        
        # Extract IV
        iv = ciphertext[:16]
        encrypted_data = ciphertext[16:]
        
        # Decrypt blocks using CBC mode
        plaintext = b''
        previous_block = iv
        
        for i in range(0, len(encrypted_data), 16):
            block = encrypted_data[i:i+16]
            decrypted_block = self.decrypt_block(block)
            # XOR with previous ciphertext block (CBC mode)
            plaintext_block = bytes(a ^ b for a, b in zip(decrypted_block, previous_block))
            plaintext += plaintext_block
            previous_block = block
        
        # Remove padding
        return self._pkcs7_unpad(plaintext)


def generate_key(key_size: int = 256) -> bytes:
    """Generate a random AES key."""
    if key_size not in [128, 192, 256]:
        raise ValueError("Key size must be 128, 192, or 256 bits")
    
    return os.urandom(key_size // 8)


def encrypt_file(file_path: str, key: bytes, output_path: str = None) -> str:
    """Encrypt a file using custom AES implementation."""
    if output_path is None:
        output_path = file_path + '.encrypted'
    
    cipher = AESCipher(key)
    
    with open(file_path, 'rb') as infile:
        plaintext = infile.read()
    
    ciphertext = cipher.encrypt(plaintext)
    
    with open(output_path, 'wb') as outfile:
        outfile.write(ciphertext)
    
    return output_path


def decrypt_file(encrypted_file_path: str, key: bytes, output_path: str = None) -> str:
    """Decrypt a file using custom AES implementation."""
    if output_path is None:
        output_path = encrypted_file_path.replace('.encrypted', '.decrypted')
    
    cipher = AESCipher(key)
    
    with open(encrypted_file_path, 'rb') as infile:
        ciphertext = infile.read()
    
    plaintext = cipher.decrypt(ciphertext)
    
    with open(output_path, 'wb') as outfile:
        outfile.write(plaintext)
    
    return output_path
