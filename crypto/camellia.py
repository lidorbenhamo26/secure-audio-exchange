"""
Camellia Cipher Implementation (128-bit key, OFB mode)

RFC 3713: A Description of the Camellia Encryption Algorithm
https://tools.ietf.org/html/rfc3713

NO external crypto libraries used. Only standard library.
"""

from .utils import rotate_left_32, rotate_left_64, xor_bytes, secure_random_bytes


# =============================================================================
# CAMELLIA S-BOXES
# =============================================================================

# Primary S-box (SBOX1) - 256 entries
SBOX1 = [
    112, 130,  44, 236, 179,  39, 192, 229, 228, 133,  87,  53, 234,  12, 174,  65,
     35, 239, 107, 147,  69,  25, 165,  33, 237,  14,  79,  78,  29, 101, 146, 189,
    134, 184, 175, 143, 124, 235,  31, 206,  62,  48, 220,  95,  94, 197,  11,  26,
    166, 225,  57, 202, 213,  71,  93,  61, 217,   1,  90, 214,  81,  86, 108,  77,
    139,  13, 154, 102, 251, 204, 176,  45, 116,  18,  43,  32, 240, 177, 132, 153,
    223,  76, 203, 194,  52, 126, 118,   5, 109, 183, 169,  49, 209,  23,   4, 215,
     20,  88,  58,  97, 222,  27,  17,  28,  50,  15, 156,  22,  83,  24, 242,  34,
    254,  68, 207, 178, 195, 181, 122, 145,  36,   8, 232, 168,  96, 252, 105,  80,
    170, 208, 160, 125, 161, 137,  98, 151,  84,  91,  30, 149, 224, 255, 100, 210,
     16, 196,   0,  72, 163, 247, 117, 219, 138,   3, 230, 218,   9,  63, 221, 148,
    135,  92, 131,   2, 205,  74, 144,  51, 115, 103, 246, 243, 157, 127, 191, 226,
     82, 155, 216,  38, 200,  55, 198,  59, 129, 150, 111,  75,  19, 190,  99,  46,
    233, 121, 167, 140, 159, 110, 188, 142,  41, 245, 249, 182,  47, 253, 180,  89,
    120, 152,   6, 106, 231,  70, 113, 186, 212,  37, 171,  66, 136, 162, 141, 250,
    114,   7, 185,  85, 248, 238, 172,  10,  54,  73,  42, 104,  60,  56, 241, 164,
     64,  40, 211, 123, 187, 201,  67, 193,  21, 227, 173, 244, 119, 199, 128, 158
]

# Derived S-boxes via bit rotation
SBOX2 = [((x << 1) | (x >> 7)) & 0xFF for x in SBOX1]  # Left rotate by 1
SBOX3 = [((x << 7) | (x >> 1)) & 0xFF for x in SBOX1]  # Right rotate by 1
SBOX4 = [SBOX1[((i << 1) | (i >> 7)) & 0xFF] for i in range(256)]  # SBOX1 with rotated input


# =============================================================================
# SIGMA CONSTANTS (Key Schedule)
# =============================================================================

SIGMA = [
    0xA09E667F3BCC908B,
    0xB67AE8584CAA73B2,
    0xC6EF372FE94F82BE,
    0x54FF53A5F1D36F1C,
    0x10E527FADE682D1D,
    0xB05688C2B3E6C1FD
]

MASK64 = 0xFFFFFFFFFFFFFFFF
MASK128 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF


class Camellia:
    """
    Camellia-128 block cipher with OFB mode support.
    
    Usage:
        cipher = Camellia(key_bytes)       # 16-byte key
        ciphertext = cipher.encrypt_ofb(plaintext, iv)
        plaintext = cipher.decrypt_ofb(ciphertext, iv)
    """
    
    BLOCK_SIZE = 16  # 128 bits
    KEY_SIZE = 16    # 128 bits
    NUM_ROUNDS = 18  # For 128-bit key
    
    def __init__(self, key: bytes):
        """
        Initialize Camellia cipher with a 128-bit key.
        
        Args:
            key: 16-byte key material
        """
        if len(key) != self.KEY_SIZE:
            raise ValueError(f"Key must be exactly {self.KEY_SIZE} bytes")
        
        self._key = key
        self._subkeys = self._key_schedule(key)
    
    # =========================================================================
    # KEY SCHEDULE
    # =========================================================================
    
    def _key_schedule(self, key: bytes) -> dict:
        """
        Generate all subkeys for Camellia-128.
        
        For 128-bit keys:
        - 4 whitening keys (kw1-kw4)
        - 18 round keys (k1-k18)  
        - 4 FL/FL^-1 keys (ke1-ke4)
        
        Returns:
            dict with 'kw', 'k', 'ke' arrays
        """
        # Convert key to 128-bit integer
        KL = int.from_bytes(key, 'big')
        
        # Generate KA using F-function iterations
        KA = self._generate_ka(KL)
        
        # Generate subkeys from rotations of KL and KA
        subkeys = self._generate_subkeys(KL, KA)
        
        return subkeys
    
    def _generate_ka(self, KL: int) -> int:
        """
        Generate KA from KL for 128-bit key schedule.
        Uses SIGMA constants and F-function.
        """
        # Split KL into high and low 64-bit halves
        D1 = (KL >> 64) & MASK64
        D2 = KL & MASK64
        
        # Initial XOR with SIGMA
        D2 = D2 ^ self._f_function(D1 ^ SIGMA[0], SIGMA[1])
        D1 = D1 ^ self._f_function(D2, SIGMA[0])
        
        # XOR with original KL halves
        D1 = D1 ^ ((KL >> 64) & MASK64)
        D2 = D2 ^ (KL & MASK64)
        
        # Second round of F-function
        D2 = D2 ^ self._f_function(D1 ^ SIGMA[2], SIGMA[3])
        D1 = D1 ^ self._f_function(D2, SIGMA[2])
        
        # Combine to form KA
        KA = ((D1 & MASK64) << 64) | (D2 & MASK64)
        return KA
    
    def _rotate_128(self, x: int, n: int) -> int:
        """Rotate a 128-bit value left by n bits."""
        n = n % 128
        return ((x << n) | (x >> (128 - n))) & MASK128
    
    def _generate_subkeys(self, KL: int, KA: int) -> dict:
        """
        Generate all subkeys from KL and KA via rotations.
        
        Key schedule for 128-bit Camellia (from RFC 3713):
        kw1, kw2 = KL
        k1, k2 = KA
        k3, k4 = KL <<< 15
        k5, k6 = KA <<< 15
        ke1, ke2 = KA <<< 30
        k7, k8 = KL <<< 45
        k9 = KA <<< 45 (high)
        k10, k11 = KL <<< 60
        k12 = KA <<< 60 (low)
        ke3, ke4 = KL <<< 77
        k13, k14 = KL <<< 94
        k15, k16 = KA <<< 94
        k17, k18 = KL <<< 111
        kw3, kw4 = KA <<< 111
        """
        subkeys = {
            'kw': [0] * 4,   # Whitening keys (kw1-kw4)
            'k': [0] * 18,   # Round keys (k1-k18)
            'ke': [0] * 4    # FL/FL^-1 keys (ke1-ke4)
        }
        
        # Whitening keys (pre-whitening)
        subkeys['kw'][0] = (KL >> 64) & MASK64
        subkeys['kw'][1] = KL & MASK64
        
        # Round keys and FL keys from rotations
        # k1, k2 from KA
        subkeys['k'][0] = (KA >> 64) & MASK64
        subkeys['k'][1] = KA & MASK64
        
        # k3, k4 from KL <<< 15
        KL_15 = self._rotate_128(KL, 15)
        subkeys['k'][2] = (KL_15 >> 64) & MASK64
        subkeys['k'][3] = KL_15 & MASK64
        
        # k5, k6 from KA <<< 15
        KA_15 = self._rotate_128(KA, 15)
        subkeys['k'][4] = (KA_15 >> 64) & MASK64
        subkeys['k'][5] = KA_15 & MASK64
        
        # ke1, ke2 from KA <<< 30
        KA_30 = self._rotate_128(KA, 30)
        subkeys['ke'][0] = (KA_30 >> 64) & MASK64
        subkeys['ke'][1] = KA_30 & MASK64
        
        # k7, k8 from KL <<< 45
        KL_45 = self._rotate_128(KL, 45)
        subkeys['k'][6] = (KL_45 >> 64) & MASK64
        subkeys['k'][7] = KL_45 & MASK64
        
        # k9 from KA <<< 45 (high), k10 from KL <<< 60 (high)
        KA_45 = self._rotate_128(KA, 45)
        subkeys['k'][8] = (KA_45 >> 64) & MASK64
        
        KL_60 = self._rotate_128(KL, 60)
        subkeys['k'][9] = (KL_60 >> 64) & MASK64
        subkeys['k'][10] = KL_60 & MASK64
        
        # k12 from KA <<< 60 (low)
        KA_60 = self._rotate_128(KA, 60)
        subkeys['k'][11] = KA_60 & MASK64
        
        # ke3, ke4 from KL <<< 77
        KL_77 = self._rotate_128(KL, 77)
        subkeys['ke'][2] = (KL_77 >> 64) & MASK64
        subkeys['ke'][3] = KL_77 & MASK64
        
        # k13, k14 from KL <<< 94
        KL_94 = self._rotate_128(KL, 94)
        subkeys['k'][12] = (KL_94 >> 64) & MASK64
        subkeys['k'][13] = KL_94 & MASK64
        
        # k15, k16 from KA <<< 94
        KA_94 = self._rotate_128(KA, 94)
        subkeys['k'][14] = (KA_94 >> 64) & MASK64
        subkeys['k'][15] = KA_94 & MASK64
        
        # k17, k18 from KL <<< 111
        KL_111 = self._rotate_128(KL, 111)
        subkeys['k'][16] = (KL_111 >> 64) & MASK64
        subkeys['k'][17] = KL_111 & MASK64
        
        # Post-whitening keys (kw3, kw4) from KA <<< 111
        KA_111 = self._rotate_128(KA, 111)
        subkeys['kw'][2] = (KA_111 >> 64) & MASK64
        subkeys['kw'][3] = KA_111 & MASK64
        
        return subkeys
    
    # =========================================================================
    # F-FUNCTION
    # =========================================================================
    
    def _f_function(self, x: int, k: int) -> int:
        """
        Camellia F-function.
        
        1. XOR input with subkey
        2. Split into 8 bytes, apply S-boxes
        3. Apply P-function (linear mixing)
        4. Combine back to 64-bit output
        
        Args:
            x: 64-bit input
            k: 64-bit subkey
            
        Returns:
            64-bit output
        """
        x ^= k
        
        # Split into 8 bytes and apply S-boxes
        t = [
            SBOX1[(x >> 56) & 0xFF],
            SBOX2[(x >> 48) & 0xFF],
            SBOX3[(x >> 40) & 0xFF],
            SBOX4[(x >> 32) & 0xFF],
            SBOX2[(x >> 24) & 0xFF],
            SBOX3[(x >> 16) & 0xFF],
            SBOX4[(x >> 8) & 0xFF],
            SBOX1[x & 0xFF]
        ]
        
        # P-function: Linear transformation (MDS-like mixing)
        y = [0] * 8
        y[0] = t[0] ^ t[2] ^ t[3] ^ t[5] ^ t[6] ^ t[7]
        y[1] = t[0] ^ t[1] ^ t[3] ^ t[4] ^ t[6] ^ t[7]
        y[2] = t[0] ^ t[1] ^ t[2] ^ t[4] ^ t[5] ^ t[7]
        y[3] = t[1] ^ t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[6]
        y[4] = t[0] ^ t[1] ^ t[5] ^ t[6] ^ t[7]
        y[5] = t[1] ^ t[2] ^ t[4] ^ t[6] ^ t[7]
        y[6] = t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[7]
        y[7] = t[0] ^ t[3] ^ t[4] ^ t[5] ^ t[6]
        
        # Combine bytes to 64-bit output
        return int.from_bytes(bytes(y), 'big')
    
    # =========================================================================
    # FL / FL^-1 FUNCTIONS
    # =========================================================================
    
    def _fl(self, x: int, ke: int) -> int:
        """
        FL function for inter-round mixing.
        
        xr' = xr XOR (ROL1(xl AND kl))
        xl' = xl XOR (xr' OR kr)
        """
        xl = (x >> 32) & 0xFFFFFFFF
        xr = x & 0xFFFFFFFF
        kl = (ke >> 32) & 0xFFFFFFFF
        kr = ke & 0xFFFFFFFF
        
        xr ^= rotate_left_32(xl & kl, 1)
        xl ^= (xr | kr)
        
        return ((xl << 32) | xr) & MASK64
    
    def _fl_inv(self, y: int, ke: int) -> int:
        """
        Inverse FL function.
        
        yl' = yl XOR (yr OR kr)
        yr' = yr XOR (ROL1(yl' AND kl))
        """
        yl = (y >> 32) & 0xFFFFFFFF
        yr = y & 0xFFFFFFFF
        kl = (ke >> 32) & 0xFFFFFFFF
        kr = ke & 0xFFFFFFFF
        
        yl ^= (yr | kr)
        yr ^= rotate_left_32(yl & kl, 1)
        
        return ((yl << 32) | yr) & MASK64
    
    # =========================================================================
    # BLOCK ENCRYPTION/DECRYPTION
    # =========================================================================
    
    def encrypt_block(self, block: bytes) -> bytes:
        """
        Encrypt a single 128-bit block.
        
        Structure for 128-bit key (18 rounds):
        - Pre-whitening: XOR with kw1, kw2
        - Rounds 1-6: F-function with k1-k6
        - FL/FL^-1 layer with ke1, ke2
        - Rounds 7-12: F-function with k7-k12
        - FL/FL^-1 layer with ke3, ke4
        - Rounds 13-18: F-function with k13-k18
        - Post-whitening: XOR with kw3, kw4
        
        Args:
            block: 16-byte plaintext block
            
        Returns:
            16-byte ciphertext block
        """
        if len(block) != self.BLOCK_SIZE:
            raise ValueError(f"Block must be exactly {self.BLOCK_SIZE} bytes")
        
        # Split block into L and R (64-bit each)
        L = int.from_bytes(block[:8], 'big')
        R = int.from_bytes(block[8:], 'big')
        
        # Pre-whitening
        L ^= self._subkeys['kw'][0]
        R ^= self._subkeys['kw'][1]
        
        # Rounds 1-6
        for i in range(6):
            if i % 2 == 0:
                R ^= self._f_function(L, self._subkeys['k'][i])
            else:
                L ^= self._f_function(R, self._subkeys['k'][i])
        
        # FL/FL^-1 layer 1
        L = self._fl(L, self._subkeys['ke'][0])
        R = self._fl_inv(R, self._subkeys['ke'][1])
        
        # Rounds 7-12
        for i in range(6, 12):
            if i % 2 == 0:
                R ^= self._f_function(L, self._subkeys['k'][i])
            else:
                L ^= self._f_function(R, self._subkeys['k'][i])
        
        # FL/FL^-1 layer 2
        L = self._fl(L, self._subkeys['ke'][2])
        R = self._fl_inv(R, self._subkeys['ke'][3])
        
        # Rounds 13-18
        for i in range(12, 18):
            if i % 2 == 0:
                R ^= self._f_function(L, self._subkeys['k'][i])
            else:
                L ^= self._f_function(R, self._subkeys['k'][i])
        
        # Final swap and post-whitening
        R ^= self._subkeys['kw'][2]
        L ^= self._subkeys['kw'][3]
        
        # Combine (note: swap L and R for output)
        return int.to_bytes(R, 8, 'big') + int.to_bytes(L, 8, 'big')
    
    def decrypt_block(self, block: bytes) -> bytes:
        """
        Decrypt a single 128-bit block.
        Uses same structure as encryption but with reversed key order.
        
        Args:
            block: 16-byte ciphertext block
            
        Returns:
            16-byte plaintext block
        """
        if len(block) != self.BLOCK_SIZE:
            raise ValueError(f"Block must be exactly {self.BLOCK_SIZE} bytes")
        
        # Split block (reversed from encryption output)
        R = int.from_bytes(block[:8], 'big')
        L = int.from_bytes(block[8:], 'big')
        
        # Pre-whitening (reversed)
        R ^= self._subkeys['kw'][2]
        L ^= self._subkeys['kw'][3]
        
        # Rounds 18-13 (reversed)
        for i in range(17, 11, -1):
            if i % 2 == 1:
                L ^= self._f_function(R, self._subkeys['k'][i])
            else:
                R ^= self._f_function(L, self._subkeys['k'][i])
        
        # FL/FL^-1 layer 2 (inversed)
        R = self._fl(R, self._subkeys['ke'][3])
        L = self._fl_inv(L, self._subkeys['ke'][2])
        
        # Rounds 12-7 (reversed)
        for i in range(11, 5, -1):
            if i % 2 == 1:
                L ^= self._f_function(R, self._subkeys['k'][i])
            else:
                R ^= self._f_function(L, self._subkeys['k'][i])
        
        # FL/FL^-1 layer 1 (inversed)
        R = self._fl(R, self._subkeys['ke'][1])
        L = self._fl_inv(L, self._subkeys['ke'][0])
        
        # Rounds 6-1 (reversed)
        for i in range(5, -1, -1):
            if i % 2 == 1:
                L ^= self._f_function(R, self._subkeys['k'][i])
            else:
                R ^= self._f_function(L, self._subkeys['k'][i])
        
        # Post-whitening (reversed)
        L ^= self._subkeys['kw'][0]
        R ^= self._subkeys['kw'][1]
        
        return int.to_bytes(L, 8, 'big') + int.to_bytes(R, 8, 'big')
    
    # =========================================================================
    # OFB MODE
    # =========================================================================
    
    def encrypt_ofb(self, plaintext: bytes, iv: bytes = None) -> tuple:
        """
        Encrypt data using OFB (Output Feedback) mode.
        
        OFB mode turns block cipher into stream cipher:
        - O_i = E_K(O_{i-1}), O_0 = IV
        - C_i = P_i XOR O_i
        
        Benefits for audio:
        - No error propagation
        - Pre-computable keystream
        - No padding required
        
        Args:
            plaintext: Data to encrypt (any length)
            iv: 16-byte initialization vector (generated if None)
            
        Returns:
            (ciphertext, iv) tuple
        """
        if iv is None:
            iv = secure_random_bytes(self.BLOCK_SIZE)
        elif len(iv) != self.BLOCK_SIZE:
            raise ValueError(f"IV must be exactly {self.BLOCK_SIZE} bytes")
        
        ciphertext = bytearray()
        output_block = iv
        
        for i in range(0, len(plaintext), self.BLOCK_SIZE):
            # Generate keystream block
            output_block = self.encrypt_block(output_block)
            
            # XOR with plaintext chunk
            chunk = plaintext[i:i + self.BLOCK_SIZE]
            encrypted_chunk = xor_bytes(chunk, output_block[:len(chunk)])
            ciphertext.extend(encrypted_chunk)
        
        return bytes(ciphertext), iv
    
    def decrypt_ofb(self, ciphertext: bytes, iv: bytes) -> bytes:
        """
        Decrypt data using OFB mode.
        
        OFB decryption is identical to encryption:
        - O_i = E_K(O_{i-1}), O_0 = IV
        - P_i = C_i XOR O_i
        
        Args:
            ciphertext: Encrypted data
            iv: 16-byte initialization vector (same as encryption)
            
        Returns:
            Decrypted plaintext
        """
        # OFB decryption is the same as encryption
        plaintext, _ = self.encrypt_ofb(ciphertext, iv)
        return plaintext
    
    @staticmethod
    def generate_iv() -> bytes:
        """Generate a random 128-bit IV for OFB mode."""
        return secure_random_bytes(Camellia.BLOCK_SIZE)
