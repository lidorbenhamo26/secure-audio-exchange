"""
Audio File I/O Handler

Provides utilities for reading and writing binary audio files
(.wav, .mp3) for encryption/decryption operations.
"""

import os
from pathlib import Path


class AudioHandler:
    """
    Handler for reading and writing audio files.
    
    Supports any binary audio format (.wav, .mp3, .flac, etc.)
    by treating files as raw binary data.
    
    Usage:
        handler = AudioHandler()
        data = handler.read('audio.wav')
        handler.write('output.wav', encrypted_data)
    """
    
    SUPPORTED_EXTENSIONS = {'.wav', '.mp3', '.flac', '.ogg', '.aac', '.m4a'}
    
    def __init__(self):
        """Initialize the audio handler."""
        pass
    
    def read(self, filepath: str) -> bytes:
        """
        Read an audio file as binary data.
        
        Args:
            filepath: Path to the audio file
            
        Returns:
            Raw bytes of the audio file
            
        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If file extension is not supported
        """
        path = Path(filepath)
        
        if not path.exists():
            raise FileNotFoundError(f"Audio file not found: {filepath}")
        
        # Warn if extension is not typical audio format
        ext = path.suffix.lower()
        if ext not in self.SUPPORTED_EXTENSIONS:
            print(f"Warning: '{ext}' is not a typical audio extension")
        
        with open(filepath, 'rb') as f:
            data = f.read()
        
        return data
    
    def write(self, filepath: str, data: bytes) -> int:
        """
        Write binary data to a file.
        
        Args:
            filepath: Output file path
            data: Binary data to write
            
        Returns:
            Number of bytes written
        """
        # Ensure parent directory exists
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(filepath, 'wb') as f:
            bytes_written = f.write(data)
        
        return bytes_written
    
    def get_file_info(self, filepath: str) -> dict:
        """
        Get basic file information.
        
        Args:
            filepath: Path to the audio file
            
        Returns:
            Dictionary with file metadata
        """
        path = Path(filepath)
        
        if not path.exists():
            raise FileNotFoundError(f"File not found: {filepath}")
        
        stat = path.stat()
        
        return {
            'filename': path.name,
            'extension': path.suffix.lower(),
            'size_bytes': stat.st_size,
            'size_kb': stat.st_size / 1024,
            'size_mb': stat.st_size / (1024 * 1024),
            'path': str(path.absolute())
        }
    
    def validate_audio_format(self, data: bytes) -> dict:
        """
        Basic validation of audio format by checking magic bytes.
        
        Args:
            data: Binary audio data
            
        Returns:
            Dictionary with format information
        """
        info = {'format': 'unknown', 'valid': False}
        
        if len(data) < 12:
            return info
        
        # WAV: RIFF header
        if data[:4] == b'RIFF' and data[8:12] == b'WAVE':
            info['format'] = 'WAV'
            info['valid'] = True
        
        # MP3: ID3 tag or frame sync
        elif data[:3] == b'ID3' or (data[0] == 0xFF and (data[1] & 0xE0) == 0xE0):
            info['format'] = 'MP3'
            info['valid'] = True
        
        # FLAC
        elif data[:4] == b'fLaC':
            info['format'] = 'FLAC'
            info['valid'] = True
        
        # OGG
        elif data[:4] == b'OggS':
            info['format'] = 'OGG'
            info['valid'] = True
        
        return info
    
    def write_as_wav(self, filepath: str, data: bytes, 
                     sample_rate: int = 44100, 
                     channels: int = 2, 
                     bits_per_sample: int = 16) -> int:
        """
        Write binary data as a valid WAV file.
        
        This allows encrypted data to be played by audio players
        (it will sound like noise/static).
        
        Args:
            filepath: Output file path (should end with .wav)
            data: Binary data to write as audio samples
            sample_rate: Sample rate in Hz (default: 44100)
            channels: Number of channels (1=mono, 2=stereo)
            bits_per_sample: Bits per sample (default: 16)
            
        Returns:
            Number of bytes written
        """
        import struct
        
        # Ensure parent directory exists
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        # Store original data size (4 bytes) at the beginning so we can recover exact bytes
        original_size = len(data)
        size_header = original_size.to_bytes(4, 'little')
        data_with_size = size_header + data
        
        # Pad data to align with sample size
        bytes_per_sample = bits_per_sample // 8 * channels
        padding_needed = len(data_with_size) % bytes_per_sample
        if padding_needed:
            data_with_size = data_with_size + b'\x00' * (bytes_per_sample - padding_needed)
        
        data_size = len(data_with_size)
        byte_rate = sample_rate * channels * bits_per_sample // 8
        block_align = channels * bits_per_sample // 8
        
        # Build WAV header (44 bytes)
        wav_header = struct.pack(
            '<4sI4s4sIHHIIHH4sI',
            b'RIFF',                    # ChunkID
            data_size + 36,             # ChunkSize (file size - 8)
            b'WAVE',                    # Format
            b'fmt ',                    # Subchunk1ID
            16,                         # Subchunk1Size (16 for PCM)
            1,                          # AudioFormat (1 = PCM)
            channels,                   # NumChannels
            sample_rate,                # SampleRate
            byte_rate,                  # ByteRate
            block_align,                # BlockAlign
            bits_per_sample,            # BitsPerSample
            b'data',                    # Subchunk2ID
            data_size                   # Subchunk2Size
        )
        
        with open(filepath, 'wb') as f:
            f.write(wav_header)
            bytes_written = f.write(data_with_size)
        
        return bytes_written + 44  # data + header
