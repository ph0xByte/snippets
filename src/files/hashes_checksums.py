# TODO: Add argon2 hash
# TODO: Add colorama for output

import hashlib
import crcmod.predefined
from typing import Union, Any


file_path = "path/to/file"


class DynamicHashes:
    @staticmethod
    def calculate_file_hash(file_path: str, algorithm: str, shake_length: int = 64) -> Union[str, None]:
        """
        Generate the hash of a file using the specified algorithm.
        Args:
            file_path (str): Path to the file to be hashed.
            algorithm (str): Hashing algorithm to use.
            shake_length (int, optional): Length of the digest for shake algorithms. Default is 64.
        Returns:
            str: Hexadecimal hash string if successful.
            None: If the algorithm is not available or an error occurs.
        """

        if algorithm not in hashlib.algorithms_available:
            return f'Algorithm {algorithm} not available'
        if algorithm not in hashlib.algorithms_guaranteed:
            return f'Algorithm {algorithm} not guaranteed to be supported on all platforms'

        try:
            hash_func = getattr(hashlib, algorithm)()
        except AttributeError as e:
            return str(e)

        try:
            with open(file_path, 'rb') as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    hash_func.update(byte_block)
                    
            if algorithm.startswith('shake_'):
                return hash_func.hexdigest(shake_length)
            else:
                return hash_func.hexdigest()
        
        except (TypeError, ValueError, IOError) as e:
            return str(e)


class ExplicitHashes:
    @staticmethod
    def hash_file_sha3_256(file_path: str) -> str:
        """
        Generate a SHA3-256 hash of the specified file.
        
        Args:
            file_path (str): Path to the file to be hashed.
        
        Returns:
            str: Hexadecimal SHA3-256 hash string.
        """
        return ExplicitHashes._hash_file(file_path, hashlib.sha3_256())

    @staticmethod
    def hash_file_sha224(file_path: str) -> str:
        """
        Generate a SHA-224 hash of the specified file.
        
        Args:
            file_path (str): Path to the file to be hashed.
        
        Returns:
            str: Hexadecimal SHA-224 hash string.
        """
        return ExplicitHashes._hash_file(file_path, hashlib.sha224())

    @staticmethod
    def hash_file_blake2b(file_path: str) -> str:
        """
        Generate a BLAKE2b hash of the specified file.
        
        Args:
            file_path (str): Path to the file to be hashed.
        
        Returns:
            str: Hexadecimal BLAKE2b hash string.
        """
        return ExplicitHashes._hash_file(file_path, hashlib.blake2b())

    @staticmethod
    def hash_file_blake2s(file_path: str) -> str:
        """
        Generate a BLAKE2s hash of the specified file.
        
        Args:
            file_path (str): Path to the file to be hashed.
        
        Returns:
            str: Hexadecimal BLAKE2s hash string.
        """
        return ExplicitHashes._hash_file(file_path, hashlib.blake2s())

    @staticmethod
    def hash_file_sha1(file_path: str) -> str:
        """
        Generate a SHA-1 hash of the specified file.
        
        Args:
            file_path (str): Path to the file to be hashed.
        
        Returns:
            str: Hexadecimal SHA-1 hash string.
        """
        return ExplicitHashes._hash_file(file_path, hashlib.sha1())

    @staticmethod
    def hash_file_shake256(file_path: str, shake_length: int = 64) -> str:
        """
        Generate a SHAKE-256 hash of the specified file.
        
        Args:
            file_path (str): Path to the file to be hashed.
            shake_length (int): Length of the digest.
        
        Returns:
            str: Hexadecimal SHAKE-256 hash string.
        """
        return ExplicitHashes._hash_file(file_path, hashlib.shake_256(), shake_length)

    @staticmethod
    def hash_file_shake128(file_path: str, shake_length: int = 32) -> str:
        """
        Generate a SHAKE-128 hash of the specified file.
        
        Args:
            file_path (str): Path to the file to be hashed.
            shake_length (int): Length of the digest.
        
        Returns:
            str: Hexadecimal SHAKE-128 hash string.
        """
        return ExplicitHashes._hash_file(file_path, hashlib.shake_128(), shake_length)

    @staticmethod
    def hash_file_sha3_224(file_path: str) -> str:
        """
        Generate a SHA3-224 hash of the specified file.
        
        Args:
            file_path (str): Path to the file to be hashed.
        
        Returns:
            str: Hexadecimal SHA3-224 hash string.
        """
        return ExplicitHashes._hash_file(file_path, hashlib.sha3_224())

    @staticmethod
    def hash_file_md5(file_path: str) -> str:
        """
        Generate an MD5 hash of the specified file.
        
        Args:
            file_path (str): Path to the file to be hashed.
        
        Returns:
            str: Hexadecimal MD5 hash string.
        """
        return ExplicitHashes._hash_file(file_path, hashlib.md5())

    @staticmethod
    def hash_file_sha3_512(file_path: str) -> str:
        """
        Generate a SHA3-512 hash of the specified file.
        
        Args:
            file_path (str): Path to the file to be hashed.
        
        Returns:
            str: Hexadecimal SHA3-512 hash string.
        """
        return ExplicitHashes._hash_file(file_path, hashlib.sha3_512())

    @staticmethod
    def hash_file_sha256(file_path: str) -> str:
        """
        Generate a SHA-256 hash of the specified file.
        
        Args:
            file_path (str): Path to the file to be hashed.
        
        Returns:
            str: Hexadecimal SHA-256 hash string.
        """
        return ExplicitHashes._hash_file(file_path, hashlib.sha256())

    @staticmethod
    def hash_file_sha384(file_path: str) -> str:
        """
        Generate a SHA-384 hash of the specified file.
        
        Args:
            file_path (str): Path to the file to be hashed.
        
        Returns:
            str: Hexadecimal SHA-384 hash string.
        """
        return ExplicitHashes._hash_file(file_path, hashlib.sha384())

    @staticmethod
    def hash_file_sha512(file_path: str) -> str:
        """
        Generate a SHA-512 hash of the specified file.
        
        Args:
            file_path (str): Path to the file to be hashed.
        
        Returns:
            str: Hexadecimal SHA-512 hash string.
        """
        return ExplicitHashes._hash_file(file_path, hashlib.sha512())

    @staticmethod
    def hash_file_sha3_384(file_path: str) -> str:
        """
        Generate a SHA3-384 hash of the specified file.
        
        Args:
            file_path (str): Path to the file to be hashed.
        
        Returns:
            str: Hexadecimal SHA3-384 hash string.
        """
        return ExplicitHashes._hash_file(file_path, hashlib.sha3_384())

    @staticmethod
    def _hash_file(file_path: str, hash_func: Any, shake_length: int = None) -> str:
        """
        Helper method to generate the hash of a file using the specified hash function.
        
        Args:
            file_path (str): Path to the file to be hashed.
            hash_func (Any): Hash function instance.
            shake_length (int, optional): Length of the digest for shake algorithms.
        
        Returns:
            str: Hexadecimal hash string.
        """
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                hash_func.update(byte_block)
        
        if shake_length:
            return hash_func.hexdigest(shake_length)
        return hash_func.hexdigest()


class Checksums:
    @staticmethod
    def generate_crc16_checksum(file_path: str) -> str:
        """
        Generate the CRC16 checksum for a given file.
        Args:
            file_path (str): Path to the file to be checksummed.
        Returns:
            str: Hexadecimal CRC16 checksum string.
        """
        return Checksums._generate_checksum(file_path, crcmod.predefined.mkCrcFun('crc-16'), 0xFFFF)

    @staticmethod
    def generate_crc32_checksum(file_path: str) -> str:
        """
        Generate the CRC32 checksum for a given file.
        Args:
            file_path (str): Path to the file to be checksummed.
        Returns:
            str: Hexadecimal CRC32 checksum string.
        """
        return Checksums._generate_checksum(file_path, crcmod.predefined.mkCrcFun('crc-32'), 0xFFFFFFFF)

    @staticmethod
    def generate_crc64_checksum(file_path: str) -> str:
        """
        Generate the CRC64 checksum for a given file.
        Args:
            file_path (str): Path to the file to be checksummed.
        Returns:
            str: Hexadecimal CRC64 checksum string.
        """
        return Checksums._generate_checksum(file_path, crcmod.predefined.mkCrcFun('crc-64'), 0xFFFFFFFFFFFFFFFF)

    @staticmethod
    def generate_crc16_ccitt_checksum(file_path: str) -> str:
        """
        Generate the CRC16-CCITT checksum for a given file.
        Args:
            file_path (str): Path to the file to be checksummed.
        Returns:
            str: Hexadecimal CRC16-CCITT checksum string.
        """
        return Checksums._generate_checksum(file_path, crcmod.mkCrcFun(0x11021, initCrc=0xFFFF, rev=False, xorOut=0x0000), 0xFFFF)

    @staticmethod
    def generate_crc16_modbus_checksum(file_path: str) -> str:
        """
        Generate the CRC16-MODBUS checksum for a given file.
        Args:
            file_path (str): Path to the file to be checksummed.
        Returns:
            str: Hexadecimal CRC16-MODBUS checksum string.
        """
        return Checksums._generate_checksum(file_path, crcmod.mkCrcFun(0x18005, initCrc=0xFFFF, rev=True, xorOut=0x0000), 0xFFFF)

    @staticmethod
    def generate_crc32c_checksum(file_path: str) -> str:
        """
        Generate the CRC32C checksum for a given file.
        Args:
            file_path (str): Path to the file to be checksummed.
        Returns:
            str: Hexadecimal CRC32C checksum string.
        """
        return Checksums._generate_checksum(file_path, crcmod.predefined.mkCrcFun('crc-32c'), 0xFFFFFFFF)

    @staticmethod
    def generate_crc32k_checksum(file_path: str) -> str:
        """
        Generate the CRC32K checksum for a given file.
        Args:
            file_path (str): Path to the file to be checksummed.
        Returns:
            str: Hexadecimal CRC32K checksum string.
        """
        return Checksums._generate_checksum(file_path, crcmod.mkCrcFun(0x741B8CD7 & 0xFFFFFFFF, initCrc=0xFFFFFFFF, rev=True, xorOut=0xFFFFFFFF), 0xFFFFFFFF)

    @staticmethod
    def generate_crc32q_checksum(file_path: str) -> str:
        """
        Generate the CRC32Q checksum for a given file.
        Args:
            file_path (str): Path to the file to be checksummed.
        Returns:
            str: Hexadecimal CRC32Q checksum string.
        """
        return Checksums._generate_checksum(file_path, crcmod.mkCrcFun(0x04C11DB7, initCrc=0x00000000, rev=False, xorOut=0x00000000), 0xFFFFFFFF)

    @staticmethod
    def generate_crc64_ecma_checksum(file_path: str) -> str:
        """
        Generate the CRC64-ECMA checksum for a given file.
        Args:
            file_path (str): Path to the file to be checksummed.
        Returns:
            str: Hexadecimal CRC64-ECMA checksum string.
        """
        return Checksums._generate_checksum(file_path, crcmod.mkCrcFun(0x42F0E1EBA9EA3693 & 0xFFFFFFFFFFFFFFFF, initCrc=0x0000000000000000, rev=False, xorOut=0x0000000000000000), 0xFFFFFFFFFFFFFFFF)

    @staticmethod
    def generate_crc64_iso_checksum(file_path: str) -> str:
        """
        Generate the CRC64-ISO checksum for a given file.
        Args:
            file_path (str): Path to the file to be checksummed.
        Returns:
            str: Hexadecimal CRC64-ISO checksum string.
        """
        return Checksums._generate_checksum(file_path, crcmod.mkCrcFun(0x000000000000001B, initCrc=0xFFFFFFFFFFFFFFFF, rev=True, xorOut=0xFFFFFFFFFFFFFFFF), 0xFFFFFFFFFFFFFFFF)

    @staticmethod
    def _generate_checksum(file_path: str, crc_func: Any, mask: int) -> str:
        """
        Helper method to generate the checksum of a file using the specified CRC function.
        Args:
            file_path (str): Path to the file to be checksummed.
            crc_func (Any): CRC function instance.
            mask (int): Mask to apply to the final checksum value.
        Returns:
            str: Hexadecimal checksum string.
        """
        checksum = 0
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                checksum = crc_func(chunk)
        return format(checksum & mask, f'0{mask.bit_length() // 4}x')


def compare_hashes(downloaded_file_hash: str, original_file_hash: str) -> bool:
    """
    Compare two hash strings to check if they are identical.
    Args:
        downloaded_file_hash (str): The hash of the downloaded file.
        original_file_hash (str): The hash of the original file.
    Returns:
        bool: True if both hashes are identical, False otherwise.
    """
    return downloaded_file_hash == original_file_hash


def raw(raw_str: str, file: str, hash_type: str = 'sha256') -> bool:
    """
    Verify if the hash of a file matches the given hash string.
    Args:
        raw_str (str): The original hash and file name in a single string, separated by a space.
        file (str): The path to the file to be hashed.
        hash_type (str): The type of hash algorithm to use (default is 'sha256').
    Returns:
        bool: True if the file's hash matches the original hash, False otherwise.
    """
    original_file_hash, file_name = raw_str.replace('  ', ' ').split(' ')

    if hash_type in hashlib.algorithms_guaranteed:
        dyn_hash = DynamicHashes.calculate_file_hash(file_path=file, algorithm=hash_type)
        return original_file_hash == dyn_hash
    else:
        raise ValueError(f"Unsupported hash type: {hash_type}")



# Dynamic Hash Calculation
print('Dynamic Hash Function')
try:
    for algo in hashlib.algorithms_guaranteed:
        print(f"{algo:<21} {DynamicHashes.calculate_file_hash(file_path, algo)}")
except (TypeError, AttributeError, ValueError) as e:
    print(e)

# Explicit Hash Calculation
print()
print('Explicit Hash Function ')
print("md5                  ", ExplicitHashes.hash_file_md5(file_path))

print("shake_128            ", ExplicitHashes.hash_file_shake128(file_path))
print("shake_256            ", ExplicitHashes.hash_file_shake256(file_path))

print("blake2s              ", ExplicitHashes.hash_file_blake2s(file_path))
print("blake2b              ", ExplicitHashes.hash_file_blake2b(file_path))

print("sha1                 ", ExplicitHashes.hash_file_sha1(file_path))
print("sha224               ", ExplicitHashes.hash_file_sha224(file_path))
print("sha256               ", ExplicitHashes.hash_file_sha256(file_path))
print("sha384               ", ExplicitHashes.hash_file_sha384(file_path))
print("sha512               ", ExplicitHashes.hash_file_sha512(file_path))

print("sha3_224             ", ExplicitHashes.hash_file_sha3_224(file_path))
print("sha3_256             ", ExplicitHashes.hash_file_sha3_256(file_path))
print("sha3_384             ", ExplicitHashes.hash_file_sha3_384(file_path))
print("sha3_512             ", ExplicitHashes.hash_file_sha3_512(file_path))


# CRC Checksums
print()
print('Checksums ')

checksum_crc16 = Checksums.generate_crc16_checksum(file_path)
print(f"CRC-16 Checksum       {checksum_crc16}")

checksum_crc32 = Checksums.generate_crc32_checksum(file_path)
print(f"CRC-32 Checksum       {checksum_crc32}")

checksum_crc64 = Checksums.generate_crc64_checksum(file_path)
print(f"CRC-64 Checksum       {checksum_crc64}")

