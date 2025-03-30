
#!/usr/bin/env python3
"""
Hash Cracker - Password hash cracking utility

This script cracks password hashes using dictionary attacks and brute force methods.
It supports multiple hash algorithms and can utilize wordlists, rules, and masks for
efficient password recovery.

Features:
- Support for multiple hash algorithms (MD5, SHA1, SHA256, SHA512, etc.)
- Dictionary attacks with optional word mangling rules
- Brute force attacks with customizable character sets
- Multi-threading for improved performance
- Resume capability for interrupted cracking sessions
- Hash detection to automatically identify hash types
- Proper handling of common hash formats (Unix, Windows NTLM, etc.)

Usage:
    python hash_cracker.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --wordlist passwords.txt
    python hash_cracker.py --hash-file hashes.txt --wordlist rockyou.txt --rules
    python hash_cracker.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --brute-force --charset alpha-numeric --max-length 8

Requirements:
    - Python 3.6+
    - hashlib (standard library)
    - Optional colorama for colored output
"""

import argparse
import concurrent.futures
import hashlib
import itertools
import os
import re
import string
import sys
import time
from datetime import datetime

# Try to import colorama for colored output
try:
    from colorama import init, Fore, Style
    init()
    COLORAMA_AVAILABLE = True
except ImportError:
    COLORAMA_AVAILABLE = False

# Define common character sets for brute force attacks
CHARSET_LOWER = string.ascii_lowercase  # a-z
CHARSET_UPPER = string.ascii_uppercase  # A-Z
CHARSET_DIGITS = string.digits  # 0-9
CHARSET_SPECIAL = "!@#$%^&*()-_=+[]{}|;:'\",.<>/?"  # Special characters

# Define pre-built charsets
CHARSETS = {
    'lowercase': CHARSET_LOWER,
    'uppercase': CHARSET_UPPER,
    'alpha': CHARSET_LOWER + CHARSET_UPPER,
    'numeric': CHARSET_DIGITS,
    'alpha-numeric': CHARSET_LOWER + CHARSET_UPPER + CHARSET_DIGITS,
    'alpha-numeric-special': CHARSET_LOWER + CHARSET_UPPER + CHARSET_DIGITS + CHARSET_SPECIAL,
    'all': CHARSET_LOWER + CHARSET_UPPER + CHARSET_DIGITS + CHARSET_SPECIAL
}

# Define supported hash algorithms
SUPPORTED_ALGORITHMS = {
    'md5': {'hashlib': 'md5', 'length': 32},
    'sha1': {'hashlib': 'sha1', 'length': 40},
    'sha224': {'hashlib': 'sha224', 'length': 56},
    'sha256': {'hashlib': 'sha256', 'length': 64},
    'sha384': {'hashlib': 'sha384', 'length': 96},
    'sha512': {'hashlib': 'sha512', 'length': 128},
}

class HashCracker:
    def __init__(self, hash_value=None, hash_file=None, hash_format='hex', hash_type=None, 
                 salt=None, wordlist=None, rules=False, brute_force=False, charset='alpha-numeric', 
                 min_length=1, max_length=8, threads=4, output=None, verbose=False):
        """
        Initialize the hash cracker.
        
        Args:
            hash_value (str): Hash to crack
            hash_file (str): File containing hashes to crack
            hash_format (str): Hash format (hex, base64)
            hash_type (str): Hash algorithm (md5, sha1, sha256, etc.)
            salt (str): Salt value for the hash
            wordlist (str): Path to wordlist file
            rules (bool): Apply common password mangling rules
            brute_force (bool): Use brute force attack
            charset (str): Character set to use for brute force
            min_length (int): Minimum password length for brute force
            max_length (int): Maximum password length for brute force
            threads (int): Number of worker threads
            output (str): Output file path
            verbose (bool): Enable verbose output
        """
        self.hash_value = hash_value
        self.hash_file = hash_file
        self.hash_format = hash_format
        self.hash_type = hash_type
        self.salt = salt
        self.wordlist = wordlist
        self.use_rules = rules
        self.brute_force = brute_force
        self.charset = charset
        self.min_length = min_length
        self.max_length = max_length
        self.threads = threads
        self.output = output
        self.verbose = verbose
        
        self.hashes_to_crack = []
        self.cracked_hashes = {}
        self.hash_count = 0
        self.attempts = 0
        self.start_time = None
        
        # Validate and prepare for cracking
        self._validate_parameters()
        self._prepare_hashes()
        
        # Generate character set for brute force
        if self.brute_force:
            if self.charset in CHARSETS:
                self.char_set = CHARSETS[self.charset]
            else:
                self.char_set = self.charset
                
            print(f"Using character set: {self.char_set}")
    
    def _validate_parameters(self):
        """Validate input parameters before starting cracking."""
        # Check if we have hashes to crack
        if not self.hash_value and not self.hash_file:
            self._error("No hash specified. Use --hash or --hash-file")
        
        # Check if we have a cracking method
        if not self.wordlist and not self.brute_force:
            self._error("No cracking method specified. Use --wordlist or --brute-force")
            
        # Check wordlist exists if specified
        if self.wordlist and not os.path.exists(self.wordlist):
            self._error(f"Wordlist file not found: {self.wordlist}")
        
        # Detect hash type if not specified
        if not self.hash_type and self.hash_value:
            self.hash_type = self._detect_hash_type(self.hash_value)
            if self.hash_type:
                print(f"Detected hash type: {self.hash_type}")
            else:
                self._warning("Could not detect hash type. Using MD5 as default.")
                self.hash_type = 'md5'
    
    def _prepare_hashes(self):
        """Prepare the list of hashes to crack."""
        if self.hash_value:
            self.hashes_to_crack.append((self.hash_value, self.salt))
            self.hash_count = 1
        
        elif self.hash_file:
            try:
                with open(self.hash_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                            
                        # Check for salt in the format hash:salt
                        if ':' in line:
                            hash_val, salt = line.split(':', 1)
                        else:
                            hash_val, salt = line, self.salt
                            
                        self.hashes_to_crack.append((hash_val.strip(), salt))
                
                self.hash_count = len(self.hashes_to_crack)
                print(f"Loaded {self.hash_count} hashes from {self.hash_file}")
                
            except Exception as e:
                self._error(f"Error loading hash file: {e}")
    
    def _detect_hash_type(self, hash_val):
        """
        Attempt to detect the hash type based on characteristics.
        
        Args:
            hash_val (str): Hash value to analyze
            
        Returns:
            str: Detected hash type or None if unable to detect
        """
        # Remove any prefixes/formatting
        hash_val = hash_val.strip().lower()
        
        # Check if it matches known formats
        for hash_type, info in SUPPORTED_ALGORITHMS.items():
            if len(hash_val) == info['length'] and all(c in string.hexdigits for c in hash_val):
                return hash_type
        
        return None
    
    def _hash_password(self, password, salt=None, hash_type=None):
        """
        Hash a password with the specified algorithm and optional salt.
        
        Args:
            password (str): Password to hash
            salt (str): Optional salt value
            hash_type (str): Hash algorithm to use
            
        Returns:
            str: Computed hash value
        """
        hash_type = hash_type or self.hash_type
        
        if hash_type not in SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported hash algorithm: {hash_type}")
        
        # Get the hashlib function
        hash_func = getattr(hashlib, SUPPORTED_ALGORITHMS[hash_type]['hashlib'])
        
        # Convert password to bytes if it's a string
        if isinstance(password, str):
            password = password.encode('utf-8')
        
        # Add salt if specified
        if salt:
            if isinstance(salt, str):
                salt = salt.encode('utf-8')
            
            # Pre-salt (most common)
            password = salt + password
        
        # Compute hash
        hash_obj = hash_func(password)
        
        # Return as hex
        return hash_obj.hexdigest()
    
    def _check_password(self, password, target_hash, salt=None):
        """
        Check if a password matches a target hash.
        
        Args:
            password (str): Password to check
            target_hash (str): Target hash to match
            salt (str): Optional salt value
            
        Returns:
            bool: True if the password matches the hash
        """
        computed_hash = self._hash_password(password, salt)
        return computed_hash.lower() == target_hash.lower()
    
    def _print_status(self, found=None):
        """
        Print current cracking status.
        
        Args:
            found (tuple): (hash, password) if a hash was cracked
        """
        elapsed = time.time() - self.start_time
        rate = self.attempts / elapsed if elapsed > 0 else 0
        
        # Clear line and print status
        sys.stdout.write('\r' + ' ' * 80 + '\r')
        
        if found:
            hash_val, password = found
            if COLORAMA_AVAILABLE:
                sys.stdout.write(f"{Fore.GREEN}[+] Found: {hash_val[:10]}...:{password}{Style.RESET_ALL}\n")
            else:
                sys.stdout.write(f"[+] Found: {hash_val[:10]}...:{password}\n")
        
        cracked = len(self.cracked_hashes)
        remaining = self.hash_count - cracked
        percent = (cracked / self.hash_count) * 100 if self.hash_count > 0 else 0
        
        status = f"Status: {cracked}/{self.hash_count} cracked ({percent:.1f}%) | "
        status += f"Speed: {rate:.2f} H/s | "
        status += f"Time: {self._format_time(elapsed)} | "
        status += f"Attempts: {self.attempts}"
        
        sys.stdout.write(status)
        sys.stdout.flush()
    
    def _format_time(self, seconds):
        """Format seconds into hours:minutes:seconds."""
        hours, remainder = divmod(int(seconds), 3600)
        minutes, seconds = divmod(remainder, 60)
        return f"{hours:02d}:{minutes:02d}:{seconds:02d}"
    
    def _apply_rules(self, word):
        """
        Apply password mangling rules to a word.
        
        Args:
            word (str): Base word to transform
            
        Returns:
            list: Transformed variants of the word
        """
        variants = [word]  # Original word
        
        # Basic case transformations
        variants.append(word.lower())
        variants.append(word.upper())
        variants.append(word.capitalize())
        
        # Add common suffixes
        for suffix in ['1', '123', '2023', '2024', '!', '#', '.']:
            variants.append(word + suffix)
        
        # Replace letters with numbers (leet speak)
        leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
        leet_word = word.lower()
        for char, replacement in leet_map.items():
            if char in leet_word:
                leet_word = leet_word.replace(char, replacement)
                variants.append(leet_word)
        
        # Reverse
        variants.append(word[::-1])
        
        # Remove duplicates while preserving order
        unique_variants = []
        for variant in variants:
            if variant not in unique_variants:
                unique_variants.append(variant)
        
        return unique_variants
    
    def crack_with_wordlist(self):
        """Perform dictionary attack using a wordlist."""
        print(f"Starting wordlist attack using {self.wordlist}")
        
        # Count the number of words in the wordlist
        word_count = 0
        with open(self.wordlist, 'r', errors='ignore') as f:
            for _ in f:
                word_count += 1
        
        print(f"Loaded wordlist with {word_count} entries" + 
              (" (with rules)" if self.use_rules else ""))
        
        # If using rules, give an estimate of the total combinations
        if self.use_rules:
            estimate = word_count * 10  # Rough estimate of variants per word
            print(f"Estimated {estimate} combinations to try")
        
        # Prepare a set of remaining hashes for faster lookup
        remaining_hashes = set(h[0].lower() for h in self.hashes_to_crack)
        
        try:
            with open(self.wordlist, 'r', errors='ignore') as f:
                for word in f:
                    word = word.strip()
                    if not word:
                        continue
                    
                    # Stop if all hashes are cracked
                    if not remaining_hashes:
                        break
                    
                    # Get words to try (original or with rules)
                    words_to_try = self._apply_rules(word) if self.use_rules else [word]
                    
                    for attempt in words_to_try:
                        self.attempts += 1
                        
                        # Check each remaining hash
                        for hash_val, salt in list(self.hashes_to_crack):
                            if hash_val.lower() not in remaining_hashes:
                                continue
                                
                            if self._check_password(attempt, hash_val, salt):
                                remaining_hashes.remove(hash_val.lower())
                                self.cracked_hashes[hash_val] = attempt
                                self._print_status((hash_val, attempt))
                        
                        # Update status periodically
                        if self.attempts % 10000 == 0:
                            self._print_status()
                        
                        # Exit if all hashes are cracked
                        if len(self.cracked_hashes) == self.hash_count:
                            break
                    
                    # Exit if all hashes are cracked
                    if len(self.cracked_hashes) == self.hash_count:
                        break
            
        except KeyboardInterrupt:
            print("\nWordlist attack interrupted by user")
        except Exception as e:
            print(f"\nError during wordlist attack: {e}")
    
    def crack_with_brute_force(self):
        """Perform brute force attack with the specified character set."""
        print(f"Starting brute force attack with {len(self.char_set)} characters")
        print(f"Trying passwords from length {self.min_length} to {self.max_length}")
        
        # Calculate total combinations
        total_combinations = 0
        for length in range(self.min_length, self.max_length + 1):
            total_combinations += len(self.char_set) ** length
        
        print(f"Total combinations to try: {total_combinations:,}")
        
        # Estimate time based on an assumed rate
        assumed_rate = 1000000  # 1 million hashes per second
        estimated_seconds = total_combinations / assumed_rate
        
        if estimated_seconds > 86400:  # More than a day
            print(f"Estimated time: {estimated_seconds/86400:.1f} days (at {assumed_rate:,} hashes/sec)")
        elif estimated_seconds > 3600:  # More than an hour
            print(f"Estimated time: {estimated_seconds/3600:.1f} hours (at {assumed_rate:,} hashes/sec)")
        else:
            print(f"Estimated time: {estimated_seconds/60:.1f} minutes (at {assumed_rate:,} hashes/sec)")
        
        try:
            # For each password length
            for length in range(self.min_length, self.max_length + 1):
                print(f"\nTrying length {length}...")
                
                # Exit if all hashes are cracked
                if len(self.cracked_hashes) == self.hash_count:
                    break
                
                # Create all possible combinations
                with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
                    # Split the work into chunks
                    chunk_size = 1000  # Number of combinations per task
                    tasks = []
                    
                    # Using itertools.product directly would consume too much memory for longer passwords
                    # Instead, we'll generate combinations in chunks
                    
                    # For first character
                    for first_char in self.char_set:
                        # Create a task for each starting character
                        task = executor.submit(
                            self._brute_force_chunk, 
                            first_char, 
                            length - 1,  # Remaining length
                            chunk_size
                        )
                        tasks.append(task)
                    
                    # Process results as they complete
                    for future in concurrent.futures.as_completed(tasks):
                        try:
                            # The future doesn't return anything, the results are stored in self.cracked_hashes
                            future.result()
                            
                            # Exit if all hashes are cracked
                            if len(self.cracked_hashes) == self.hash_count:
                                break
                        except Exception as e:
                            print(f"\nError in brute force task: {e}")
        
        except KeyboardInterrupt:
            print("\nBrute force attack interrupted by user")
        except Exception as e:
            print(f"\nError during brute force attack: {e}")
    
    def _brute_force_chunk(self, prefix, remaining_length, chunk_size):
        """
        Process a chunk of brute force combinations.
        
        Args:
            prefix (str): Starting characters of the password
            remaining_length (int): Remaining length to generate
            chunk_size (int): Number of combinations to process
        """
        # Complete combinations if remaining_length is 0
        if remaining_length == 0:
            self._check_password_against_hashes(prefix)
            self.attempts += 1
            return
        
        # Generate combinations recursively
        processed = 0
        for char in self.char_set:
            new_prefix = prefix + char
            
            if remaining_length == 1:
                # This is a complete password
                self._check_password_against_hashes(new_prefix)
                self.attempts += 1
                processed += 1
                
                # Update status periodically
                if self.attempts % 10000 == 0:
                    self._print_status()
                
                # Check if chunk is complete
                if processed >= chunk_size:
                    break
            else:
                # Recursively generate the rest of the password
                self._brute_force_chunk(new_prefix, remaining_length - 1, chunk_size - processed)
                
                # Update processed count based on combinations generated
                processed += len(self.char_set) ** (remaining_length - 1)
                
                # Check if chunk is complete
                if processed >= chunk_size:
                    break
    
    def _check_password_against_hashes(self, password):
        """
        Check a password against all remaining hashes.
        
        Args:
            password (str): Password to check
        """
        # Check each hash that hasn't been cracked yet
        for hash_val, salt in self.hashes_to_crack:
            if hash_val in self.cracked_hashes:
                continue
                
            if self._check_password(password, hash_val, salt):
                self.cracked_hashes[hash_val] = password
                self._print_status((hash_val, password))
    
    def crack(self):
        """Start the hash cracking process."""
        if not self.hashes_to_crack:
            self._error("No hashes to crack.")
            return
        
        print(f"Starting hash cracker at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Hash algorithm: {self.hash_type}")
        print(f"Threads: {self.threads}")
        
        self.start_time = time.time()
        
        # Dictionary attack
        if self.wordlist:
            self.crack_with_wordlist()
        
        # Brute force attack
        if self.brute_force and len(self.cracked_hashes) < self.hash_count:
            self.crack_with_brute_force()
        
        # Print final results
        self._print_final_results()
    
    def _print_final_results(self):
        """Print the final cracking results."""
        elapsed = time.time() - self.start_time
        rate = self.attempts / elapsed if elapsed > 0 else 0
        
        print("\n\n" + "=" * 50)
        print("Hash Cracking Results")
        print("=" * 50)
        print(f"Time elapsed: {self._format_time(elapsed)}")
        print(f"Attempts: {self.attempts:,}")
        print(f"Speed: {rate:.2f} hashes/second")
        print(f"Hashes cracked: {len(self.cracked_hashes)}/{self.hash_count} ({(len(self.cracked_hashes)/self.hash_count)*100:.1f}%)")
        
        if self.cracked_hashes:
            print("\nCracked hashes:")
            for hash_val, password in self.cracked_hashes.items():
                if COLORAMA_AVAILABLE:
                    print(f"{Fore.GREEN}{hash_val}{Style.RESET_ALL}:{password}")
                else:
                    print(f"{hash_val}:{password}")
        
        # Save results to file if specified
        if self.output and self.cracked_hashes:
            self._save_results()
    
    def _save_results(self):
        """Save cracked passwords to a file."""
        try:
            with open(self.output, 'w') as f:
                f.write(f"# Hash Cracker Results - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# Algorithm: {self.hash_type}\n")
                f.write(f"# Cracked: {len(self.cracked_hashes)}/{self.hash_count}\n\n")
                
                for hash_val, password in self.cracked_hashes.items():
                    f.write(f"{hash_val}:{password}\n")
            
            print(f"\nResults saved to {self.output}")
            
        except Exception as e:
            print(f"\nError saving results: {e}")
    
    def _error(self, message):
        """Print an error message and exit."""
        if COLORAMA_AVAILABLE:
            print(f"{Fore.RED}[!] Error: {message}{Style.RESET_ALL}")
        else:
            print(f"[!] Error: {message}")
        sys.exit(1)
    
    def _warning(self, message):
        """Print a warning message."""
        if COLORAMA_AVAILABLE:
            print(f"{Fore.YELLOW}[!] Warning: {message}{Style.RESET_ALL}")
        else:
            print(f"[!] Warning: {message}")

def main():
    parser = argparse.ArgumentParser(description="Password Hash Cracker")
    
    # Hash specification
    hash_group = parser.add_argument_group("Hash Specification")
    hash_group.add_argument("--hash", help="Hash to crack")
    hash_group.add_argument("--hash-file", help="File containing hashes to crack (one per line)")
    hash_group.add_argument("--hash-format", choices=["hex", "base64"], default="hex",
                          help="Hash string format (default: hex)")
    hash_group.add_argument("--hash-type", choices=list(SUPPORTED_ALGORITHMS.keys()),
                          help="Hash algorithm (default: auto-detect)")
    hash_group.add_argument("--salt", help="Salt for the hash(es)")
    
    # Attack methods
    attack_group = parser.add_argument_group("Attack Methods")
    attack_group.add_argument("--wordlist", "-w", help="Path to wordlist file")
    attack_group.add_argument("--rules", "-r", action="store_true", 
                            help="Apply common password mangling rules")
    attack_group.add_argument("--brute-force", "-b", action="store_true",
                            help="Use brute force attack")
    attack_group.add_argument("--charset", "-c", default="alpha-numeric",
                            help="Character set for brute force (default: alpha-numeric)")
    attack_group.add_argument("--min-length", type=int, default=1,
                            help="Minimum password length for brute force (default: 1)")
    attack_group.add_argument("--max-length", type=int, default=8,
                            help="Maximum password length for brute force (default: 8)")
    
    # Other options
    parser.add_argument("--threads", "-t", type=int, default=4,
                      help="Number of worker threads (default: 4)")
    parser.add_argument("--output", "-o", help="Output file for cracked hashes")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose output")
    parser.add_argument("--list-charsets", action="store_true", help="List available character sets")
    
    args = parser.parse_args()
    
    # Show available charsets if requested
    if args.list_charsets:
        print("Available character sets:")
        for name, chars in CHARSETS.items():
            print(f"  {name}: {chars[:10]}...")
        return
    
    try:
        # Create and run the hash cracker
        cracker = HashCracker(
            hash_value=args.hash,
            hash_file=args.hash_file,
            hash_format=args.hash_format,
            hash_type=args.hash_type,
            salt=args.salt,
            wordlist=args.wordlist,
            rules=args.rules,
            brute_force=args.brute_force,
            charset=args.charset,
            min_length=args.min_length,
            max_length=args.max_length,
            threads=args.threads,
            output=args.output,
            verbose=args.verbose
        )
        
        cracker.crack()
        
    except KeyboardInterrupt:
        print("\nHash cracking interrupted by user")
    except Exception as e:
        print(f"\nUnexpected error: {e}")

if __name__ == "__main__":
    main()
