#!/usr/bin/env python3
"""
Password Strength Checker - Evaluates password security

This script analyzes passwords to evaluate their strength based on various criteria,
including length, character variety, common patterns, and presence in known password lists.

Features:
- Check password length and complexity
- Detect common password patterns and sequences
- Compare against lists of commonly used passwords
- Provide detailed feedback with specific improvement suggestions
- Estimate password cracking time based on different attack methods

Usage:
    python password_checker.py --password "MySecretP@ssw0rd" 
    python password_checker.py --input passwords.txt --output results.csv

Requirements:
    - Python 3.6+
"""

import argparse
import re
import csv
import math
import os
import getpass
import platform
from collections import Counter
import string

# Platform-specific paths to common password lists
if platform.system() == 'Windows':
    COMMON_PASSWORDS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "common_passwords.txt")
    LEAKED_PASSWORDS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "leaked_passwords.txt")
else:
    COMMON_PASSWORDS_FILE = "common_passwords.txt"
    LEAKED_PASSWORDS_FILE = "leaked_passwords.txt"

# Character set sizes for entropy calculation
CHARSET_SIZES = {
    'lowercase': 26,    # a-z
    'uppercase': 26,    # A-Z
    'digits': 10,       # 0-9
    'special': 33       # Special characters (~33 common ones)
}

class PasswordStrengthChecker:
    def __init__(self, common_passwords_file=None, leaked_passwords_file=None):
        """
        Initialize the password strength checker.
        
        Args:
            common_passwords_file (str): Path to file with common passwords
            leaked_passwords_file (str): Path to file with leaked passwords
        """
        self.common_passwords = set()
        self.leaked_passwords = set()
        
        # Load common passwords if file exists
        if common_passwords_file and os.path.exists(common_passwords_file):
            with open(common_passwords_file, 'r') as f:
                self.common_passwords = set(line.strip().lower() for line in f)
        
        # Load leaked passwords if file exists
        if leaked_passwords_file and os.path.exists(leaked_passwords_file):
            with open(leaked_passwords_file, 'r') as f:
                self.leaked_passwords = set(line.strip().lower() for line in f)
    
    def check_password(self, password):
        """
        Check password strength and return detailed analysis.
        
        Args:
            password (str): Password to check
            
        Returns:
            dict: Analysis results
        """
        if not password:
            return {'score': 0, 'feedback': 'Password cannot be empty.'}
        
        # Initialize results dictionary
        results = {
            'length': len(password),
            'has_lowercase': bool(re.search(r'[a-z]', password)),
            'has_uppercase': bool(re.search(r'[A-Z]', password)),
            'has_digit': bool(re.search(r'[0-9]', password)),
            'has_special': bool(re.search(r'[^a-zA-Z0-9]', password)),
            'is_common': password.lower() in self.common_passwords,
            'is_leaked': password.lower() in self.leaked_passwords,
            'repeated_chars': self._check_repeated_chars(password),
            'sequential_chars': self._check_sequential_chars(password),
            'entropy': self._calculate_entropy(password),
            'feedback': [],
            'score': 0
        }
        
        # Generate feedback
        self._generate_feedback(results, password)
        
        # Calculate final score (0-100)
        self._calculate_score(results)
        
        return results
    
    def _check_repeated_chars(self, password):
        """Check for repeated characters in the password."""
        char_counts = Counter(password)
        return max(char_counts.values()) if char_counts else 0
    
    def _check_sequential_chars(self, password):
        """Check for sequential characters in the password."""
        sequences = [
            string.ascii_lowercase,
            string.ascii_uppercase,
            string.digits,
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm"
        ]
        
        for seq in sequences:
            for i in range(len(seq) - 2):
                if seq[i:i+3] in password:
                    return True
        return False
    
    def _calculate_entropy(self, password):
        """Calculate password entropy (bits)."""
        # Determine character pools used
        char_pools = 0
        if re.search(r'[a-z]', password):
            char_pools += CHARSET_SIZES['lowercase']
        if re.search(r'[A-Z]', password):
            char_pools += CHARSET_SIZES['uppercase']
        if re.search(r'[0-9]', password):
            char_pools += CHARSET_SIZES['digits']
        if re.search(r'[^a-zA-Z0-9]', password):
            char_pools += CHARSET_SIZES['special']
        
        # Entropy = log2(pool_size^length)
        if char_pools == 0:
            return 0
        return math.log2(char_pools) * len(password)
    
    def _generate_feedback(self, results, password):
        """Generate helpful feedback based on password analysis."""
        feedback = []
        
        # Length feedback
        if results['length'] < 8:
            feedback.append("Password is too short. Use at least 8 characters.")
        elif results['length'] < 12:
            feedback.append("Password length is acceptable but could be stronger with 12+ characters.")
        else:
            feedback.append("Good password length.")
        
        # Character variety feedback
        missing_char_types = []
        if not results['has_lowercase']:
            missing_char_types.append("lowercase letters")
        if not results['has_uppercase']:
            missing_char_types.append("uppercase letters")
        if not results['has_digit']:
            missing_char_types.append("numbers")
        if not results['has_special']:
            missing_char_types.append("special characters")
        
        if missing_char_types:
            feedback.append(f"Add {', '.join(missing_char_types)} to increase strength.")
        else:
            feedback.append("Good character variety with mixed case, numbers and special characters.")
        
        # Common/leaked password check
        if results['is_common']:
            feedback.append("This is a commonly used password and should be changed immediately!")
        if results['is_leaked']:
            feedback.append("This password appears in data breaches and should never be used!")
        
        # Pattern checks
        if results['repeated_chars'] > 2:
            feedback.append(f"Avoid repeating the same character ({results['repeated_chars']} repetitions found).")
        if results['sequential_chars']:
            feedback.append("Avoid sequential characters (like 'abc' or '123').")
        
        # Entropy feedback
        if results['entropy'] < 40:
            feedback.append("Very weak entropy, easy to crack.")
        elif results['entropy'] < 60:
            feedback.append("Moderate entropy, could be stronger.")
        elif results['entropy'] < 80:
            feedback.append("Good entropy, strong against most attacks.")
        else:
            feedback.append("Excellent entropy, very strong password.")
        
        # Estimate cracking time based on entropy
        cracking_time = self._estimate_cracking_time(results['entropy'])
        feedback.append(f"Estimated time to crack: {cracking_time}")
        
        results['feedback'] = feedback
    
    def _estimate_cracking_time(self, entropy):
        """Estimate password cracking time based on entropy."""
        # Assume 10 billion guesses per second (modern hardware)
        guesses_per_second = 10_000_000_000
        
        # Time = 0.5 * (character_pool ^ length) / guesses_per_second
        seconds = 0.5 * (2 ** entropy) / guesses_per_second
        
        if seconds < 1:
            return "Instant"
        elif seconds < 60:
            return f"{seconds:.1f} seconds"
        elif seconds < 3600:
            return f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            return f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            return f"{seconds/86400:.1f} days"
        elif seconds < 315360000:  # 10 years
            return f"{seconds/31536000:.1f} years"
        else:
            return "Centuries"
    
    def _calculate_score(self, results):
        """Calculate a score from 0-100 for the password."""
        score = 0
        
        # Length score (up to 30 points)
        length_score = min(30, results['length'] * 2.5)
        score += length_score
        
        # Character variety (up to 25 points)
        variety_score = 0
        if results['has_lowercase']: variety_score += 5
        if results['has_uppercase']: variety_score += 7
        if results['has_digit']: variety_score += 7
        if results['has_special']: variety_score += 6
        score += variety_score
        
        # Complexity deductions
        if results['repeated_chars'] > 2:
            score -= (results['repeated_chars'] - 1) * 2
        if results['sequential_chars']:
            score -= 10
        
        # Common/leaked password severe penalty
        if results['is_common'] or results['is_leaked']:
            score = max(0, score - 50)
        
        # Entropy bonus (up to 20 points)
        entropy_score = min(20, results['entropy'] / 5)
        score += entropy_score
        
        # Minimum length threshold
        if results['length'] < 8:
            score = min(score, 40)  # Cap score at 40 for too short passwords
        
        # Ensure score is between 0 and 100
        results['score'] = max(0, min(100, int(score)))
        
        # Add score assessment
        if results['score'] < 40:
            results['assessment'] = "Very Weak"
        elif results['score'] < 60:
            results['assessment'] = "Weak"
        elif results['score'] < 80:
            results['assessment'] = "Moderate"
        elif results['score'] < 90:
            results['assessment'] = "Strong"
        else:
            results['assessment'] = "Very Strong"
    
    def check_password_file(self, input_file, output_file=None):
        """
        Check password strength for all passwords in a file.
        
        Args:
            input_file (str): Path to file with passwords (one per line)
            output_file (str): Optional path to CSV output file
        """
        results = []
        
        try:
            with open(input_file, 'r') as f:
                for line in f:
                    password = line.strip()
                    if password:
                        result = self.check_password(password)
                        result['password'] = password
                        results.append(result)
                        
            print(f"Analyzed {len(results)} passwords from {input_file}")
            
            # Output to CSV if requested
            if output_file:
                self._write_results_to_csv(results, output_file)
                print(f"Results written to {output_file}")
            
            return results
            
        except Exception as e:
            print(f"Error processing file: {e}")
            return []
    
    def _write_results_to_csv(self, results, output_file):
        """Write password check results to a CSV file."""
        if not results:
            return
            
        fieldnames = ['password', 'score', 'assessment', 'length', 'entropy', 
                    'has_lowercase', 'has_uppercase', 'has_digit', 'has_special',
                    'is_common', 'is_leaked', 'repeated_chars', 'sequential_chars']
        
        with open(output_file, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for result in results:
                # Only include relevant fields
                row = {field: result.get(field, '') for field in fieldnames}
                writer.writerow(row)

def main():
    parser = argparse.ArgumentParser(description="Password Strength Checker")
    parser.add_argument("--password", "-p", help="Password to check")
    parser.add_argument("--input", "-i", help="Input file with passwords (one per line)")
    parser.add_argument("--output", "-o", help="Output CSV file for results")
    parser.add_argument("--common-list", "-c", default=COMMON_PASSWORDS_FILE, 
                        help=f"Common passwords list file (default: {COMMON_PASSWORDS_FILE})")
    parser.add_argument("--leaked-list", "-l", default=LEAKED_PASSWORDS_FILE,
                        help=f"Leaked passwords list file (default: {LEAKED_PASSWORDS_FILE})")
    
    args = parser.parse_args()
    
    # Initialize checker
    checker = PasswordStrengthChecker(args.common_list, args.leaked_list)
    
    # Check single password or file of passwords
    if args.password:
        result = checker.check_password(args.password)
        print(f"\nPassword Analysis (Score: {result['score']}/100 - {result.get('assessment', '')})")
        print("-" * 60)
        for feedback in result['feedback']:
            print(f"- {feedback}")
    elif args.input:
        checker.check_password_file(args.input, args.output)
    else:
        # Interactive mode
        print("Password Strength Checker - Interactive Mode")
        print("(Password will not be displayed as you type for security)")
        while True:
            password = getpass.getpass("\nEnter password to check (or empty to quit): ")
            if not password:
                break
                
            result = checker.check_password(password)
            print(f"\nPassword Analysis (Score: {result['score']}/100 - {result.get('assessment', '')})")
            print("-" * 60)
            for feedback in result['feedback']:
                print(f"- {feedback}")

if __name__ == "__main__":
    main()
