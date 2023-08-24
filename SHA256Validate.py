# This application takes 2 values:
# - A file to generate a SHA256 hexadecimal value for
# - A SHA256 hexadecimal string to compare the computed value with
# Generates the SHA256 hex value for the specified file and compares it with the given string
# This application is a SHA256 key validator

import argparse
import hashlib
import os

from Values import bcolors

TERMINAL_WIDTH = os.get_terminal_size().columns

def calculate_sha(filename):
    with open(filename, "rb") as file:
        return hashlib.file_digest(file, "sha256")

def validate_sha(filename, sha256):
    digest = calculate_sha(filename)
    is_sha256_valid = digest.hexdigest() == sha256
    
    print("-" * TERMINAL_WIDTH)
    print(f"File:\t\t\t\t{ bcolors.OKCYAN + filename }", end=bcolors.ENDC_NEWLINE)
    print(f"Calculated SHA256 Hash:\t\t{ bcolors.OKCYAN + digest.hexdigest() }", end=bcolors.ENDC_NEWLINE)
    print(f"Entered SHA256 Hash:\t\t{ bcolors.OKCYAN + sha256 }", end=bcolors.ENDC_NEWLINE)
    
    print()
    print(f"{ bcolors.UNDERLINE }SHA256 Validation Test:\t\t", end=bcolors.ENDC)
    if is_sha256_valid:
        print(f"{ bcolors.OKGREEN }PASS", end=bcolors.ENDC_NEWLINE)
    else:
        print(f"{ bcolors.FAIL }FAIL{ bcolors.ENDC }", end=bcolors.ENDC_NEWLINE)
    
    print("-" * TERMINAL_WIDTH)
    return is_sha256_valid

def main():
    parser = argparse.ArgumentParser(
        prog='SHA256Validate',
        description='Generates the SHA256 hex value for the specified file and compares it with the given string')
    parser.add_argument('filename', type=str)
    parser.add_argument('sha256', type=str)

    args = parser.parse_args()

    if args.filename is not None and args.sha256 is not None:
        try:
            validate_sha(args.filename, args.sha256.lower())
        except Exception as ex:
            print(f"{ bcolors.FAIL }An error has occured. Validate your arguments!")
            print(ex, bcolors.ENDC)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()