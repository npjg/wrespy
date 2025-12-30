#!/usr/bin/python3

import argparse
import subprocess
import sys
import pefile
import nefile

def main():
    parser = argparse.ArgumentParser(description='Extract resources from PE or NE files')
    parser.add_argument('input_file', help='Path to the PE or NE file')
    parser.add_argument('output_dir', help='Directory to extract resources to')
    args = parser.parse_args()

    filepath = args.input_file
    output_dir = args.output_dir

    # DETECT THE FILE TYPE.
    # We will first assume this is a PE file, and if
    # loading as a PE fails we will try reading as an
    # NE file.
    try:
        # Try to load as PE file
        executable = pefile.PE(filepath)
        print(f"Detected PE file: {filepath}")

        # Shell out to wrestool to extract resources
        try:
            subprocess.run(['wrestool', '--extract', '--raw', '--output', output_dir, filepath],
                         check=True)
            print(f"Resources extracted to {output_dir}")
        except subprocess.CalledProcessError as e:
            print(f"Error running wrestool: {e}", file=sys.stderr)
            sys.exit(1)
        except FileNotFoundError:
            print("Error: wrestool not found. Please install icoutils.", file=sys.stderr)
            sys.exit(1)

    except pefile.PEFormatError:
        # Not a PE file, try NE
        try:
            executable = nefile.NE(filepath)
            print(f"Detected NE file: {filepath}")

            # Use nefile to extract resources
            executable.export_resources(output_dir)
            print(f"Resources exported to {output_dir}")

        except nefile.NEFormatError:
            print(f"Skipping {filepath}: Not a valid PE or NE file", file=sys.stderr)
            sys.exit(0)

if __name__ == '__main__':
    main()