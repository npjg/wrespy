#!/usr/bin/python3

# The main purpose of this script is bulk-exporting resources (especially graphical resources)
# from old Windows executables (both PE and NE).

import argparse
import os
import subprocess
import sys
import shutil
import tempfile
import textwrap

def extract_with_wrestool(filepath, output_dir):
    """Extract resources from a PE file using wrestool."""
    try:
        # Use the output directory directly (no extra subdirectory needed)
        os.makedirs(output_dir, exist_ok=True)
        file_output_dir = output_dir

        # DEFINE TYPES THAT WE WANT TO REMOVE.
        # These are not graphical types, and so I am not interested in them.
        resource_type_ids_to_exclude = [
            4, # RT_MENU
            5, # RT_DIALOG
            6, # RT_STRING
            7, # RT_FONTDIR
            8, # RT_FONT
            9, # RT_ACCELERATOR
            10, # RT_RCDATA
            11, # RT_MESSAGETABLE
            16, # RT_VERSION
        ]
        exclude_args = [f"--type=-{resource_type}" for resource_type in resource_type_ids_to_exclude]
        # TODO: This doesn't seem to be working as expected. Maybe wrestool doesn't handle the arguments
        # like I think it does?
        exclude_args = []

        # EXTRACT THE RESOURCES.
        # This gets all resources (including the ones that wrestool can't process). However,
        # bitmaps and icons and such don't have the proper icons written, so we need another pass.
        subprocess.run([
            'wrestool', '--extract', '--raw', *exclude_args, '--output', file_output_dir, filepath],
            check=True)
        # This now gets the resources wrestool CAN process - we will overwrite the old raw
        # files for the images that wrestool can process.
        subprocess.run([
            'wrestool', '--extract', *exclude_args, '--output', file_output_dir, filepath],
            check=True)

        # FIX AVI FILE NAMES.
        # Wrestool doesn't add these extensions appropriately, so we will add them after the fact.
        for root, dirs, files in os.walk(file_output_dir):
            for file in files:
                if '_AVI_' in file and not file.lower().endswith('.avi'):
                    old_path = os.path.join(root, file)
                    new_path = f"{old_path}.avi"
                    os.rename(old_path, new_path)

        # REMOVE THE DIRECTORY IF IT IS EMPTY.
        if not os.listdir(file_output_dir):
            shutil.rmtree(file_output_dir)

    except subprocess.CalledProcessError as e:
        print(f"Error running wrestool: {e}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print("Error: wrestool not found. Please install icoutils.", file=sys.stderr)
        sys.exit(1)

def extract_resources(filepath, output_dir):
    extract_with_wrestool(filepath, output_dir)

def process_file(filepath, output_dir):
    """Process a single file and extract resources if it's a valid PE or CAB file."""
    # Check if the file is a CAB file
    if filepath.lower().endswith('.cab'):
        with tempfile.TemporaryDirectory() as temp_dir:
            try:
                # Extract the CAB file into a temporary directory
                subprocess.run(['cabextract', '-d', temp_dir, filepath], check=True)

                # Process each file inside the extracted CAB directory
                for root, dirs, files in os.walk(temp_dir):
                    for filename in files:
                        extracted_file_path = os.path.join(root, filename)
                        process_file(extracted_file_path, output_dir)
            except subprocess.CalledProcessError as e:
                print(f"Error extracting CAB file: {e}", file=sys.stderr)
                sys.exit(1)
            except FileNotFoundError:
                print("Error: cabextract not found. Please install it.", file=sys.stderr)
                sys.exit(1)
        return

    # Otherwise, attempt to extract any resources that might be in here.
    extract_resources(filepath, output_dir)

def process_path(input_path, output_dir=None):
    """Process a file or directory recursively."""
    if os.path.isfile(input_path):
        # If output_dir is not provided for a file, create a default output directory based on input_path.
        if output_dir is None:
            output_dir = f"{input_path}.out"
            os.makedirs(output_dir, exist_ok=True)
        process_file(input_path, output_dir)

    elif os.path.isdir(input_path):
        # When processing a directory without an explicit output path,
        # create a .out folder for each file in its own location.
        for root, dirs, files in os.walk(input_path):
            for filename in files:
                filepath = os.path.join(root, filename)
                if output_dir is None:
                    # Create a .out folder next to each file
                    file_output_dir = f"{filepath}.out"
                else:
                    # If output_dir is provided, maintain parallel directory structure
                    relative_root = os.path.relpath(root, input_path)
                    parallel_output_dir = os.path.join(output_dir, relative_root)
                    os.makedirs(parallel_output_dir, exist_ok=True)
                    file_output_dir = parallel_output_dir
                process_file(filepath, file_output_dir)
    else:
        print(f"Error: {input_path} is not a valid file or directory", file=sys.stderr)
        sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description=textwrap.dedent('''
            Extract resources from Windows executables (PE or NE).

            If input_filepath is a directory, wrespy decodes all resources in all
            files and subdirectories within that directory, producing a parallel directory
            structure in the output directory.

            If output_directory_path is not given, the directory <input_filepath>.out is created
            and the output is written there.
        ''')
    )
    parser.add_argument('input_filepath', help='Path to a Windows executable or a directory containing such executables. Files that are not PE or NE files will be ignored.')
    parser.add_argument('--output_directory_path', help='Path to directory where resources should be extracted. If not provided, <input_filepath>.out will be used.')
    args = parser.parse_args()

    input_filepath = args.input_filepath
    output_directory_path = args.output_directory_path
    process_path(input_filepath, output_directory_path)

if __name__ == '__main__':
    main()