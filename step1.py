#!/usr/bin/env python3
import sys
import subprocess
import os


if __name__ == "__main__":
    print ("going to run bootstrap 1")
    try:
        subprocess.run(['packer','build',os.getcwd() + '/bootstrap1.json'], check=True)
    except subprocess.CalledProcessError as err:
        print('ERROR:', err)
        sys.exit(2)
