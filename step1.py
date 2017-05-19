#!/usr/bin/env python3
import sys
import subprocess

if __name__ == "__main__":
    print ("going to run bootstrap 1")
    # try:
        subprocess.run(['/usr/local/bin/packer','build',os.getcwd() + '/builders/bootstrap1.json'], check=True)
    except subprocess.CalledProcessError as err:
        print('ERROR:', err)
