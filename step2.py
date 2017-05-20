#!/usr/bin/env python3
import sys
import os
import subprocess
import json

if __name__ == "__main__":
    # Reading manifest data
    with open(os.getcwd() + '/bootstrap1-manifest.json', 'r') as f:
        data = json.load(f)
    latest_uuid = data['last_run_uuid']
    builds = data['builds']
    latest=list(filter(lambda build: build['packer_run_uuid'] == latest_uuid, builds))
    if(len(latest) > 0):
        artifact = latest[0]['artifact_id'].split(':')
        print('going to build bootstrap 2 in region:' + artifact[0] + ' with artifact:' + artifact[1])
    else:
        print("failed to find previous ami in bootstrap1-manifest.json")
        sys.exit(2)
    try:
        subprocess.run(['/usr/local/bin/packer','build','-var','region='+artifact[0],'-var','parent_ami_id='+artifact[1],os.getcwd() + '/bootstrap2.json'], check=True)
    except subprocess.CalledProcessError as err:
        print('ERROR:', err)
        sys.exit(2)
