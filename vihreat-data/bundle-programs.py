import os
import json
import glob


base_dir = os.environ["JSON_AD_DIR"]

all_programs = []
for program_file in glob.glob(f"{base_dir}/p*.json"):
    with open(program_file, 'r') as infile:
        program = json.load(infile)
        all_programs += program

with open(f"{base_dir}/all_programs.json", "w") as outfile:
    json.dump(all_programs, outfile)