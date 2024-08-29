import json
import glob

all_programs = []
for program_file in glob.glob("json/p*.json"):
    with open(program_file, 'r') as infile:
        program = json.load(infile)
        all_programs += program

with open('json/all_programs.json', 'w') as outfile:
    json.dump(all_programs, outfile)