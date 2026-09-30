import os
import re

def check_file(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        
    in_object = False
    keys_in_current_object = set()
    object_start_line = 0
    
    for i, line in enumerate(lines):
        line = line.strip()
        if "{" in line and "}" not in line:
            # We don't have a full robust parser, but we can look for specific lines
            pass

    # A simpler approach: regex search for common duplicate properties in stellar.toml lint context
    # Usually it's in a configuration object or mock object.

def regex_search(filepath):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Just print any line with "exportAnchorTests:" or something similar.
    # What did I add in that PR?
    
regex_search("src/cli.ts")

