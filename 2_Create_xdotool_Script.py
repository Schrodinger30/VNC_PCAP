import os
import string
import pandas as pd

# Define the allowed characters (a-z, A-Z, 0-9)
alnum_set = set(string.ascii_letters + string.digits)

non_alphanumeric_key_map = {
    # ASCII ranges: a-z, A-Z & 0-9
    ' ':	'space',
    '.':	'period',
    '-':	'minus',
    '{':	'braceleft',
    '_':	'underscore',
    '}':	'braceright',
    ',':	'comma',
    '!':	'exclam',
    '~':	'asciitilde',
    '"':	'quotedbl',
    '#':	'numbersign',
    '%':	'percent',
    '&':	'ampersand',
    '`':    'grave',
    '(':	'parenleft',
    ')':	'parenright',
    '+':	'plus',
    ':':	'colon',
    ';':	'semicolon',
    '<':	'less',
    '=':	'equal',
    '>':	'greater',
    '?':	'question',
    '@':	'at',
    '[':	'bracketleft',
    ']':	'bracketright',
    "'":    'apostrophe',
    '$':    'dollar',
    '/':	'slash',
    '\\':   'backslash',
    '|':    'bar',
    '<Enter>': 'Return',
    '<Escape>': 'Escape',
    '<Backspace>': 'BackSpace',
    '<Space>': 'space',
    '*SYNTHETIC* <F6>': "F6"
    }


# Load data
data = pd.read_csv('./keystroke_log_v2.csv', delimiter=',', quotechar = '"')

# Apply conditional mapping
data['xdo_keyname'] = data['output'].apply(
    lambda x: non_alphanumeric_key_map[x] if x not in alnum_set and x in non_alphanumeric_key_map else x
)


data['xdo_keyname'] = data.apply(
    lambda row: f"ctrl+{row['key_name']}" if row['ctrl'] else row['xdo_keyname'], axis=1
)


filtered_data = data[~data['xdo_keyname'].str.contains(r"\*SYNTHETIC\*", regex=True)]


#%%
# Open a bash script file to write the commands
with open('generate_xdotool_script_v2.sh', 'w') as f:
    # Add shebang line
    f.write('#!/bin/bash\n\n')

    # Start by typing "vim flag.txt" and hitting Enter
    f.write('xdotool search --onlyvisible --class qterminal windowactivate --sync\n')
    f.write('sleep 1\n')
    
    f.write("xdotool type 'vim flag.txt'\n")
    f.write('sleep 0.1\n')
    f.write('xdotool key Return\n')
    f.write('sleep 1\n')  # Wait for Vim to launch

    # Loop over relevant rows
    for index, row in data.iloc[13:838].iterrows(): #.iloc[13:838]
        f.write(f"xdotool key {row['xdo_keyname']}\n")
        f.write("sleep 0.01\n")
    
    
    # Type md5sum flag.txt
    f.write('xdotool type "md5sum flag.txt"\n')
    f.write('sleep 0.1\n')
    f.write('xdotool key Return\n')
    
# Make the script executable
os.chmod('generate_xdotool_script_v2.sh', 0o755)

print("Bash script generated as 'generate_xdotool_script_v2.sh'")
