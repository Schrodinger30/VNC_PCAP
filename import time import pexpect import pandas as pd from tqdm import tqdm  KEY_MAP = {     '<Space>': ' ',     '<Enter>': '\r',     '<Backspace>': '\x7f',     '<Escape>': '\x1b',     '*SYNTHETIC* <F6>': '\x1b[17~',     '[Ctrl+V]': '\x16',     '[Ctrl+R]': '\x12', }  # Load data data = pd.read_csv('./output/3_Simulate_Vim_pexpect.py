import time
import pexpect
import pandas as pd
from tqdm import tqdm

KEY_MAP = {
    '<Space>': ' ',
    '<Enter>': '\r',
    '<Backspace>': '\x7f',
    '<Escape>': '\x1b',
    '*SYNTHETIC* <F6>': '\x1b[17~',
    '[Ctrl+V]': '\x16',
    '[Ctrl+R]': '\x12',
}

# Load data
data = pd.read_csv('./output/keystroke_log.csv', delimiter=',', quotechar = '"')

# Apply conditional mapping
data['pexpect_keyname'] = data['output'].apply(lambda x: KEY_MAP.get(str(x).strip(), str(x).strip()))

# Filter out empty synthetic key presses
filtered_data = data[~data['pexpect_keyname'].str.contains(r"\*SYNTHETIC\*", regex=True)].reset_index()

vim = pexpect.spawn('vim flag.txt')
time.sleep(1)

subset = filtered_data.iloc[13:833]

for index, row in tqdm(subset.iterrows(), total=len(subset)):
    vim.send(row['pexpect_keyname'])
    time.sleep(0.05)
    
vim.send('\x1b')  # Escape to normal mode
time.sleep(0.1)
vim.send(':wq\r') # Write and quit
time.sleep(0.5)

vim.expect(pexpect.EOF)
