import pandas as pd
from ids_main import SELECTED_FEATURES

df = pd.read_csv('data\\Monday-WorkingHours.pcap_ISCX.csv', nrows=0)
df.columns = df.columns.str.strip()

available = [f for f in SELECTED_FEATURES if f in df.columns]
missing = [f for f in SELECTED_FEATURES if f not in df.columns]
print('available:', available)
print('missing:', missing)
