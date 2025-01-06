import os
import shutil

# Define source and destination directories
base_dir = r'c:/Users/orange/Desktop/Python Projects/security_toolkit'
src_dir = os.path.join(base_dir, 'src', 'tools')

# Ensure destination directories exist
os.makedirs(os.path.join(src_dir, 'network'), exist_ok=True)
os.makedirs(os.path.join(src_dir, 'system'), exist_ok=True)
os.makedirs(os.path.join(src_dir, 'web'), exist_ok=True)
os.makedirs(os.path.join(src_dir, 'crypto'), exist_ok=True)

# Files to move
files_to_move = {
    'network_scanner.py': os.path.join(src_dir, 'network'),
    'system_monitor.py': os.path.join(src_dir, 'system'),
    'ip_info.py': os.path.join(src_dir, 'network'),
    'advanced_tools.py': os.path.join(src_dir, 'web'),
    'extended_security_tools.py': os.path.join(src_dir, 'web'),
    'specialized_security_tools.py': os.path.join(src_dir, 'web')
}

# Move files
for filename, dest_dir in files_to_move.items():
    src_path = os.path.join(base_dir, filename)
    dest_path = os.path.join(dest_dir, filename)
    
    if os.path.exists(src_path):
        shutil.move(src_path, dest_path)
        print(f"Moved {filename} to {dest_path}")
    else:
        print(f"File {filename} not found")
