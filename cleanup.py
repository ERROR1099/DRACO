import os
import shutil

def cleanup_toolkit():
    """Remove unnecessary and redundant files from the security toolkit"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    
    # Files to remove
    files_to_remove = [
        'ultimate_security_toolkit.py',
        'advanced_tools.py',
        'security_toolkit.py',
        'move_files.py',
        'move_files.bat',
        'ip_info.py'
    ]
    
    # Directories to remove (if they exist)
    dirs_to_remove = []
    
    print("🧹 Cleaning up Security Toolkit...")
    
    # Remove specified files
    for filename in files_to_remove:
        filepath = os.path.join(base_dir, filename)
        try:
            if os.path.exists(filepath):
                os.remove(filepath)
                print(f"✅ Removed: {filename}")
        except Exception as e:
            print(f"❌ Could not remove {filename}: {e}")
    
    # Remove specified directories
    for dirname in dirs_to_remove:
        dirpath = os.path.join(base_dir, dirname)
        try:
            if os.path.exists(dirpath):
                shutil.rmtree(dirpath)
                print(f"✅ Removed directory: {dirname}")
        except Exception as e:
            print(f"❌ Could not remove directory {dirname}: {e}")
    
    print("🎉 Cleanup complete!")

def main():
    cleanup_toolkit()

if __name__ == "__main__":
    main()
