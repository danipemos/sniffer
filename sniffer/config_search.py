import os
import subprocess

def get_mounted_disks():
    disks = []
    result = subprocess.run(['lsblk', '-rno', 'NAME,MOUNTPOINT'], capture_output=True, text=True)
    lines = result.stdout.strip().splitlines()
    for line in lines:
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            name, mount_point = parts
            if not name.startswith("sda"):
                disks.append(mount_point)
    return disks

def find_config(directory):
    file_path = os.path.join(directory, 'config.ini')
    system_file_path = os.path.join(directory, 'System Volume Information', 'config.ini')
    if os.path.isfile(file_path) or os.path.isfile(system_file_path):
        if os.path.isfile(file_path):
            return file_path
        elif os.path.isfile(system_file_path):
            return system_file_path
    else:
        return None

def search_config():
    disks = get_mounted_disks()
    for disk in disks:
        if os.path.isdir(disk):
            file_path = find_config(disk)
            if file_path:
                return file_path
    file_path = '/home/sniffer/config.ini'
    return file_path

