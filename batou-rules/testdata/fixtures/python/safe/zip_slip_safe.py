import tarfile
import os

def extract_tar_safe(tar_path, dest_dir):
    """Safe: extractall with members filter."""
    tf = tarfile.open(tar_path)
    safe_members = []
    for member in tf.getmembers():
        member_path = os.path.realpath(os.path.join(dest_dir, member.name))
        if member_path.startswith(os.path.realpath(dest_dir)):
            safe_members.append(member)
    tf.extractall(dest_dir, members=safe_members)
    tf.close()
