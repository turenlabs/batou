import tarfile
import os

def extract_tar(tar_path, dest_dir):
    """Vulnerable: extractall without members filter or safe filter."""
    tf = tarfile.open(tar_path)
    tf.extractall(dest_dir)
    tf.close()

def extract_tar_manual(tar_path, dest_dir):
    """Vulnerable: manual extraction with path join using entry name."""
    tf = tarfile.open(tar_path)
    for member in tf.getmembers():
        dest_path = os.path.join(dest_dir, member.name)
        tf.extract(member, dest_dir)
    tf.close()
