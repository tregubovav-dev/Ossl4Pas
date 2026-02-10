import os
import sys
import json
import urllib.request
import zipfile
import tarfile
import shutil
import re

# ==============================================================================
# CONFIGURATION
# ==============================================================================
REPO_OWNER = "TaurusTLS-Developers"
REPO_NAME = "OpenSSL-Distribution"
# Where to extract files relative to Repo Root
TARGET_DIR = "lib\\openssl"

# Versions to install
TARGET_VERSIONS = ["3.0.19", "3.3.6", "3.6.1"]

# Platforms to install
TARGET_PLATFORMS = {
    "Windows-x64-dev.zip":    "Win64",
    "Windows-x86-dev.zip":    "Win32",
    "Linux-x64-dev.tar.gz":   "Linux64",
    "macOS-x64-dev.tar.gz":   "OSX64",
    "macOS-arm64-dev.tar.gz": "OSXARM64",
    "Android-arm64-dev.tar.gz":   "Android64"
}

# ==============================================================================
# LOGIC
# ==============================================================================
def log(msg):
    print(f"[SETUP] {msg}")

def download_file(url, dest_path):
    log(f"Downloading {url}...")
    try:
        with urllib.request.urlopen(url) as response, open(dest_path, 'wb') as out_file:
            shutil.copyfileobj(response, out_file)
        return True
    except Exception as e:
        log(f"Download failed: {e}")
        return False

def windows_filter(member, path):
    # 1. Only process files in bin/, lib/, and debug/ directories
    name = member.name.lstrip('./') # remove ./ if present
    if not (name.startswith('bin/') or name.startswith('lib/') or name.startswith('debug/')):
        return None  # Skip to other directories

    # 2. Skip symlinks on Windows to avoid PermissionError
    if member.issym():
        return None
    
    # 3. Set default permissions
    if member.isdir():
            member.mode = 0o755
    else:
        member.mode = 0o644
        
    return member

def extract_archive(archive_path, extract_to):
    log(f"Extracting to {extract_to}...")
    os.makedirs(extract_to, exist_ok=True)
    
    if archive_path.endswith('.zip'):
        with zipfile.ZipFile(archive_path, 'r') as z:
            z.extractall(extract_to)
    elif archive_path.endswith('.tar.gz'):
        with tarfile.open(archive_path, 'r:gz') as t:
            # FIX: On Windows, filter out symlinks to prevent PermissionError
            if os.name == 'nt':
                members = []
                for member in t.getmembers():
                    if member.isdir():
                        os.makedirs(os.path.join(extract_to, member.name), exist_ok=True)
                        continue  # Directories will be created as needed
                    else:
                        parent_dir = os.path.dirname(os.path.join(extract_to, member.name))
                        if not os.path.exists(parent_dir):
                            os.makedirs(parent_dir, exist_ok=True)
    
                        member.mode = 0o644  # Regular files with read/write permissions

                t.extractall(extract_to, filter=windows_filter)
            else:
                # On Linux/Mac, extract everything including symlinks
                t.extractall(extract_to)
    else:
        log("Unknown archive format")

def organize_files(extract_root, final_root):
    """
    Moves files from the extracted Dev package structure to our clean structure.
    Source (Dev Zip):
       bin/ (.dll)
       lib/ (.lib)
    Target:
       {final_root}/static (libs)
       {final_root}/shared (dlls)
    """
    static_dir = os.path.join(final_root, "static")
    shared_dir = os.path.join(final_root, "shared")
    debug_dir = os.path.join(final_root, "debug")
    
    os.makedirs(static_dir, exist_ok=True)
    os.makedirs(shared_dir, exist_ok=True)
    os.makedirs(debug_dir, exist_ok=True)

    # 1. Move Static Libs
    src_lib = os.path.join(extract_root, "lib")
    if os.path.exists(src_lib):
        # Move all contents of lib/ to static/
        for item in os.listdir(src_lib):
            s = os.path.join(src_lib, item)
            d = os.path.join(static_dir, item)
            shutil.move(s, d)

    # 2. Move Shared Libs (Bin)
    src_bin = os.path.join(extract_root, "bin")
    if os.path.exists(src_bin):
        # Move all contents of bin/ to shared/
        for item in os.listdir(src_bin):
            s = os.path.join(src_bin, item)
            d = os.path.join(shared_dir, item)
            shutil.move(s, d)

    # 3. Move Debug Symbols
    src_debug = os.path.join(extract_root, "debug")
    if os.path.exists(src_debug):
        # Move contents
        for item in os.listdir(src_debug):
            s = os.path.join(src_debug, item)
            d = os.path.join(debug_dir, item)
            shutil.move(s, d)

def generate_version_inc(version, target_dir):
    """
    Generates 'ossl_version_scope.inc' inside the static lib directory.
    Example Content: {$DEFINE OSSL_3_3}
    """
    # Parse Major.Minor (e.g. 3.3.6 -> 3.3)
    match = re.match(r'^(\d+)\.(\d+)', version)
    if not match:
        log(f"Could not parse version '{version}' for define generation.")
        return

    major, minor = match.groups()
    define_str = f"OSSL_{major}_{minor}" # e.g. OSSL_3_3
    
    # We place the include file in the 'static' folder so it's found 
    # when that folder is added to the search path during static builds.
    inc_path = os.path.join(target_dir, "static", "ossl_version_scope.inc")
    
    # Ensure static dir exists (it should from organize_files)
    os.makedirs(os.path.dirname(inc_path), exist_ok=True)

    with open(inc_path, "w") as f:
        f.write(f"// Auto-generated by setup_libs.py for OpenSSL {version}\n")
        f.write(f"{{$DEFINE {define_str}}}\n")
    
    log(f"Generated version include: {define_str}")

def main():
    # 1. Resolve Paths
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir)
    base_lib_dir = os.path.join(repo_root, TARGET_DIR)
    temp_dir = os.path.join(repo_root, "_temp_deps")

    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
    os.makedirs(temp_dir)

    # 2. Iterate Versions
    for version in TARGET_VERSIONS:
        # Construct Tag Name (v.3.x.x)
        tag = f"v.{version}"
        
        for suffix, local_plat in TARGET_PLATFORMS.items():
            # Construct Asset Name
            # Pattern: openssl-{ver}-{plat}
            asset_name = f"openssl-{version}-{suffix}"
            download_url = f"https://github.com/{REPO_OWNER}/{REPO_NAME}/releases/download/{tag}/{asset_name}"
            
            local_archive = os.path.join(temp_dir, asset_name)
            
            # Download
            if download_file(download_url, local_archive):
                # Extract
                extract_path = os.path.join(temp_dir, f"{version}_{local_plat}")
                extract_archive(local_archive, extract_path)
                
                # Organize
                # Target: Libs/OpenSSL/3.0.15/Win64/
                final_dest = os.path.join(base_lib_dir, version, local_plat)
                if os.path.exists(final_dest):
                    shutil.rmtree(final_dest)
                    
                organize_files(extract_path, final_dest)
                
                # Generate Version Include File for Static Linking
                generate_version_inc(version, final_dest)
                
                log(f"Installed {version} for {local_plat}")
            else:
                log(f"Skipping {version} {local_plat} (Not found or error)")

    # Cleanup
    shutil.rmtree(temp_dir)
    log("Dependency setup complete.")

if __name__ == "__main__":
    main()
    