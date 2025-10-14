import subprocess
import os
import sys

VOL_PATH = r"C:\Users\Tanush\Documents\volatility3"
WINPMEM_PATHS = [
    r"C:\MemoryDumps\winpmem_mini_x64_rc2.exe"
]
DUMP_PATH = r"C:\Forensics\memdump.raw"
RESULT_DIR = r"C:\Forensics\results"

os.makedirs(RESULT_DIR, exist_ok=True)

winpmem_path = None
for path in WINPMEM_PATHS:
    if os.path.exists(path):
        winpmem_path = path
        print(f"[+] Found winpmem at: {path}")
        break

if not winpmem_path:
    print("[-] Error: Could not find winpmem executable. Please check:")
    print("   1. The file exists on your Desktop")
    print("   2. The filename is correct")
    print("   3. You have the necessary permissions")
    
    desktop_path = r"C:\Users\Tanush\Desktop"
    if os.path.exists(desktop_path):
        print(f"\nFiles on your Desktop:")
        for file in os.listdir(desktop_path):
            if "winpmem" in file.lower() or "wimpmem" in file.lower():
                print(f"  -> {file}")
    
    sys.exit(1)

print(f"[+] Capturing memory dump using {winpmem_path}...")
try:
    result = subprocess.run([winpmem_path, DUMP_PATH], capture_output=True, text=True)
    
    if os.path.exists(DUMP_PATH) and os.path.getsize(DUMP_PATH) > 0:
        print("[+] Memory dump completed successfully")
        print(f"[+] Dump file size: {os.path.getsize(DUMP_PATH)} bytes")
    else:
        print("[-] Memory dump failed - no output file created")
        print(f"WinPMEM output: {result.stdout}")
        print(f"WinPMEM errors: {result.stderr}")
        sys.exit(1)
        
except FileNotFoundError as e:
    print(f"[-] File not found: {e}")
    sys.exit(1)

print("[+] Running Volatility3 analysis...")
try:
    subprocess.run([
        sys.executable,
        "vol.py",
        "-f", DUMP_PATH,
        "windows.pslist",
        "--output", "json",
        "--output-file", os.path.join(RESULT_DIR, "processes.json")
    ], cwd=VOL_PATH, check=True)
except subprocess.CalledProcessError as e:
    print(f"[-] Error running Volatility: {e}")

modules = ["windows.netstat", "windows.malfind", "windows.driverscan"]
for mod in modules:
    print(f"[+] Running {mod}...")
    try:
        subprocess.run([
            sys.executable,
            "vol.py",
            "-f", DUMP_PATH,
            mod,
            "--output", "json",
            "--output-file", os.path.join(RESULT_DIR, f"{mod}.json")
        ], cwd=VOL_PATH, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[-] Error running {mod}: {e}")

print("[+] Analysis complete. Results saved in:", RESULT_DIR)
