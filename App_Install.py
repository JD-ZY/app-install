import winreg
import platform
import tkinter as tk
import base64
from tkinter import PhotoImage
from tkinter import messagebox, ttk
import subprocess
import os
import re
import sys
import shutil
import ctypes

_reboot_needed: bool = False   # global flag – set to True when an uninstall returns 3010

def resource_path(relative_name: str) -> str:
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, relative_name)

# Function to copy all .lnk shortcuts from a given folder to the Public Desktop
def copy_shortcuts(source_folder):
    desktop = os.path.join(os.environ.get('PUBLIC', r'C:\Users\Public'), 'Desktop')
    if os.path.exists(source_folder):
        for file in os.listdir(source_folder):
            if file.lower().endswith('.lnk'):
                src = os.path.join(source_folder, file)
                dst = os.path.join(desktop, file)
                try:
                    shutil.copy2(src, dst)
                    print(f'Copied shortcut to desktop: {file}')
                except Exception as e:
                    print(f'Failed to copy shortcut {file}: {e}')

# Check for admin privileges, relaunch as admin if not elevated
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

if not is_admin():
    exe = sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__)
    params = ' '.join([f'\"{arg}\"' for arg in sys.argv])
    try:
        ret = ctypes.windll.shell32.ShellExecuteW(None, 'runas', exe, params, None, 1)
    except Exception as e:
        messagebox.showerror('Elevation Error', f'Failed to request admin permissions: {e}')
        sys.exit(0)
    if int(ret) <= 32:
        messagebox.showerror('Elevation Error', 'Failed to request admin permissions. Please run as administrator.')
        sys.exit(0)
    else:
        sys.exit(0)

# Determine base path (one level up from script or executable location)
exe_dir = os.path.dirname(sys.executable) if getattr(sys, 'frozen', False) else os.path.dirname(os.path.abspath(__file__))
base_path = os.path.abspath(os.path.join(exe_dir, '..'))

# Define application installer paths
apps = {
    'Install Watchguard VPN': os.path.join(base_path, 'Apps', 'Watchguard VPN', 'WG-MVPN-SSL_12_11.exe'),
    'Install Adobe Reader': os.path.join(base_path, 'Apps', 'Adobe Reader', 'AcroRdrDC2500120432_en_US.exe'),
    'Install Google Chrome': os.path.join(base_path, 'Apps', 'Google Chrome', 'googlechromestandaloneenterprise64.msi'),
    'Install Microsoft Office': os.path.join(base_path, 'Apps', 'Office', 'OfficeSetup.exe')
}

# Gather Ninja companies from available installers in the Ninja directory
ninja_dir = os.path.join(base_path, 'Apps', 'Ninja')
ninja_companies = []
if os.path.isdir(ninja_dir):
    for filename in os.listdir(ninja_dir):
        match = re.match(r'NinjaOne-Agent-(.+?)-(MainOffice|DeviceDeployment)-Auto\.(exe|msi)', filename)
        if match:
            company = match.group(1)
            if company not in ninja_companies:
                ninja_companies.append(company)
ninja_companies.sort(key=str.lower)

# Function to run installers silently (supports .exe and .msi)
def run_silent(path, custom_args=None):
    ext = os.path.splitext(path)[1].lower()
    if ext == '.msi':
        subprocess.run(['msiexec', '/i', path, '/qn', '/norestart'], check=True)
    elif ext == '.exe':
        args = custom_args if custom_args else ['/verysilent']
        subprocess.run([path] + args, check=True)

# Registry paths to search for uninstall information
uninstall_paths = [
    r'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    r'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall'
]

# ------------------------------------------------------------------
# Return every installed product found in all 3 uninstall hives.
# Yields tuples: (display_name, publisher, uninstall_cmd)
# ------------------------------------------------------------------
def iter_uninstall_entries():
    UNINSTALL_SUBKEYS = (
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
        r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    )
    HIVES = (
        (winreg.HKEY_LOCAL_MACHINE, "HKLM"),
        (winreg.HKEY_CURRENT_USER, "HKCU"),
    )

    for root, hive_name in HIVES:
        for path in UNINSTALL_SUBKEYS:
            try:
                with winreg.OpenKey(root, path) as key:
                    for i in range(winreg.QueryInfoKey(key)[0]):
                        try:
                            subkey_name = winreg.EnumKey(key, i)
                            with winreg.OpenKey(key, subkey_name) as subkey:
                                name = winreg.QueryValueEx(subkey, "DisplayName")[0]
                                publisher = winreg.QueryValueEx(subkey, "Publisher")[0] \
                                            if _value_exists(subkey, "Publisher") else ""
                                cmd = winreg.QueryValueEx(subkey, "QuietUninstallString")[0] \
                                      if _value_exists(subkey, "QuietUninstallString") \
                                      else winreg.QueryValueEx(subkey, "UninstallString")[0]
                                yield name, publisher, cmd
                        except Exception:
                            continue
            except FileNotFoundError:
                continue


def _value_exists(key, value_name):
    try:
        winreg.QueryValueEx(key, value_name)
        return True
    except FileNotFoundError:
        return False


def get_uninstall_command(app_name):
    import difflib
    matches = []
    for path in uninstall_paths:
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    try:
                        subkey_name = winreg.EnumKey(key, i)
                        with winreg.OpenKey(key, subkey_name) as subkey:
                            try:
                                name = winreg.QueryValueEx(subkey, 'DisplayName')[0]
                            except Exception:
                                continue
                            if not name:
                                continue
                            # Check for direct match or partial match
                            if app_name.lower() in name.lower():
                                try:
                                    uninstall_str = winreg.QueryValueEx(subkey, 'QuietUninstallString')[0]
                                except Exception:
                                    try:
                                        uninstall_str = winreg.QueryValueEx(subkey, 'UninstallString')[0]
                                    except Exception:
                                        continue
                                return uninstall_str
                            else:
                                try:
                                    uninstall_str = winreg.QueryValueEx(subkey, 'UninstallString')[0]
                                except Exception:
                                    uninstall_str = ''
                                matches.append((name, uninstall_str))
                    except Exception:
                        continue
        except WindowsError:
            continue
    # Fuzzy match if no direct match found
    best_cmd = None
    best_name = None
    best_ratio = 0.0
    for name, cmd in matches:
        ratio = difflib.SequenceMatcher(None, app_name.lower(), name.lower()).ratio()
        if ratio > 0.65 and ratio > best_ratio:
            best_ratio = ratio
            best_cmd = cmd
            best_name = name
    if best_cmd:
        print(f'🔍 Fuzzy matched "{app_name}" to "{best_name}"')
        return best_cmd
    return None

import shlex

import shlex
from subprocess import run, CalledProcessError

import shlex

import shlex
import subprocess

import shlex
import subprocess

def run_uninstall_command(cmd: str, app_name: str) -> None:
    """
    Execute an uninstall command silently.
    • Handles MSI and EXE paths with spaces correctly (no shell=True).
    • Adds proper quiet flags, incl. special-cases for Dell Pair and InstallShield.
    • Treats exit code 3010 (= reboot required) as success and sets _reboot_needed.
    """
    global _reboot_needed  # flag defined near the top of the script

    # ------------- break the command string into tokens ---------------
    parts = shlex.split(cmd, posix=False)
    if not parts:
        print(f"⚠️ No command found for {app_name}")
        return

    # ------------------------------------------------------------------
    # 1)  MSI uninstallers
    # ------------------------------------------------------------------
    if parts[0].lower().endswith("msiexec.exe") or parts[0].lower() == "msiexec":
        new_args = []
        has_uninstall = False

        for arg in parts[1:]:
            u = arg.upper()
            if u.startswith("/I"):               # /I{GUID} → /X{GUID}
                has_uninstall = True
                new_args.append("/X" + arg[2:])
            elif u.startswith("/X"):             # already uninstall
                has_uninstall = True
                new_args.append(arg)
            else:
                new_args.append(arg)

        if not has_uninstall:
            new_args.insert(0, "/X")

        if "/QN" not in (a.upper() for a in new_args):
            new_args.append("/qn")
        if "/NORESTART" not in (a.upper() for a in new_args):
            new_args.append("/norestart")

        cmd_list = ["msiexec"] + new_args

    # ---------------------------------------------------------------
    # 2)  EXE uninstallers (everything that isn't msiexec)
    # ---------------------------------------------------------------
    else:
        exe_path, *rest = parts

        # Drop outer quotes from the executable path
        if (exe_path.startswith('"') and exe_path.endswith('"')) or (
            exe_path.startswith("'") and exe_path.endswith("'")
        ):
            exe_path = exe_path[1:-1]

        lower_rest = [a.lower() for a in rest]
        is_installshield = ("installshield" in " ".join(lower_rest)) or ("-runfromtemp" in lower_rest)

        # ---------- make sure we have a silent switch ---------------
        silent_flags = ("/quiet", "/silent", "/s", "/verysilent", "/S")
        has_quiet = any(f in (a.lower() for a in rest) for f in silent_flags)

        if not has_quiet:
            if app_name.lower() == "dell pair":
                rest.append("/S")                         # Dell Pair special case
            elif is_installshield:
                # Insert /s right BEFORE the first "-remove" (required order)
                try:
                    idx = lower_rest.index("-remove")
                    rest.insert(idx, "-s")
                except ValueError:
                    rest.insert(0, "-s")                  # fall back: put it first
            else:
                rest.append("/quiet")                     # generic EXE
    # ---------- Dell Optimizer Core / UI special case ---------------
        if "optimizer" in app_name.lower():
            # Dell’s InstallShield stub wants exactly: -silent AFTER -runfromtemp
            rest = ["-remove", "-runfromtemp", "-silent"]

        cmd_list = [exe_path] + rest
    # --------------------------- run it -------------------------------
    pretty_cmd = " ".join(shlex.quote(a) for a in cmd_list)
    print(f"🔧 Running: {pretty_cmd}")

    result = subprocess.run(cmd_list, capture_output=True)  # check=False on purpose
    rc = result.returncode

    if rc in (0, 3010):                               # 3010 = reboot required
        if rc == 3010:
            _reboot_needed = True
            print(f"✔️ {app_name} removed – reboot required to finish cleanup.")
        else:
            print(f"✔️ Successfully uninstalled {app_name}")
        subprocess.run(["shutdown", "/a"], capture_output=True)  # cancel forced restart
    else:
        print(f"⚠️ Failed to uninstall {app_name} (exit {rc})")
        if result.stderr:
            print(result.stderr.decode(errors='ignore').strip())

            
def remove_dell_software():
    """
    Silently uninstalls every program whose display name OR publisher
    contains 'Dell' (case-insensitive).
    """
    if platform.system() != "Windows":
        print("Not a Windows system – skipping Dell removal.")
        return

    candidates = []
    for name, publisher, cmd in iter_uninstall_entries():
        hint = f"{name} {publisher}".lower()
        if "dell" in hint:
            candidates.append((name, cmd))

    if not candidates:
        print("ℹ️  No Dell software detected.")
        return

    print("📦 Starting silent Dell removal...")
    for name, cmd in candidates:
        if cmd:
            print(f"🧹 Attempting to uninstall: {name}")
            run_uninstall_command(cmd, name)
        else:
            print(f"⚠️  No uninstall command for {name}")

    print("✅ Finished removing Dell software.")
    if _reboot_needed:
        print("🔄 A reboot is recommended to finish cleanup.")


# ------------------------------------------------------------------
# Quietly uninstall *all* Microsoft 365 / Office versions
# ------------------------------------------------------------------
def remove_office_apps(timeout_minutes: int = 30):
    """
    Uses the Office Deployment Tool to remove all Office products.
    Allows up to `timeout_minutes` for completion (default 30).
    """
    xml = """<Configuration>
    <Remove All="TRUE" />
    <Display Level="None" AcceptEULA="TRUE" />
    </Configuration>"""

    config_path = os.path.join(base_path, "uninstall.xml")
    with open(config_path, "w") as f:
        f.write(xml)

    cmd = [apps["Install Microsoft Office"], "/configure", config_path]
    pretty = " ".join(cmd)
    print(f"🔧 Running: {pretty}")

    try:
        result = subprocess.run(
            cmd,
            timeout=timeout_minutes * 60,   # 30 min default
            capture_output=True
        )
        # OfficeSetup exit codes: 0 = success, 17002|3010 = reboot required
        if result.returncode in (0, 3010, 17002):
            if result.returncode != 0:
                global _reboot_needed
                _reboot_needed = True
            print("✔️ Office removed (a reboot may be required).")
        else:
            print(f"⚠️ Office removal exited with code {result.returncode}")
    except subprocess.TimeoutExpired:
        print(f"⚠️ Office uninstall still running after {timeout_minutes} min; "
              f"continuing without waiting.")


# Build the GUI
root = tk.Tk()

# Load the external PNG
logo_image = tk.PhotoImage(file=resource_path("logo.png"))
logo_label = tk.Label(root, image=logo_image)
logo_label.pack(anchor="ne", padx=10, pady=10)


root.title('App Installer')
check_vars = {}

# Checkbox for Dell bloatware removal
dell_checkbox_var = tk.BooleanVar()
tk.Checkbutton(root, text='Remove Dell Bloatware', variable=dell_checkbox_var).pack(anchor='w', padx=10)

# Checkboxes for each application in the apps dictionary
for app in apps:
    var = tk.BooleanVar()
    check_vars[app] = var
    tk.Checkbutton(root, text=app, variable=var).pack(anchor='w', padx=10)

# Checkbox for Ninja installer
ninja_var = tk.BooleanVar()
tk.Checkbutton(root, text='Install Ninja', variable=ninja_var).pack(anchor='w', padx=10)
check_vars['Install Ninja'] = ninja_var

# Label and dropdown for Ninja companies (hidden until checkbox is checked)
company_label = tk.Label(root, text='Select Company:')
company_dropdown = ttk.Combobox(root, values=ninja_companies, state='readonly')
if ninja_companies:
    company_dropdown.current(0)

# --- Install button -------------------------------------------------
install_button = tk.Button(root,
                           text="Install Selected",
                           bg="#0078D7",
                           fg="white",
                           command=lambda: install_selected())
install_button.pack(pady=20)

# Toggle function to show/hide the company dropdown based on Ninja checkbox
def toggle_company_list(*args):
    if ninja_var.get():
        company_label.pack(anchor='w', padx=12, before=install_button)
        company_dropdown.pack(anchor='w', padx=12, before=install_button)
    else:
        company_label.pack_forget()
        company_dropdown.pack_forget()

ninja_var.trace_add('write', toggle_company_list)

def install_selected():
    """Run all requested tasks when the user clicks ‘Install Selected’. """
    install_button.config(state="disabled")          # block double-clicks
    root.update_idletasks()                          # tidy UI before work

    failed = []                                      # collect problems
    try:
        print('Starting installation process...')

        # 1) Dell bloatware removal
        if dell_checkbox_var.get():
            print('Removing Dell bloatware...')
            remove_dell_software()

        # 2) Remove old Office if new one is ticked
        if check_vars.get('Install Microsoft Office') \
           and check_vars['Install Microsoft Office'].get():
            print('Removing existing Microsoft Office installations...')
            remove_office_apps()

        # 3) Ninja agent
        if ninja_var.get():
            print('Installing Ninja agent...')
            company = company_dropdown.get().strip()
            if not company:
                reason = ('No Ninja installers available'
                          if not ninja_companies else 'Company not selected')
                failed.append(('Install Ninja', reason))
                print(reason)
            else:
                installer_found = False
                for filename in os.listdir(ninja_dir):
                    if filename.startswith(
                        f'NinjaOne-Agent-{company}-MainOffice-Auto'):
                        installer_found = True
                        try:
                            run_silent(os.path.join(ninja_dir, filename))
                            print(f'Ran Ninja installer: {filename}')
                        except Exception as e:
                            failed.append(('Install Ninja', str(e)))
                            print(f'Failed to install Ninja: {e}')
                        break
                if not installer_found:
                    failed.append(('Install Ninja', 'Installer not found'))
                    print(f'Ninja installer not found for company: {company}')

        # 4) Regular application installs
        for app_label, var in check_vars.items():
            if app_label == 'Install Ninja' or not var.get():
                continue

            app_name = (app_label[8:]
                        if app_label.lower().startswith('install ')
                        else app_label)
            print(f'Installing {app_name}...')
            path = apps.get(app_label)
            if path and os.path.isfile(path):
                try:
                    if 'Adobe Reader' in app_label:
                        run_silent(path, ['/sAll', '/rs', '/rps',
                                          '/msi', 'EULA_ACCEPT=YES'])
                    else:
                        run_silent(path)
                    print(f'Successfully installed {app_name}.')
                except Exception as e:
                    failed.append((app_label, str(e)))
                    print(f'Failed to install {app_name}: {e}')
            else:
                failed.append((app_label, 'Installer not found'))
                print(f'Installer not found for {app_name}.')

        # 5) Copy shortcuts
        if check_vars.get('Install Microsoft Office') \
           and check_vars['Install Microsoft Office'].get():
            print('Copying Microsoft Office shortcuts to desktop...')
            copy_shortcuts(os.path.join(base_path, 'Apps', 'Office'))

        if check_vars.get('Install Watchguard VPN') \
           and check_vars['Install Watchguard VPN'].get():
            print('Copying Watchguard VPN shortcuts to desktop...')
            copy_shortcuts(os.path.join(base_path, 'Apps', 'Watchguard VPN'))

        # 6) Final user message
        if failed:
            msg = '\n'.join(f"{name}: {err}" for name, err in failed)
            messagebox.showerror('Install Issues',
                                 f'Some tasks failed:\n{msg}')
            print('Installation completed with issues.')
        else:
            if _reboot_needed:
                messagebox.showinfo('Success',
                                    'All tasks completed.\nA reboot is recommended.')
            else:
                messagebox.showinfo('Success', 'All tasks completed successfully.')
            print('Installation completed successfully.')

    finally:
        install_button.config(state="normal")         # always re-enable the button
       

# Run the Tkinter event loop
root.mainloop()
