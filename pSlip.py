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
from tqdm import tqdm
from datetime import datetime
import xml.etree.ElementTree as ET
import platform
import shutil
#!/usr/bin/env python3
import sys
import subprocess
import os
import textwrap
import re
import zipfile
import multiprocessing
from multiprocessing import Pool
from tqdm import tqdm
from datetime import datetime
import xml.etree.ElementTree as ET
import platform
import shutil

RESET = "\033[0m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
CYAN = "\033[96m"
RED = "\033[91m"
BOLD = "\033[1m"

BANNER = f"""
{YELLOW}
██████╗ ███████╗██╗     ██╗██████╗ 
██╔══██╗██╔════╝██║     ██║██╔══██╗
██████╔╝███████╗██║     ██║██████╔╝
██╔═══╝ ╚════██║██║     ██║██╔═══╝ 
██║     ███████║███████╗██║██║     
╚═╝     ╚══════╝╚═╝╚═╝                                                  
{RESET}{BOLD}
Version 1.0.8 | Github.com/Actuator/pSlip
{RESET}
"""

def print_help():
    print(BANNER)
    print(textwrap.dedent(f"""\
        {BOLD}Usage:{RESET} python pSlip.py <apk_file or directory> [-p] [-js] [-call] [-aes] [-all] [-allsafe] [-html <output_file>]

        {BOLD}Options:{RESET}
        -h, --help        Show this help message and exit
        -p                List all permissions requested by the application
        -perm             Scan for custom permissions that are set to a 'normal' protection level
        -js               Scan for explicit JavaScript injection vulnerabilities
        -call             Scan for components with exposed CALL permissions
        -aes              Scan for hardcoded AES/DES keys and IVs
        -taptrap          Scan for tapjacking risk (obscured touch defenses)
        -json <file>      Output the vulnerability details to a JSON file
        -all              Scan for all of the vulnerabilities listed above
        -allsafe          Skip AES/DES key detection for faster scans and mitigate decompilation issues
        -html <file>      Output the vulnerability details to an HTML file
        
        {BOLD}Note:{RESET} Basic manifest hardening checks (allowBackup, debuggable,
                     cleartext traffic, exposed providers) are always enabled.
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
    Perform cheap manifest-level hardening checks.

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


def extract_manifest(apk_file, base_dir):
    if os.path.exists(base_dir):
        try:
            subprocess.run(['rm', '-rf', base_dir], check=True)
        except Exception:
            pass
        except subprocess.CalledProcessError as e:
            print(f"{RED}Error: Failed to remove existing directory '{base_dir}': {e}{RESET}")
            return None
    try:
        subprocess.run(['apktool', 'd', '-f', '-o', base_dir, apk_file],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception:
        pass
    except subprocess.CalledProcessError as e:
        print(f"{RED}Error: Failed to extract APK file '{apk_file}': {e.stderr.decode()}{RESET}")
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
    """
    parse the manifest for exported components, with special handling for <activity-alias>.
       If check_js=True, checks for scheme='javascript' or mimeType='text/javascript'.
       If check_call=True, looks for 'android.intent.action.CALL' or 'CALL_PRIVILEGED'.
       Also flags http/https with empty/wildcard host.
    """
    dangerous_components = {}
    try:
        tree = ET.parse(manifest_file)
        root = tree.getroot()
        android_ns = 'http://schemas.android.com/apk/res/android'
        ET.register_namespace('android', android_ns)

        package_name = get_package_name(root)
        application = root.find('application')
        if application is None:
            return dangerous_components

        real_activities_map = collect_real_activities_export_status(
            application, package_name, target_sdk_version
        )

        component_types = ['activity', 'activity-alias', 'service', 'receiver']
        for component_type in component_types:
            components = application.findall(component_type)
            for component in components:
                component_name = component.get(f'{{{android_ns}}}name')
                if component_name is None:
                    continue

                # both the alias AND its underlying activity must be exported
                if component_type == 'activity-alias':
                    alias_is_exp = is_exported(component, target_sdk_version)
                    target_name = component.get(f'{{{android_ns}}}targetActivity')
                    if target_name is None:
                        continue

                    # construct the same format used in real_activities_map
                    fq_target_name = format_component_name(package_name, target_name)
                    underlying_is_exp = real_activities_map.get(fq_target_name, False)

                    if not (alias_is_exp and underlying_is_exp):
                        continue  # skip

                    exported = True
                else:
                    # for normal <activity>, <service>, <receiver>
                    exported = is_exported(component, target_sdk_version)

                if not exported:
                    continue

                intent_filters = component.findall('intent-filter')
                for intent_filter in intent_filters:
                    actions = intent_filter.findall('action')
                    data_elements = intent_filter.findall('data')

                    is_call_vulnerable = False
                    is_js_vulnerable = False
                    is_http_open_vulnerable = False

               
                    if check_call:
                        for action in actions:
                            action_name = action.get(f'{{{android_ns}}}name')
                            if action_name in ('android.intent.action.CALL',
                                               'android.intent.action.CALL_PRIVILEGED'):
                                #if the component itself is permission-gated don't flag it
                                comp_perm = (component.get(f'{{{android_ns}}}permission') or '').strip()
                                if comp_perm in (
                                    'android.permission.CALL_PHONE',
                                    'android.permission.CALL_PRIVILEGED',
                                    'android.permission.CALL_EMERGENCY',
                                ):
                                    
                                    continue
                                is_call_vulnerable = True
                                break

              
                    if check_js:
                        for data_tag in data_elements:
                            scheme = data_tag.get(f'{{{android_ns}}}scheme')
                            mime_type = data_tag.get(f'{{{android_ns}}}mimeType')
                            if scheme and scheme.lower() == 'javascript':
                                is_js_vulnerable = True
                                break
                            if mime_type and mime_type.lower() == 'text/javascript':
                                is_js_vulnerable = True
                                break

                   
                    for data_tag in data_elements:
                        scheme = data_tag.get(f'{{{android_ns}}}scheme')
                        host = data_tag.get(f'{{{android_ns}}}host')
                        if scheme and scheme.lower() in ['http', 'https']:
                            if not host or host.strip() in ['', '*']:
                                is_http_open_vulnerable = True
                                break

                    # If any of the flags are triggered, store the result
                    if any([is_call_vulnerable, is_js_vulnerable, is_http_open_vulnerable]):
                        formatted_name = format_component_name(package_name, component_name)
                        if formatted_name not in dangerous_components:
                            dangerous_components[formatted_name] = {
                                'intent_filters': [],
                                'is_call_vulnerable': False,
                                'is_js_vulnerable': False,
                                'is_http_open_vulnerable': False
                            }

                        # Keep raw XML for reference
                        intent_filter_str = ET.tostring(intent_filter, encoding='unicode')
                        dangerous_components[formatted_name]['intent_filters'].append(intent_filter_str)

                        if is_call_vulnerable:
                            dangerous_components[formatted_name]['is_call_vulnerable'] = True
                        if is_js_vulnerable:
                            dangerous_components[formatted_name]['is_js_vulnerable'] = True
                        if is_http_open_vulnerable:
                            dangerous_components[formatted_name]['is_http_open_vulnerable'] = True

    except Exception:
        pass
    except Exception as e:
        print(f"{RED}Error: Failed to parse manifest file '{manifest_file}': {e}{RESET}")
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

def generate_adb_command(package_name, component_name):
    
    return (
        f"adb shell am start "
        f"-a android.intent.action.CALL "
        f"-d tel:+15055034455 "
        f"-n {package_name}/{component_name.split('/')[-1]}"
    )

def generate_js_adb_command(package_name, component_name):
  
    return (
        f"adb shell am start "
        f"-a android.intent.action.VIEW "
        f"-d 'javascript:alert(1)' "
        f"-n {package_name}/{component_name.split('/')[-1]}"
    )


def decompile_and_find_aes_keys(apk_file, package_name):
  
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

    def _command_exists(cmd):
        from shutil import which
        return which(cmd) is not None

    # ---------- tolerant JADX ----------
    def _try_jadx(apk_path, out_dir):
        cand = 'jadx' if _command_exists('jadx') else ('jadx-cli' if _command_exists('jadx-cli') else None)
        if not cand:
            return False, "jadx not found"
        if os.path.exists(out_dir):
            shutil.rmtree(out_dir, ignore_errors=True)
        proc = subprocess.run([cand, '-d', out_dir, apk_path, '-q'],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        ok = proc.returncode == 0
        if not ok:
            any_java = False
            for root, _, files in os.walk(out_dir):
                if any(f.endswith('.java') or f.endswith('.kt') for f in files):
                    any_java = True
                    break
            if any_java:
                return True, f"jadx returned {proc.returncode} but produced sources"
            return False, proc.stderr.decode(errors='ignore') or f"jadx exit {proc.returncode}"
        return True, "ok"


    def _try_apktool(apk_path, out_dir):
        if not _command_exists('apktool'):
            return False, "apktool not found"
        if os.path.exists(out_dir):
            shutil.rmtree(out_dir, ignore_errors=True)
        proc = subprocess.run(['apktool', 'd', '-s', '-o', out_dir, apk_path],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc.returncode != 0:
            return False, proc.stderr.decode(errors='ignore') or f"apktool exit {proc.returncode}"
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
    else:
        print(f"{YELLOW}Warning: JADX failed for '{apk_file}': {why}{RESET}")

    found_any = any(v.get('Issue Type') in ('Hardcoded AES Key','Hardcoded DES Key','Hardcoded IV') for v in vulnerabilities)
    if (not ok) or (not found_any):
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
        except Exception:
            pass

    try:
        shutil.rmtree(base_dir, ignore_errors=True)
    except Exception:
        pass
    except Exception:
        pass

    return vulnerabilities




def analyze_apk_original(args):
    """
    extract, parse, and analyze a single APK for vulnerabilities and permissions.
    Returns (apk_file, vulnerabilities, permissions, package_name).
    """
    apk_file, list_permissions_flag, check_js, check_call, collect_permission_vulns = args
    vulnerabilities = []
    permissions = []

    if not is_valid_apk(apk_file):
        return apk_file, vulnerabilities, permissions, None

    base_dir = os.path.splitext(apk_file)[0]
    manifest_file = extract_manifest(apk_file, base_dir)
    if manifest_file is None:
        return apk_file, vulnerabilities, permissions, None

    try:
        tree = ET.parse(manifest_file)
        root = tree.getroot()
    except Exception:
        pass
    except Exception as e:
        print(f"{RED}Error: Failed to parse manifest file '{manifest_file}': {e}{RESET}")
        return apk_file, vulnerabilities, permissions, None

    target_sdk_version = get_target_sdk_version(root)
    if target_sdk_version is None:
        target_sdk_version = 33

    package_name = get_package_name(root)

    # Always-on manifest hardening checks (cheap vs. bytecode scanning).
    try:
        vulnerabilities.extend(
            check_manifest_hardening(root, package_name, target_sdk_version)
        )
    except Exception:
        # Hardening checks should never break the overall analysis.
        pass

    dangerous_components = find_dangerous_components(
        manifest_file, target_sdk_version, check_js, check_call
    )

    for component_name, comp_data in dangerous_components.items():
        if comp_data['is_call_vulnerable'] and check_call:
            adb_cmd = generate_adb_command(package_name, component_name)
            vulnerabilities.append({
                'package_name': package_name,
                'Component': component_name,
                'Issue Type': 'Exposed CALL Permission',
                'Details': 'Potential outbound dialing permission vulnerability',
                'ADB Command': adb_cmd
            })

        if comp_data['is_js_vulnerable'] and check_js:
            adb_cmd = generate_js_adb_command(package_name, component_name)
            vulnerabilities.append({
                'package_name': package_name,
                'Component': component_name,
                'Issue Type': 'JavaScript Injection',
                'Details': 'Potential JavaScript or arbitrary URI loading vulnerability',
                'ADB Command': adb_cmd
            })

        if comp_data['is_http_open_vulnerable']:
            if not comp_data['is_js_vulnerable']:
                cmd_http = (
                    f"adb shell am start "
                    f"-a android.intent.action.VIEW "
                    f"-d 'http://www.windows93.net' "
                    f"-n {package_name}/{component_name.split('/')[-1]}"
                )
                cmd_js = generate_js_adb_command(package_name, component_name)
                combined_cmd = f"URL Redirect:\n{cmd_http}\nJS Injection:\n{cmd_js}"
                vulnerabilities.append({
                    'package_name': package_name,
                    'Component': component_name,
                    'Issue Type': 'URL Redirect',
                    'Details': (
                        "Exported component with http/https in intent-filter but lacking an explicit JavaScript scheme. "
                        "Test for both URL redirect and JS injection."
                    ),
                    'ADB Command': combined_cmd
                })
            else:
                cmd_http = (
                    f"adb shell am start "
                    f"-a android.intent.action.VIEW "
                    f"-d 'http://www.windows93.net/' "
                    f"-n {package_name}/{component_name.split('/')[-1]}"
                )
                vulnerabilities.append({
                    'package_name': package_name,
                    'Component': component_name,
                    'Issue Type': 'URL Redirect',
                    'Details': "Exported component that may allow arbitrary URLs to be loaded",
                    'ADB Command': cmd_http
                })

    apk_name = os.path.basename(apk_file)
    perms_found, new_vulns, normal_protection_permissions = find_permissions(
        manifest_file, apk_name, collect_permission_vulns, package_name
    )

    if new_vulns:
        for nv in new_vulns:
            nv['package_name'] = package_name
        vulnerabilities.extend(new_vulns)

    if perms_found:
        permissions = perms_found

    if collect_permission_vulns and normal_protection_permissions:
        comps_req_perms = find_components_requiring_permissions(
            manifest_file, target_sdk_version, normal_protection_permissions, package_name
        )
        for comp in comps_req_perms:
            vulnerabilities.append({
                'package_name': package_name,
                'Component': comp['component_name'],
                'Issue Type': 'Weak Permission',
                'Details': (
                    f'Exported {comp["component_type"]} "{comp["component_name"].split("/")[-1]}" '
                    f'requires permission "{comp["required_permission"]}" with weak protection level.'
                ),
                'ADB Command': 'N/A'
            })

    try:
        subprocess.run(['rm', '-rf', base_dir], check=True)
    except Exception:
        pass
    except subprocess.CalledProcessError as e:
        print(f"{RED}Warning: Failed to remove directory '{base_dir}': {e}{RESET}")

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
def generate_html_report(vulnerabilities, permissions, output_file):
    grouped_by_package = {}
    for v in vulnerabilities:
        pkg = v.get('package_name', 'N/A')
        grouped_by_package.setdefault(pkg, []).append(v)

    html_content = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>pSlip Vulnerability Report</title>
<style>
:root{
  --bg:#ffffff; --text:#0f172a; --muted:#64748b; --card:#ffffff; --border:#e2e8f0;
  --primary:#2563eb; --primary-contrast:#ffffff; --radius:12px;
  --shadow:0 1px 2px rgba(2,8,23,.06),0 8px 24px rgba(2,8,23,.05);
  --header-h:56px; --row-hover:rgba(2,6,23,.04); --row-target:rgba(37,99,235,.10);
}
@media (prefers-color-scheme: dark){
  :root{
    --bg:#0b1220; --text:#e5e7eb; --muted:#94a3b8; --card:#0e1626; --border:#1f2a44;
    --primary:#60a5fa; --primary-contrast:#0b1220;
    --shadow:0 1px 2px rgba(0,0,0,.35),0 8px 24px rgba(0,0,0,.25);
    --row-hover:rgba(255,255,255,.04); --row-target:rgba(96,165,250,.16);
  }
}
*{box-sizing:border-box}
html{scroll-behavior:smooth}
body{
  margin:0;padding:0;color:var(--text);background:
    radial-gradient(1200px 600px at 20% -10%, rgba(37,99,235,.08), transparent 60%),
    radial-gradient(900px 500px at 120% 10%, rgba(16,185,129,.06), transparent 60%),
    var(--bg);
  font-family:ui-sans-serif,system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans","Helvetica Neue",Arial,"Apple Color Emoji","Segoe UI Emoji";
  font-variant-numeric:tabular-nums;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;
}
header{
  position:sticky;top:0;z-index:50;height:var(--header-h);display:flex;align-items:center;padding:0 20px;color:#fff;
  background:linear-gradient(90deg, rgba(3,7,18,.85), rgba(2,6,23,.70)),linear-gradient(90deg,#1f2937,#111827);
  border-bottom:1px solid rgba(255,255,255,.08);backdrop-filter:saturate(160%) blur(8px);
}
header h1{margin:0;font-size:18px;font-weight:700;letter-spacing:.2px}
.container{width:min(1200px,94vw);margin:20px auto}
.vulnerabilities,.permissions{
  background:var(--card);margin:24px 0;padding:18px;border:1px solid var(--border);border-radius:var(--radius);box-shadow:var(--shadow)
}
.vulnerabilities h2,.permissions h2{margin:0 0 12px 0;font-size:18px;letter-spacing:.2px}
.pkg-header{margin:16px 0 10px 0;padding:12px 14px;border-left:4px solid var(--primary);
  background:linear-gradient(180deg, rgba(37,99,235,.10), transparent);border-radius:var(--radius)}
.pkg-title{font-size:18px;font-weight:700}
.pkg-sub{font-size:13px;color:var(--muted);margin-top:4px}
.pkg-sub a{font-weight:600;color:var(--primary)}
a{color:var(--primary);text-decoration:none}a:hover{text-decoration:underline}
table{
  width:100%;border-collapse:separate;border-spacing:0;margin-bottom:16px;border:1px solid var(--border);
  border-radius:var(--radius);overflow:hidden;background:var(--card)
}
th,td{ text-align:left;padding:10px 12px;vertical-align:top;border-bottom:1px solid var(--border)}
th{ background:linear-gradient(180deg, rgba(2,6,23,.04), transparent);font-weight:700;font-size:13px}
tr:last-child td{border-bottom:0} tr:nth-child(even) td{background:rgba(2,6,23,.02)}
tr:hover td{background:var(--row-hover);transition:background .15s ease}
tr[id]:target td{background:var(--row-target)!important;box-shadow:inset 0 0 0 1px var(--primary)}
.adb-command{white-space:pre-wrap;font-family:ui-monospace,SFMono-Regular,Menlo,Monaco,Consolas,"Liberation Mono",monospace;font-size:12px}
/* severity chips */
.sev{display:inline-block;padding:3px 8px;border-radius:999px;font-weight:700;font-size:12px;letter-spacing:.2px}
.sev-critical{background:#fee2e2;color:#991b1b}.sev-high{background:#ffe4e6;color:#9f1239}
.sev-medium{background:#fff7ed;color:#9a3412}.sev-low{background:#ecfdf5;color:#065f46}
.sev-info{background:#e0f2fe;color:#075985}
@media (prefers-color-scheme: dark){
  .sev-critical{background:rgba(239,68,68,.2);color:#fecaca}
  .sev-high{background:rgba(244,63,94,.2);color:#fecdd3}
  .sev-medium{background:rgba(251,146,60,.2);color:#fed7aa}
  .sev-low{background:rgba(16,185,129,.2);color:#bbf7d0}
  .sev-info{background:rgba(59,130,246,.2);color:#bfdbfe}
}

/* --- overflow safety (2026) --- */
.container{overflow-x:hidden}
table{table-layout:fixed;display:block;max-width:100%;overflow-x:auto}
thead,tbody,tr{width:100%}
th,td{overflow-wrap:anywhere;word-break:break-word;hyphens:auto}
.adb-command,.pkg-title,.pkg-sub,a{overflow-wrap:anywhere;word-break:break-word;hyphens:auto}
</style>
</head>
<body>
    <header><h1>pSlip Vulnerability Report</h1></header>
    <div class="container">
"""
    from datetime import datetime as _dt
    html_content += "<p>Generated on: " + _dt.now().strftime('%Y-%m-%d %H:%M:%S') + "</p>"
    html_content += "<div class='vulnerabilities'><h2>Vulnerabilities</h2>"

    # ---------- Tapjacking Risk summary table ----------
    rows = []
    for pkg, vulns in grouped_by_package.items():
        R = _taptrap_risk_rollup(vulns)
        c = R["counts"]
        rows.append((pkg, R["headline"], R["score"], c["Critical"], c["High"], c["Medium"], c["Low"], c["Info"], c["Total"]))
    rows.sort(key=lambda r: (_severity_rank(r[1]), -int(r[2]), r[0]))

    html_content += """
    <div id='Risk' class='pkg-header'>
      <div class='pkg-title'>Tapjacking Risk</div>
    </div>
    <table>
      <tr>
        <th>App (package)</th><th>Tapjacking Risk</th><th>Score</th>
        <th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Info</th><th>Total</th>
      </tr>
    """
    for pkg, head, score, cC, cH, cM, cL, cI, tot in rows:
        anch = 'pkg-' + _anchorize(pkg)
        html_content += (
            "<tr>"
            f"<td><a href='#{anch}'>{pkg}</a></td><td>{head}</td><td>{score}</td>"
            f"<td>{cC}</td><td>{cH}</td><td>{cM}</td><td>{cL}</td><td>{cI}</td><td>{tot}</td>"
            "</tr>"
        )
    html_content += "</table><br/>"

    # ---------- General Findings Index ----------
    index_rows = []  # (pkg, issue_type, component, severity, confidence, anchor)
    if not vulnerabilities:
        html_content += "<p>No vulnerabilities found.</p>"
    else:
        per_pkg_rows = {}
        for pkg_name, vuln_list in grouped_by_package.items():
            sorted_list = _sorted_vulns(vuln_list)
            rows_for_pkg = []
            anchor_pkg = 'pkg-' + _anchorize(pkg_name)
            counter = 0

            for v in sorted_list:
                comp_full  = v.get('Component', 'N/A')
                issue_type = v.get('Issue Type', 'N/A') or 'N/A'
                severity   = v.get('Severity', '—')
                confidence = str(v.get('Confidence', ''))
                details    = v.get('Details', 'N/A') or 'N/A'
                adb_cmd    = v.get('ADB Command', 'N/A') or 'N/A'
                counter += 1
                row_anchor = f"{anchor_pkg}-v-{counter}"
                index_rows.append((pkg_name, issue_type, comp_full, severity, confidence, row_anchor))
                rows_for_pkg.append({
                    "comp_full": comp_full,
                    "issue_type": issue_type,
                    "severity": severity,
                    "confidence": confidence,
                    "details": details,
                    "adb_cmd": adb_cmd,
                    "row_anchor": row_anchor
                })

            per_pkg_rows[pkg_name] = {
                "anchor_pkg": anchor_pkg,
                "rows": rows_for_pkg,
                "rollup": _taptrap_risk_rollup(vuln_list)
            }

        html_content += """
        <div class='vulnerabilities'>
          <h2>Findings Index</h2>
          <p>This index lists <strong>all</strong> findings across categories. Click any item to jump to full details below.</p>
          <table>
            <tr>
              <th>App (package)</th><th>Issue Type</th><th>Component</th><th>Severity</th><th>Confidence</th>
            </tr>
        """
        if index_rows:
            index_rows.sort(
                key=lambda r: (
                    _severity_rank(r[3]),
                    -int(float(r[4] or 0)),
                    r[0].lower(),
                    r[2].lower()
                )
            )
            for pkg_name, issue_type, comp_full, sev, conf, anchor in index_rows:
                html_content += (
                    "<tr>"
                    f"<td>{pkg_name}</td>"
                    f"<td>{issue_type}</td>"
                    f"<td><a href='#{anchor}'>{comp_full}</a></td>"
                    f"<td>{sev}</td>"
                    f"<td>{conf}</td>"
                    "</tr>"
                )
        else:
            html_content += "<tr><td colspan='5'>No findings detected.</td></tr>"
        html_content += "</table></div>"

        # ---------- Full per-package details ----------
        for pkg_name, pdata in per_pkg_rows.items():
            R = pdata["rollup"]
            counts = R["counts"]
            anchor_id = pdata["anchor_pkg"]
            html_content += (
                f"<div id='{anchor_id}' class='pkg-header'>"
                f"<div class='pkg-title'>{pkg_name}</div>"
                f"<div class='pkg-sub'>Tapjacking Risk: <span class='sev sev-{R['headline'].lower()}'>{R['headline']}</span> (Score: {R['score']}/100)</div>"
                f"<div class='pkg-sub'>Counts — Critical: {counts['Critical']}  High: {counts['High']}  Medium: {counts['Medium']}  Low: {counts['Low']}  Info: {counts['Info']}  Total: {counts['Total']}</div>"
                "</div>"
            )
            html_content += (
                "<table>"
                "<tr><th>Component</th><th>Issue Type</th><th>Severity</th><th>Confidence</th><th>Details</th></tr>"
            )
            for row in pdata["rows"]:
                adb_html = ""
                if row["adb_cmd"] and row["adb_cmd"] != "N/A":
                    adb_html = "<br/><strong>ADB Command:</strong><br/><span class='adb-command'>" + row["adb_cmd"].replace("\\n","<br/>") + "</span>"
                html_content += (
                    f"<tr id='{row['row_anchor']}'>"
                    f"<td>{row['comp_full']}</td>"
                    f"<td>{row['issue_type']}</td>"
                    f"<td>{row['severity']}</td>"
                    f"<td>{row['confidence']}</td>"
                    f"<td>{row['details']}{adb_html}</td>"
                    "</tr>"
                )
            html_content += "</table>"
            html_content += "<div class='pkg-sub' style='margin:8px 0 24px 0;'><a href='#Risk'>↑ Back to Risk</a></div>"

    if permissions:
        html_content += "<div class='permissions'><h2>Permissions Summary</h2>"
        for apk_file, perms_list in permissions.items():
            apk_name = os.path.basename(apk_file)
            html_content += f"<h3>{apk_name}</h3><ul>"
            for perm in perms_list:
                html_content += f"<li>{perm}</li>"
            html_content += "</ul>"
        html_content += "</div>"

    html_content += "</div></body></html>"
    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"{GREEN}HTML report successfully generated at '{output_file}'.{RESET}")
    except Exception:
        pass
    except Exception as e:
        print(f"{RED}Error: Failed to write HTML report to '{output_file}': {e}{RESET}")
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
            conf_num = int(conf)
        except Exception:
            pass
        except Exception:
            try:
                conf_num = int(float(conf))
            except Exception:
                pass
            except Exception:
                conf_num = 0
        comp = v.get("Component", "") or ""
        return (_severity_rank(sev), -conf_num, comp.lower())
    return sorted(vulns, key=key)



def generate_json_report(vulnerabilities, permissions, output_file):
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

def _is_taptrap_issue(v):
    it = (v.get("Issue Type","") or "").lower()
    return it.startswith("tapjacking risk")

def _anchorize(s: str) -> str:
    s = ''.join(ch if (ch.isalnum() or ch in '._-') else '-' for ch in (s or ''))
    while '--' in s:
        s = s.replace('--', '-')
    return s.strip('-') or 'item'

def _taptrap_risk_rollup(vulns):

    def _norm(sev):
        s = (sev or "").strip().lower()
        if s == "critical": return "Critical"
        if s == "high": return "High"
        if s == "medium": return "Medium"
        if s == "low": return "Low"
        return "Info"

    def _sev_weight(sev):
        return {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}.get(sev, 1)

    tv = [v for v in vulns if _is_taptrap_issue(v)]
    if not tv:
        return {"headline": "Info", "score": 0,
                "counts": {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0, "Total": 0}}

    counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0, "Total": 0}
    per_sev_conf = {"Critical": [], "High": [], "Medium": [], "Low": [], "Info": []}

    for v in tv:
        sev = _norm(v.get("Severity", "Info"))
        try:
            conf = float(v.get("Confidence", 0) or 0.0)
        except Exception:
            pass
        except Exception:
            conf = 0.0
        counts[sev] += 1
        counts["Total"] += 1
        per_sev_conf[sev].append(conf)

    present = [s for s in ["Critical", "High", "Medium", "Low"] if counts[s] > 0]
    headline = present[0] if present else "Info"

    peak = 0.0
    for sev, confs in per_sev_conf.items():
        w = _sev_weight(sev) / 5.0
        if confs:
            peak = max(peak, w * max(confs))

    bonus = (
        5.0 * max(0, counts["High"] - 1) +
        3.0 * counts["Medium"] +
        1.5 * counts["Low"]
    )
    bonus = min(30.0, bonus)

    score = int(max(0.0, min(100.0, peak + bonus)))
    return {"headline": headline, "score": score, "counts": counts}

def analyze_apk(args):
    apk_file, list_permissions_flag, check_js, check_call, collect_permission_vulns, check_taptrap = args
    _args_original = (apk_file, list_permissions_flag, check_js, check_call, collect_permission_vulns)
    apk_file, vulnerabilities, permissions, package_name = analyze_apk_original(_args_original)
    try:
        if check_taptrap and package_name:
            base_dir = os.path.splitext(apk_file)[0]
            tap_vulns = detect_taptrap_layout_risks_with_context(base_dir, package_name, apk_file)
            if tap_vulns:
                vulnerabilities.extend(tap_vulns)
    except Exception:
        pass
    except Exception as _e:
        try:
            print(f"{YELLOW}Warning: TapTrap scan failed: {_e}{RESET}")
        except Exception:
            pass
        except Exception:
            pass
    return apk_file, vulnerabilities, permissions, package_name

def _android_ns():
    return 'http://schemas.android.com/apk/res/android'

def _get_android_attr(elem, name):
    return elem.get(f'{{{_android_ns()}}}{name}')

def _load_strings_map(res_dir):
    strings = {}
    if not os.path.isdir(res_dir):
        return strings
    for root_dir, _, files in os.walk(res_dir):
        base = os.path.basename(root_dir)
        if not base.startswith("values"):
            continue
        for f in files:
            if f != "strings.xml":
                continue
            path = os.path.join(root_dir, f)
            try:
                tree = ET.parse(path)
                root = tree.getroot()
            except Exception:
                pass
            except Exception:
                continue
            for s in root.findall("string"):
                name = s.get("name")
                if not name:
                    continue
                text = (s.text or "").strip()
                if not text:
                    continue
                strings.setdefault(name, set()).add(text)
    return strings

def _resolve_text(attr_val, strings_map):
    if not attr_val:
        return set()
    val = attr_val.strip()
    if val.startswith("@string/"):
        key = val.split("/",1)[1]
        return set(strings_map.get(key, []))
    if val.startswith("@android:string/"):
        framework = {"ok": {"OK","Ok","Okay"}, "cancel": {"Cancel","CANCEL"}}
        key = val.split("/",1)[1]
        return set(framework.get(key, []))
    return {val}



def _tokenize(s):
    import re as _re
    return set(_re.findall(r"[A-Za-z0-9]+", (s or "").lower()))


HIGH_RISK_SEMANTIC_TOKENS = {
    "login","auth","verify","pay","checkout","approve","password","otp","pin",
    "confirm","secure","submit","card","transfer","send"
}

SENSITIVE_INPUT_TYPES = {"textpassword","numberpassword","textvisiblepassword","textwebpassword","phone","number"}



def _evidence_for_texts(texts, tokens_set):
    hits = []
    for t in texts:
        toks = _tokenize(t)
        inter = toks & tokens_set
        if inter:
            hits.append(f"text='{t}' hits {sorted(inter)}")
    return hits

def _is_sensitive_input_elem(elem, strings_map):
    tag = (elem.tag or '').lower()
    if not (tag.endswith('edittext') or tag.endswith('textinputedittext')):
        return (False, [], False, 0)
    evidence, conf = [], 0
    it = (_get_android_attr(elem, 'inputType') or '').lower()
    it_hit = any(w in it for w in SENSITIVE_INPUT_TYPES)
    if it_hit:
        evidence.append(f"inputType={it}")
        conf += 1
    id_attr = (_get_android_attr(elem, 'id') or '')
    id_tokens = _tokenize(id_attr)
    id_hits = id_tokens & HIGH_RISK_SEMANTIC_TOKENS
    is_high_semantic = bool(id_hits) or it_hit
    if id_hits:
        evidence.append(f"id hits {sorted(id_hits)}")
        conf += 1
    hints = set()
    hints |= _resolve_text(_get_android_attr(elem, 'hint'), strings_map)
    hints |= _resolve_text(_get_android_attr(elem, 'text'), strings_map)
    ev = _evidence_for_texts(hints, HIGH_RISK_SEMANTIC_TOKENS)
    if ev:
        evidence.extend(ev)
        conf += 1
        is_high_semantic = True
    return (bool(evidence), evidence, is_high_semantic, conf)

def _is_sensitive_button_elem(elem, strings_map):
    tag = (elem.tag or '').lower()
    clickable = (_get_android_attr(elem, 'clickable') or '').lower() == 'true'
    is_buttonish = clickable or tag.endswith('button')
    if not is_buttonish:
        return (False, [], False, 0)
    evidence, conf = [], 0
    texts = set()
    texts |= _resolve_text(_get_android_attr(elem, 'text'), strings_map)
    texts |= _resolve_text(_get_android_attr(elem, 'contentDescription'), strings_map)
    id_attr = (_get_android_attr(elem, 'id') or '')
    id_tokens = _tokenize(id_attr)

    low_risk = {"help","info","search","back","cancel","close","learn","learnmore","later"}
    if (set(_tokenize(" ".join(texts))) & low_risk) or (id_tokens & low_risk):
        return (False, [], False, 0)

    ev_text = _evidence_for_texts(texts, HIGH_RISK_SEMANTIC_TOKENS)
    if ev_text:
        evidence.extend(ev_text)
        conf += 1
    id_hits = id_tokens & HIGH_RISK_SEMANTIC_TOKENS
    if id_hits:
        evidence.append(f"id hits {sorted(id_hits)}")
        conf += 1
    is_high_semantic = bool(ev_text or id_hits)
    return (is_high_semantic, evidence, is_high_semantic, conf)

def _view_identifier(elem, layout_file):
    vid = _get_android_attr(elem, 'id') or ''
    tag = (elem.tag or 'View').split('}')[-1]
    nice_id = vid.split('/')[-1] if '/' in vid else (vid or tag)
    return f"layout/{os.path.basename(layout_file)}#{nice_id}"

def detect_taptrap_layout_risks(base_dir, package_name):
    vulnerabilities = []
    res_dir = os.path.join(base_dir, 'res')
    strings_map = _load_strings_map(res_dir)
    if not os.path.isdir(res_dir):
        return vulnerabilities
    try:
        for root_dir, _, files in os.walk(res_dir):
            if not os.path.basename(root_dir).startswith('layout'):
                continue
            for file in files:
                if not file.endswith('.xml'):
                    continue
                layout_path = os.path.join(root_dir, file)
                try:
                    tree = ET.parse(layout_path)
                    lroot = tree.getroot()
                except Exception:
                    continue
                for elem in lroot.iter():
                    sens1, ev1, high1, c1 = _is_sensitive_input_elem(elem, strings_map)
                    sens2, ev2, high2, c2 = _is_sensitive_button_elem(elem, strings_map)
                    if not (sens1 or sens2):
                        continue
                    ftwo = (_get_android_attr(elem, 'filterTouchesWhenObscured') or '').lower()
                    if ftwo == 'true':
                        continue
                    comp = _view_identifier(elem, layout_path)
                    details = ('Sensitive view missing android:filterTouchesWhenObscured="true". '
                               'Set the attribute or override onFilterTouchEventForSecurity() on this view.')
                    evidence = "; ".join(ev1 + ev2)
                    conf = c1 + c2
                    vuln = {
                        'package_name': package_name,
                        'Component': comp,
                        'Issue Type': 'Tapjacking Risk (Obscured Touches Not Filtered)',
                        'Details': details + (f" Evidence: {evidence}." if evidence else ""),
                        'Confidence': conf,
                        'ADB Command': 'N/A'
                    }
                    if high1 or high2:
                        vuln['__is_high_semantic'] = True
                    vulnerabilities.append(vuln)
    except Exception:
        pass
    except Exception as e:
        try:
            print(f"{YELLOW}Warning: TapTrap layout scan failed: {e}{RESET}")
        except Exception:
            pass
        except Exception:
            pass
    return vulnerabilities

def _scan_apk_for_taptrap_mitigations(apk_path):
    sigs = {
        "onFilterTouchEventForSecurity": False,
        "getFlags_bitcheck": False,
        "setFilterTouchesWhenObscured_true": False,
        "flag_secure_addFlags": False,
        "compose_ui_present": False,
        "compose_sensitive_widgets": False,
    }
    try:
        with zipfile.ZipFile(apk_path, 'r') as zf:
            for member in [m for m in zf.namelist() if m.endswith('.dex')]:
                data = zf.read(member)
                def bfind(s): 
                    try:
                        return s.encode('utf-8') in data
                    except Exception:
                        return False
                if bfind('onFilterTouchEventForSecurity') or bfind('onFilterTouchEventForSecurity(Landroid/view/MotionEvent;)Z'):
                    sigs["onFilterTouchEventForSecurity"] = True
                if bfind('Landroid/view/MotionEvent;->getFlags()I') or bfind('FLAG_WINDOW_IS_OBSCURED') or bfind('FLAG_WINDOW_IS_PARTIALLY_OBSCURED'):
                    sigs["getFlags_bitcheck"] = True
                if bfind('Landroid/view/View;->setFilterTouchesWhenObscured(Z)V'):
                    sigs["setFilterTouchesWhenObscured_true"] = True
                if bfind('Landroid/view/Window;->addFlags(I)V') and (b'0x2000' in data or b'8192' in data or b'FLAG_SECURE' in data):
                    sigs["flag_secure_addFlags"] = True
                if bfind('Landroidx/compose'):
                    sigs["compose_ui_present"] = True
                if (bfind('Landroidx/compose/material/TextField') or 
                    bfind('Landroidx/compose/material3/TextField') or 
                    bfind('PasswordVisualTransformation') or 
                    bfind('OutlinedTextField')):
                    sigs["compose_sensitive_widgets"] = True
    except Exception:
        pass
    except Exception as e:
        try:
            print(f"{YELLOW}Warning: dex scan failed: {e}{RESET}")
        except Exception:
            pass
        except Exception:
            pass
    sigs["any_mitigation"] = any([
        sigs["onFilterTouchEventForSecurity"],
        sigs["getFlags_bitcheck"],
        sigs["setFilterTouchesWhenObscured_true"],
        sigs["flag_secure_addFlags"],
    ])
    return sigs

def _classify_severity_tuned(is_high_semantic: bool, mitigated: bool, confidence: int) -> str:
  
    if mitigated:
        return "Info"

    if is_high_semantic:
        if confidence >= 75:
            return "High"
        if confidence >= 50:
            return "Medium"
        if confidence >= 28:
            return "Low"
        return "Info"
    else:
        if confidence >= 80:
            return "High"
        if confidence >= 55:
            return "Medium"
        if confidence >= 30:
            return "Low"
        return "Info"


def _confidence_score(evidence_count: int, is_high_semantic: bool, mitigated: bool, compose_only: bool = False) -> int:

    ec = min(int(evidence_count or 0), 3)
    base = {0: 15, 1: 38, 2: 62, 3: 80}[ec]

    if is_high_semantic:
        base += 10
    if compose_only:
        base = max(base, 42)
    if mitigated:
        base -= 35

    return max(5, min(99, int(base)))



def detect_taptrap_layout_risks_with_context(base_dir, package_name, apk_path):
    results = []
    sigs = _scan_apk_for_taptrap_mitigations(apk_path)
    xml_findings = detect_taptrap_layout_risks(base_dir, package_name)
    mitigated = sigs.get("any_mitigation", False)

    for v in xml_findings:
        v2 = dict(v)
        is_high = v2.pop('__is_high_semantic', False)
        evidence_count = int(v2.pop('Confidence', 0) or 0)
        conf = _confidence_score(evidence_count, is_high, mitigated, compose_only=False)
        v2["Confidence"] = conf
        v2["Severity"] = _classify_severity_tuned(is_high, mitigated, conf)

        if mitigated and "Mitigations detected in code" not in v2["Details"]:
            v2["Details"] += " Mitigations detected in code; confirm critical views are covered."
        results.append(v2)

    if (sigs.get("compose_ui_present") and sigs.get("compose_sensitive_widgets") and not mitigated and not xml_findings):
        results.append({
            'package_name': package_name,
            'Component': 'compose/*',
            'Issue Type': 'Tapjacking Risk (Compose UI, no obscured-touch defenses found)',
            'Details': 'Compose TextField/Password visuals detected but no obscured-touch filtering in code; protect container or host view.',
            'Severity': 'Info',
            'Confidence': _confidence_score(1, False, False, compose_only=True),
            'ADB Command': 'N/A'
        })
    return results

# ---------------- AES scan timeout helpers ----------------
def _pslip__aes_worker(apk_file, pkg_name, q):
    """run AES key analysis in an isolated process and return results via queue."""
    try:
        res = decompile_and_find_aes_keys(apk_file, pkg_name)
    except Exception:
        pass
    except Exception:
        res = []
    try:
        q.put(res)
    except Exception:
        pass
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
            pass
        except Exception:
            return []
    q = multiprocessing.Queue()
    p = multiprocessing.Process(target=_pslip__aes_worker, args=(apk_file, pkg_name, q), daemon=True)
    p.start()
    p.join(timeout_seconds)
    if p.is_alive():
        try:
            p.terminate()
        except Exception:
            pass
        except Exception:
            pass
        try:
            p.join(5)
        except Exception:
            pass
        except Exception:
            pass
        try:
            print(f"{YELLOW}AES analysis exceeded {timeout_seconds//60} minutes on '{apk_file}'. Skipping and continuing.{RESET}")
        except Exception:
            pass
        except Exception:
            pass
        return []
    try:
        return q.get_nowait()
    except Exception:
        pass
    except Exception:
        return []



def main():
    global check_aes
    start_time = datetime.now()
    if len(sys.argv) < 2:
        print_help()
        sys.exit(1)

    argument = sys.argv[1]
    if argument in ("-h", "--help"):
        print_help()
        sys.exit(0)

    list_permissions_flag = False
    check_js = False
    check_call = False
    check_aes = False
    check_taptrap = False
    html_output = None
    aes_timeout_minutes = 5  
    csv_output = None
    json_output = None
    collect_permission_vulns = False
    html_output = None

    options = sys.argv[2:]
    skip_next = False
    for i, option in enumerate(options):
        if skip_next:
            skip_next = False
            continue

        if option == '-p':
            list_permissions_flag = True
        elif option == '-js':
            check_js = True
        elif option == '-call':
            check_call = True
        elif option == '-aes':
            check_aes = True
        elif option == '-taptrap':
            check_taptrap = True
        elif option == '-perm':
            collect_permission_vulns = True
        elif option == '-all':
            check_js = True
            check_call = True
            check_aes = True
            collect_permission_vulns = True
            check_taptrap = True
        elif option == '-allsafe':
            check_js = True
            check_call = True
            collect_permission_vulns = True
            check_taptrap = True

            if i + 1 < len(options):
                _csv_file = options[i + 1]
                # map to JSON file
                base, _ext = os.path.splitext(_csv_file)
                json_output = (base or 'report') + '.json'
                print(f"{YELLOW}Note: '-csv' is deprecated. Writing JSON to '{json_output}'. Use -json <file> next time.{RESET}")
                skip_next = True
            else:
                print(f"{RED}Error: '-csv' flag requires a value (output file).{RESET}")
                print_help()
                sys.exit(1)

        elif option == '-html':
            if i + 1 < len(options):
                html_output = options[i + 1]
                skip_next = True
            else:
                print(f"{RED}Error: '-html' flag requires an output file name.{RESET}")
                print_help()
                sys.exit(1)
        elif option == '-json':
            if i + 1 < len(options):
                json_output = options[i + 1]
                skip_next = True
            else:
                print(f"{RED}Error: '-json' flag requires a value (output file).{RESET}")
                print_help()
                sys.exit(1)
        elif option == '-aes-timeout':
            if i + 1 < len(options):
                try:
                    aes_timeout_minutes = int(options[i + 1])
                except Exception:
                    pass
                except ValueError:
                    print(f"{RED}Error: '-aes-timeout' expects an integer number of minutes.{RESET}")
                    print_help()
                    sys.exit(1)
                skip_next = True
            else:
                print(f"{RED}Error: '-aes-timeout' flag requires a value (minutes).{RESET}")
                print_help()
                sys.exit(1)
        else:
            print(f"{RED}Unknown option: {option}{RESET}")
            print_help()
            sys.exit(1)

    if list_permissions_flag:
        collect_permission_vulns = True

    apk_paths = []
    if os.path.isfile(argument) and argument.endswith('.apk'):
        apk_paths.append(argument)
    elif os.path.isdir(argument):
        for root, dirs, files in os.walk(argument):
            for file in files:
                if file.endswith('.apk'):
                    apk_file = os.path.join(root, file)
                    apk_paths.append(apk_file)
    else:
        print(f"{RED}Error: Please provide a valid APK file or directory.{RESET}")
        print_help()
        sys.exit(1)

    if not apk_paths:
        print(f"{RED}No APK files found to analyze.{RESET}")
        sys.exit(1)

    print(BANNER)
    pool_args = [
        (apk_file, list_permissions_flag, check_js, check_call, collect_permission_vulns, check_taptrap)
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
        apk_file, vulnerabilities, perms, package_name = result
        if vulnerabilities:
            all_vulnerabilities.extend(vulnerabilities)
        if perms and list_permissions_flag:
            all_permissions_dict[apk_file] = perms
        if package_name:
            package_names_for_apks[apk_file] = package_name

    ## wired from CLI -> env for AES timeout wrapper




    if check_aes:
        print(f"\n{BOLD}Starting AES key extraction...{RESET}\n")
        for apk_file in tqdm(apk_paths, desc="Analyzing for AES keys"):
            if not is_valid_apk(apk_file):
                continue
            pkg_name = package_names_for_apks.get(apk_file, os.path.basename(apk_file))
            timeout_seconds = max(0, int(aes_timeout_minutes)) * 60
            aes_vulns = run_aes_with_timeout(apk_file, pkg_name, timeout_seconds)
            if aes_vulns:
                all_vulnerabilities.extend(aes_vulns)

    end_time = datetime.now()
    total_time = end_time - start_time

    print(f"\n{BOLD}Vulnerability Summary:{RESET}\n")
    display_vulnerabilities_table(all_vulnerabilities)

    if html_output:
        print(f"\n{BOLD}Generating HTML report...{RESET}\n")
        generate_html_report(all_vulnerabilities, all_permissions_dict, html_output)

    if csv_output:
        print(f"\n{BOLD}Generating CSV report...{RESET}\n")
        generate_csv_report(all_vulnerabilities, all_permissions_dict, csv_output)
        generate_csv_taptrap_rollup(all_vulnerabilities, csv_output)

    if list_permissions_flag:
        print(f"\n{BOLD}Permissions Summary:{RESET}\n")
        for apk_file, perms in all_permissions_dict.items():
            print(f"{CYAN}{os.path.basename(apk_file)}:{RESET}")
            for perm in perms:
                print(f"  {perm}")
            print()

    print(f"\n{BOLD}Total Execution Time:{RESET} {total_time}")

    if 'json_output' in locals() and json_output:
        try:
            generate_json_report(all_vulnerabilities, locals().get("permissions", {}), json_output)
        except Exception:
            pass
        except Exception as _e_json:
            try:
                print(f"{RED}Error generating JSON report: {_e_json}{RESET}")
            except Exception:
                pass
            except Exception:
                pass


if __name__ == "__main__":
    main()
