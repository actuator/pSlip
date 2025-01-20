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
Version 1.0.1 | Github.com/Actuator/pSlip
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
        -all              Scan for all of the vulnerabilities listed above
        -allsafe          Skip AES/DES key detection for faster scans and mitigate decompilation issues
        -html <file>      Output the vulnerability details to an HTML file
    """))

def command_exists(command):
    return shutil.which(command) is not None

def extract_manifest(apk_file, base_dir):
    if os.path.exists(base_dir):
        try:
            subprocess.run(['rm', '-rf', base_dir], check=True)
        except subprocess.CalledProcessError as e:
            print(f"{RED}Error: Failed to remove existing directory '{base_dir}': {e}{RESET}")
            return None
    try:
        subprocess.run(['apktool', 'd', '-f', '-o', base_dir, apk_file],
                       check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
    except Exception as e:
        print(f"{RED}Error: Unable to extract targetSdkVersion: {e}{RESET}")
    return None

def get_package_name(manifest_root):
    try:
        package_name = manifest_root.attrib.get('package')
        return package_name
    except Exception as e:
        print(f"{RED}Error: An unexpected error occurred while extracting package name: {e}{RESET}")
        return None

def is_exported(component, target_sdk_version):
    """
    Checks 'android:exported' status. If not explicitly set and targetSdkVersion < 31,
    returns True if there's an <intent-filter>.
    """
    android_ns = 'http://schemas.android.com/apk/res/android'
    exported = component.get(f'{{{android_ns}}}exported')
    if exported is not None:
        return exported.lower() == 'true'
    else:
        # For targetSdkVersion <31, exported is implicitly true if there's any intent-filter
        # For >=31, must be explicitly set; otherwise default is false
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

        # collect export status of  target activity 
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

                    # Check for CALL
                    if check_call:
                        for action in actions:
                            action_name = action.get(f'{{{android_ns}}}name')
                            if action_name in ['android.intent.action.CALL',
                                               'android.intent.action.CALL_PRIVILEGED']:
                                is_call_vulnerable = True
                                break

                    # Check for JavaScript scheme or MIME
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

                    # Check for "http"/"https" with missing host
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

            # if protectionLevel is normal or not set, add to normal_protection_permissions
            if protectionLevel is None or protectionLevel == 'normal':
                normal_protection_permissions.append(name)

    except Exception as e:
        print(f"{RED}Error: An unexpected error occurred while reading permissions: {e}{RESET}")
        return permissions, [], []

    return permissions, new_vulnerabilities, normal_protection_permissions

def find_components_requiring_permissions(manifest_file, target_sdk_version, permissions_list, package_name):
    """
    Look for exported components that require a permission (with normal or no protection level).
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
    except zipfile.BadZipFile:
        print(f"{YELLOW}Warning: '{apk_file}' is not a valid APK file or is corrupted. Skipping.{RESET}")
        return False
    except Exception as e:
        print(f"{RED}Error: An unexpected error occurred while validating '{apk_file}': {e}{RESET}")
        return False

def generate_adb_command(package_name, component_name):
    """Build an ADB command for CALL-based vulnerabilities."""
    return (
        f"adb shell am start "
        f"-a android.intent.action.CALL "
        f"-d tel:+15055034455 "
        f"-n {package_name}/{component_name.split('/')[-1]}"
    )

def generate_js_adb_command(package_name, component_name):
    """Build an ADB command for JS-based vulnerabilities."""
    return (
        f"adb shell am start "
        f"-a android.intent.action.VIEW "
        f"-d 'javascript:alert(1)' "
        f"-n {package_name}/{component_name.split('/')[-1]}"
    )

def decompile_and_find_aes_keys(apk_file, package_name):
    if "_JAVA_OPTIONS" in os.environ:
        del os.environ["_JAVA_OPTIONS"]

    vulnerabilities = []
    apk_file_abs = os.path.abspath(apk_file)
    base_dir = os.path.splitext(apk_file_abs)[0] + "_jadx"

    try:
        if os.path.exists(base_dir):
            subprocess.run(['rm', '-rf', base_dir], check=True)
        subprocess.run(
            ['jadx', '-d', base_dir, apk_file_abs],
            check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
    except subprocess.CalledProcessError as e:
        error_output = e.stderr.decode()
        print(f"{RED}Error: Failed to decompile APK with JADX '{apk_file}':\n{error_output}{RESET}")
        return vulnerabilities
    except Exception as e:
        print(f"{RED}Error: An unexpected error occurred during decompilation of '{apk_file}': {e}{RESET}")
        return vulnerabilities

    # Regex patterns for AES keys, IV, DES keys, etc.
    aes_key_pattern = re.compile(r'SecretKeySpec\(\s*["\']([A-Za-z0-9+/=]{16,32})["\']\.getBytes')
    iv_pattern = re.compile(r'IvParameterSpec\(\s*["\']([A-Za-z0-9+/=]{16,32})["\']\.getBytes')
    des_key_pattern = re.compile(r'SecretKeySpec\(\s*["\']([A-Za-z0-9+/=]{8})["\']\.getBytes')

    found_aes_keys = []
    found_ivs = []
    found_des_keys = []

    for root_dir, dirs, files in os.walk(base_dir):
        for file in files:
            if file.endswith('.java'):
                java_file = os.path.join(root_dir, file)
                try:
                    with open(java_file, 'r', encoding='utf-8') as f:
                        code = f.read()
                  
                        keys_found = aes_key_pattern.findall(code)
                        for key_val in keys_found:
                            found_aes_keys.append({
                                'key': key_val,
                                'java_file': java_file
                            })
                     
                        ivs_found = iv_pattern.findall(code)
                        for iv_val in ivs_found:
                            found_ivs.append({
                                'iv': iv_val,
                                'java_file': java_file
                            })
                        
                        des_found = des_key_pattern.findall(code)
                        for dk_val in des_found:
                            found_des_keys.append({
                                'key': dk_val,
                                'java_file': java_file
                            })
                except Exception as e:
                    print(f"{RED}Error reading file {java_file}: {e}{RESET}")


    try:
        subprocess.run(['rm', '-rf', base_dir], check=True)
    except subprocess.CalledProcessError as e:
        print(f"{RED}Error cleaning up decompiled files: {e}{RESET}")

    
    for item in found_aes_keys:
        file_name = os.path.basename(item['java_file'])
        vulnerabilities.append({
            'package_name': package_name,
            'Component': f"{package_name}/{file_name}",
            'Issue Type': 'Hardcoded AES Key',
            'Details': f"AES Key: {item['key']}",
            'ADB Command': 'N/A'
        })
    for item in found_ivs:
        file_name = os.path.basename(item['java_file'])
        vulnerabilities.append({
            'package_name': package_name,
            'Component': f"{package_name}/{file_name}",
            'Issue Type': 'Hardcoded IV',
            'Details': f"IV: {item['iv']}",
            'ADB Command': 'N/A'
        })
    for item in found_des_keys:
        file_name = os.path.basename(item['java_file'])
        vulnerabilities.append({
            'package_name': package_name,
            'Component': f"{package_name}/{file_name}",
            'Issue Type': 'Hardcoded DES Key',
            'Details': f"DES Key: {item['key']}",
            'ADB Command': 'N/A'
        })

    return vulnerabilities

def analyze_apk(args):
    """
    Extract, parse, and analyze a single APK for vulnerabilities and permissions.
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
    except Exception as e:
        print(f"{RED}Error: Failed to parse manifest file '{manifest_file}': {e}{RESET}")
        return apk_file, vulnerabilities, permissions, None

    target_sdk_version = get_target_sdk_version(root)
    if target_sdk_version is None:
        target_sdk_version = 33

    package_name = get_package_name(root)

   
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
    except subprocess.CalledProcessError as e:
        print(f"{RED}Warning: Failed to remove directory '{base_dir}': {e}{RESET}")

    return apk_file, vulnerabilities, permissions, package_name

def display_vulnerabilities_table(vulnerabilities):
    """
    Group vulnerabilities by 'package_name' and print them in a neat list.
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
        if pkg not in grouped_by_package:
            grouped_by_package[pkg] = []
        grouped_by_package[pkg].append(v)

    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>pSlip Vulnerability Report</title>
    <style>
        /* Basic reset */
        * {{
            margin: 0;
            padding: 0;
        }}
        body {{
            background-color: #ffffff;
            font-family: "Helvetica Neue", Helvetica, Arial, sans-serif;
            color: #1c1e21;
            margin: 20px;
        }}
        header {{
            background-color: #4267B2;
            padding: 20px;
            color: #fff;
            margin-bottom: 20px;
        }}
        header h1 {{
            margin: 0;
            font-size: 28px;
        }}
        .container {{
            width: 90%;
            margin: 0 auto;
        }}
        .vulnerabilities, .permissions {{
            background-color: #ffffff;
            margin-bottom: 40px;
            padding: 15px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }}
        .vulnerabilities h2, .permissions h2 {{
            color: #4267B2;
            margin-top: 0;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
            border: 1px solid #ddd;
        }}
        th, td {{
            border: 1px solid #ddd;
            text-align: left;
            padding: 8px;
            vertical-align: top;
        }}
        th {{
            background-color: #f0f2f5;
            color: #050505;
        }}
        tr:nth-child(even) {{
            background-color: #f7f7f7;
        }}
        tr:nth-child(odd) {{
            background-color: #ffffff;
        }}
        .adb-command {{
            white-space: pre-wrap;
        }}
        h3.package-title {{
            margin-top: 20px;
            margin-bottom: 10px;
        }}
    </style>
</head>
<body>
    <header>
        <h1>pSlip Vulnerability Report</h1>
    </header>
    <div class="container">
        <p>Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <div class="vulnerabilities">
            <h2>Vulnerabilities</h2>
"""

    if not vulnerabilities:
        html_content += "<p>No vulnerabilities found.</p>"
    else:
        for pkg_name, vuln_list in grouped_by_package.items():
            html_content += f"""
            <h3 class="package-title">Package: {pkg_name}</h3>
            <table>
                <tr>
                    <th>Component</th>
                    <th>Issue Type</th>
                    <th>Details</th>
                </tr>
            """
            for v in vuln_list:
                adb_command = v.get('ADB Command', 'N/A')
                adb_command_html = ""
                if adb_command != "N/A":
                    adb_command_html = (
                        "<br/><strong>ADB Command:</strong><br/>"
                        f"<span class='adb-command'>{adb_command.replace('\n', '<br/>')}</span>"
                    )

                component_full = v.get('Component', 'N/A')
                issue_type = v.get('Issue Type', 'N/A')
                details = v.get('Details', 'N/A')

                html_content += f"""
                <tr>
                    <td>{component_full}</td>
                    <td>{issue_type}</td>
                    <td>
                        {details}
                        {adb_command_html}
                    </td>
                </tr>
                """
            html_content += "</table>"

    html_content += "</div>"

    if permissions:
        html_content += """
        <div class="permissions">
            <h2>Permissions Summary</h2>
        """
        for apk_file, perms_list in permissions.items():
            apk_name = os.path.basename(apk_file)
            html_content += f"<h3>{apk_name}</h3><ul>"
            for perm in perms_list:
                html_content += f"<li>{perm}</li>"
            html_content += "</ul>"
        html_content += "</div>"

    html_content += """
    </div> <!-- /.container -->
</body>
</html>
"""

    try:
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        print(f"{GREEN}HTML report successfully generated at '{output_file}'.{RESET}")
    except Exception as e:
        print(f"{RED}Error: Failed to write HTML report to '{output_file}': {e}{RESET}")

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
        elif option == '-perm':
            collect_permission_vulns = True
        elif option == '-all':
            check_js = True
            check_call = True
            check_aes = True
            collect_permission_vulns = True
        elif option == '-allsafe':
    
            check_js = True
            check_call = True
            collect_permission_vulns = True
        elif option == '-html':
            if i + 1 < len(options):
                html_output = options[i + 1]
                skip_next = True
            else:
                print(f"{RED}Error: '-html' flag requires an output file name.{RESET}")
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
        (apk_file, list_permissions_flag, check_js, check_call, collect_permission_vulns)
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

   
    if check_aes:
        print(f"\n{BOLD}Starting AES key extraction...{RESET}\n")
        for apk_file in tqdm(apk_paths, desc="Analyzing for AES keys"):
            if not is_valid_apk(apk_file):
                continue
            pkg_name = package_names_for_apks.get(apk_file, os.path.basename(apk_file))
            aes_vulns = decompile_and_find_aes_keys(apk_file, pkg_name)
            if aes_vulns:
                all_vulnerabilities.extend(aes_vulns)

    end_time = datetime.now()
    total_time = end_time - start_time

    print(f"\n{BOLD}Vulnerability Summary:{RESET}\n")
    display_vulnerabilities_table(all_vulnerabilities)

    if html_output:
        print(f"\n{BOLD}Generating HTML report...{RESET}\n")
        generate_html_report(all_vulnerabilities, all_permissions_dict, html_output)

    if list_permissions_flag:
        print(f"\n{BOLD}Permissions Summary:{RESET}\n")
        for apk_file, perms in all_permissions_dict.items():
            print(f"{CYAN}{os.path.basename(apk_file)}:{RESET}")
            for perm in perms:
                print(f"  {perm}")
            print()

    print(f"\n{BOLD}Total Execution Time:{RESET} {total_time}")

if __name__ == "__main__":
    main()
