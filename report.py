#!/usr/bin/env python3
"""
report.py

SPDX-License-Identifier: MIT

Copyright (C) 2024, 2025  Anthony Green <green@moxielogic.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

import sqlite3
import json
import logging
import sys
import os
import re
import html
from datetime import datetime
from pathlib import Path
import hashlib
import traceback
import functools
import requests
from dateutil import parser as date_parser
import markdown
import yaml

# Constants
SCANDY_DB_FILENAME = "scandy.db"
SEVERITY_ORDER = ["", "Unknown", "Low", "Medium", "Moderate", "High", "Important", "Critical"]

# Global variables
db = None
image_name = None
ghsa_files = {}
ordered_vulns = []

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_db_connection():
    """Establish database connection and create tables if needed."""
    global db
    try:
        db = sqlite3.connect(SCANDY_DB_FILENAME)
        db.row_factory = sqlite3.Row
        logging.info(f"Connected to database {SCANDY_DB_FILENAME}")
        
        cursor = db.cursor()
        # Create RH CVE table
        cursor.execute("CREATE TABLE IF NOT EXISTS rhcve (cve TEXT PRIMARY KEY, content TEXT)")
        # Create per-run vulnerability db
        cursor.execute("CREATE TABLE IF NOT EXISTS vulns (id TEXT, age INTEGER, components TEXT, severity TEXT, image TEXT)")
        db.commit()
        
        logging.info("Validated databases")
    except Exception as e:
        logging.error(f"Database connection error: {traceback.format_exc()}")
        raise
    
    return db

class Vulnerability:
    """Base vulnerability class."""
    def __init__(self):
        self.id = None
        self.severity = None
        self.component = None
        self.title = None
        self.published_date = None
        self.description = None
        self.location = None
        self.references = []

class GrypeVulnerability(Vulnerability):
    """Grype-specific vulnerability class."""
    def __init__(self, json_data):
        super().__init__()
        self.initialize_from_json(json_data)
    
    def initialize_from_json(self, json_data):
        """Initialize from Grype JSON data."""
        vuln_data = json_data.get('vulnerability', {})
        artifact_data = json_data.get('artifact', {})
        
        self.id = vuln_data.get('id')
        grok_ghsa(self)
        
        if not self.description:
            self.description = vuln_data.get('description')
        
        self.component = artifact_data.get('name')
        
        if artifact_data.get('type') != 'rpm':
            locations = artifact_data.get('locations', [])
            if locations:
                self.location = locations[0].get('path')
        else:
            self.location = f"{artifact_data.get('name')}-{artifact_data.get('version')}"
        
        severity = vuln_data.get('severity', '')
        self.severity = capitalize_word(severity)
        self.references = self.references + vuln_data.get('urls', [])

class TrivyVulnerability(Vulnerability):
    """Trivy-specific vulnerability class."""
    def __init__(self, json_data):
        super().__init__()
        self.status = None
        self.initialize_from_json(json_data)
    
    def initialize_from_json(self, json_data):
        """Initialize from Trivy JSON data."""
        self.id = json_data.get('VulnerabilityID')
        grok_ghsa(self)
        
        severity = json_data.get('Severity', '')
        self.severity = capitalize_word(severity)
        self.status = json_data.get('Status')
        self.title = json_data.get('Title')
        
        if not self.published_date:
            pub_date = json_data.get('PublishedDate')
            if pub_date:
                parsed_date = date_parser.parse(pub_date)
                # Ensure datetime is timezone-naive
                if parsed_date.tzinfo is not None:
                    self.published_date = parsed_date.replace(tzinfo=None)
                else:
                    self.published_date = parsed_date
        
        if not self.description:
            self.description = json_data.get('Description')
        
        self.component = json_data.get('PkgName')
        self.location = f"{self.component}-{json_data.get('InstalledVersion')}"
        self.references = self.references + json_data.get('References', [])

class RedHatVulnerability(Vulnerability):
    """Red Hat-specific vulnerability class."""
    def __init__(self, json_data):
        super().__init__()
        self.initialize_from_json(json_data)
    
    def initialize_from_json(self, json_data):
        """Initialize from Red Hat JSON data."""
        self.id = json_data.get('name')
        severity = json_data.get('threat_severity', '')
        self.severity = capitalize_word(severity)
        
        details = json_data.get('details', [''])[0] if json_data.get('details') else ''
        self.description = replace_newlines_with_br(html.escape(details))
        
        self.references = json_data.get('references', [])
        
        pub_date = json_data.get('public_date')
        if pub_date:
            parsed_date = date_parser.parse(pub_date)
            # Ensure datetime is timezone-naive
            if parsed_date.tzinfo is not None:
                self.published_date = parsed_date.replace(tzinfo=None)
            else:
                self.published_date = parsed_date
        
        bugzilla = json_data.get('bugzilla', {})
        self.title = bugzilla.get('description')

def get_component(vlist):
    """Get the first component from a list of vulnerabilities."""
    for v in vlist:
        if v.component:
            return v.component
    return "?"

def capitalize_word(word):
    """Capitalize the first letter of word and make the rest lower-case."""
    if word and len(word) > 1:
        return word[0].upper() + word[1:].lower()
    return word

def extract_cve(url):
    """Extract CVE ID from URL."""
    pattern = r"CVE-\d{4}-\d{4,7}$"
    match = re.search(pattern, url)
    return match.group() if match else None

def grok_ghsa(vuln):
    """Process GitHub Security Advisory data."""
    if vuln.id and vuln.id.startswith("GHSA-"):
        ghsa_file = ghsa_files.get(vuln.id)
        if ghsa_file:
            try:
                with open(ghsa_file, 'r') as f:
                    ghjson = json.load(f)
                
                pt = ghjson.get('published')
                if pt:
                    parsed_date = date_parser.parse(pt)
                    # Ensure datetime is timezone-naive
                    if parsed_date.tzinfo is not None:
                        vuln.published_date = parsed_date.replace(tzinfo=None)
                    else:
                        vuln.published_date = parsed_date
                
                reference_list = ghjson.get('references', [])
                for reference in reference_list:
                    url = reference.get('url')
                    if url:
                        vuln.references.append(url)
                        if reference.get('type') == 'ADVISORY':
                            cveid = extract_cve(url)
                            if cveid:
                                vuln.id = cveid
                
                summary = ghjson.get('summary', '')
                details = ghjson.get('details', '')
                vuln.description = markdown.markdown(f"{summary}\n\n{details}\n")
            except Exception as e:
                logging.error(f"Error processing GHSA file {ghsa_file}: {e}")

def replace_newlines_with_br(input_string):
    """Replace newlines in input_string with <br>."""
    return input_string.replace('\n', '<br>')

def get_severity(vulns, vuln_type):
    """Get severity for specific vulnerability type."""
    for v in vulns:
        if isinstance(v, vuln_type):
            return v.severity
    return None

def grype_severity(vulns):
    return get_severity(vulns, GrypeVulnerability)

def trivy_severity(vulns):
    return get_severity(vulns, TrivyVulnerability)

def redhat_severity(vulns):
    return get_severity(vulns, RedHatVulnerability)

def get_description(vulns):
    """Get description prioritizing RedHat, then Trivy, then Grype."""
    for vuln_type in [RedHatVulnerability, TrivyVulnerability, GrypeVulnerability]:
        for v in vulns:
            if isinstance(v, vuln_type) and v.description:
                return v.description
    return ""

def vuln_sort_key(v1, v2):
    """Sort vulnerabilities."""
    # Find Trivy vulnerabilities
    trivy1 = next((v for v in v1 if isinstance(v, TrivyVulnerability)), None)
    trivy2 = next((v for v in v2 if isinstance(v, TrivyVulnerability)), None)
    
    # Debug logging
    id1 = v1[0].id if v1 else "no-id"
    id2 = v2[0].id if v2 else "no-id"
    sev1 = trivy1.severity if trivy1 else None
    sev2 = trivy2.severity if trivy2 else None
    
    if not trivy1 or not trivy2:
        # Items with Trivy data should come before items without
        if trivy1 and not trivy2:
            result = -1  # v1 has trivy, v2 doesn't - v1 comes first
        elif not trivy1 and trivy2:
            result = 1   # v1 doesn't have trivy, v2 does - v2 comes first
        else:
            result = 0   # neither has trivy - keep current order
        logging.info(f"SORT DEBUG: {id1}(trivy={bool(trivy1)}) vs {id2}(trivy={bool(trivy2)}) -> {result}")
        return result
    
    # Compare by severity - items WITH severity come before items WITHOUT severity
    if not trivy1.severity or not trivy2.severity:
        if trivy1.severity and not trivy2.severity:
            result = -1  # v1 has severity, v2 doesn't - v1 comes first
            logging.info(f"SORT DEBUG: {id1}(sev={sev1}) vs {id2}(sev={sev2}) -> {result} (v1 has sev)")
            return result
        elif not trivy1.severity and trivy2.severity:
            result = 1   # v1 doesn't have severity, v2 does - v2 comes first
            logging.info(f"SORT DEBUG: {id1}(sev={sev1}) vs {id2}(sev={sev2}) -> {result} (v2 has sev)")
            return result
        else:
            result = 0   # both have no severity - keep current order
            logging.info(f"SORT DEBUG: {id1}(sev={sev1}) vs {id2}(sev={sev2}) -> {result} (both no sev)")
            return result
    
    if trivy1.severity != trivy2.severity:
        idx1 = SEVERITY_ORDER.index(trivy1.severity) if trivy1.severity in SEVERITY_ORDER else 999
        idx2 = SEVERITY_ORDER.index(trivy2.severity) if trivy2.severity in SEVERITY_ORDER else 999
        result = idx2 - idx1  # Reversed: higher severity (lower index) comes first
        logging.info(f"SORT DEBUG: {id1}(sev={sev1},idx={idx1}) vs {id2}(sev={sev2},idx={idx2}) -> {result} (diff sev)")
        return result
    
    # Compare by ID
    id1, id2 = trivy1.id, trivy2.id
    if id1[:8] != id2[:8]:
        result = -1 if id1 < id2 else 1
        logging.info(f"SORT DEBUG: {id1} vs {id2} -> {result} (diff id prefix)")
        return result
    
    # Compare by CVE number
    if '-' in id1 and '-' in id2:
        try:
            n1 = int(id1.split('-')[-1])
            n2 = int(id2.split('-')[-1])
            result = n1 - n2
            logging.info(f"SORT DEBUG: {id1}(n={n1}) vs {id2}(n={n2}) -> {result} (cve num)")
            return result
        except:
            pass
    
    result = -1 if id1 < id2 else 1
    logging.info(f"SORT DEBUG: {id1} vs {id2} -> {result} (final string)")
    return result

def reference_sort(r1, r2):
    """Order references by preference."""
    patterns = [
        "access.redhat.com/security/cve",
        "access.redhat.com/errata",
        "nist.gov",
        "cve.org",
        "bugzilla.redhat",
        "bugzilla",
        "fedora"
    ]
    
    for pattern in patterns:
        if pattern in r1 and pattern not in r2:
            return -1
        if pattern not in r1 and pattern in r2:
            return 1
    
    return -1 if r1 < r2 else 1

def collect_references(cve_id, vulns):
    """Collect and deduplicate references."""
    refs = []
    
    # Add RedHat CVE link if it's a CVE
    if cve_id.startswith("CVE-"):
        refs.append(f"https://access.redhat.com/security/cve/{cve_id}")
    
    # Collect all references
    for v in vulns:
        if v.references:
            for r in v.references:
                # Split on whitespace
                expanded = re.split(r'\s+', r)
                refs.extend(expanded)
    
    # Remove duplicates and sort
    unique_refs = list(set(refs))
    return sorted(unique_refs, key=lambda x: (reference_sort(x, "") * -1, x))

def collect_locations(vulns):
    """Collect unique locations."""
    locations = []
    for v in vulns:
        if v.location:
            locations.append(v.location)
    return sorted(list(set(locations)))

def collect_components(vulns):
    """Collect unique components."""
    components = []
    for v in vulns:
        if v.component:
            components.append(v.component)
    return sorted(list(set(components)))

def get_redhat_security_data(cve_id):
    """Get Red Hat security data from cache or API."""
    cursor = db.cursor()
    cursor.execute("SELECT content FROM rhcve WHERE cve = ?", (cve_id,))
    row = cursor.fetchone()
    
    if row:
        logging.info(f"Found cached redhat security API response for {cve_id}")
        return row[0]
    
    try:
        response = requests.get(f"https://access.redhat.com/hydra/rest/securitydata/cve/{cve_id}")
        if response.status_code == 200:
            content = response.text
            cursor.execute("INSERT INTO rhcve (cve, content) VALUES (?, ?)", (cve_id, content))
            db.commit()
            logging.info(f"Caching redhat security API response for {cve_id}")
            return content
        elif response.status_code == 404:
            return f"Red Hat is not tracking {cve_id}"
    except Exception as e:
        logging.error(f"Error fetching Red Hat security data: {e}")
        return None

def check_pattern(items, pattern_type, pattern):
    """Check if any item matches the pattern."""
    if not items:
        return False
    
    for item in items:
        if pattern_type == "contains":
            if pattern in item:
                return True
        elif pattern_type == "startswith":
            if item.startswith(pattern):
                return True
        elif pattern_type == "endswith":
            if item.endswith(pattern):
                return True
        elif pattern_type == "regex":
            if re.search(pattern, item):
                return True
    return False

def get_opinion(cve, components, locations, image):
    """Load opinions from YAML and find matching opinion."""
    if cve == "CVE-2022-27943":
        logging.info(f"DEBUG: Looking for opinion: cve={cve}, components={components}, locations={locations}, image={image}")
    try:
        with open('opinions.yaml', 'r') as f:
            opinions_data = yaml.safe_load(f)
    except FileNotFoundError:
        logging.warning("opinions.yaml not found, no opinions will be provided")
        return None
    
    # Check each opinion rule
    for rule in opinions_data.get('opinions', []):
        # Check CVE match (single or multiple)
        if 'cve' in rule:
            if rule['cve'] != cve:
                continue
        elif 'cves' in rule:
            if cve not in rule['cves']:
                continue
        elif 'components' not in rule:
            # Must have either CVE(s) or components to match
            continue
        
        # Check component conditions
        if 'components' in rule:
            # Default behavior: all vulnerability components must be from rule's set
            # This matches Lisp: (every (lambda (x) (member x rule-components)) vuln-components)
            if not all(comp in rule['components'] for comp in components):
                if cve == "CVE-2022-27943":
                    logging.info(f"DEBUG: Rule {rule.get('cve', 'no-cve')} components check failed: vuln_components={components}, rule_components={rule['components']}")
                continue
            else:
                if cve == "CVE-2022-27943":
                    logging.info(f"DEBUG: Rule {rule.get('cve', 'no-cve')} components check passed: vuln_components={components}, rule_components={rule['components']}")
        
        if 'components_exact' in rule:
            # Exact match required - lists must be identical
            # This matches Lisp: (equal components '(...))
            if set(components) != set(rule['components_exact']):
                continue
        
        if 'all_components' in rule:
            # Explicit: ALL components must be present
            if not all(comp in components for comp in rule['all_components']):
                continue
        
        if 'any_components' in rule:
            # ANY component can match
            if not any(comp in components for comp in rule['any_components']):
                continue
        
        if 'components_exclude' in rule:
            # These components must NOT be present
            if any(comp in components for comp in rule['components_exclude']):
                continue
        
        # Check location patterns
        if 'locations' in rule:
            # Exact location matches
            if not all(loc in locations for loc in rule['locations']):
                continue
        
        if 'locations_pattern' in rule:
            # Pattern matching for locations
            if ':' in rule['locations_pattern']:
                pattern_type, pattern = rule['locations_pattern'].split(':', 1)
                if not check_pattern(locations, pattern_type, pattern):
                    continue
        
        if 'locations_exclude' in rule:
            # Exclusion pattern - must NOT match
            if ':' in rule['locations_exclude']:
                pattern_type, pattern = rule['locations_exclude'].split(':', 1)
                if check_pattern(locations, pattern_type, pattern):
                    continue  # Skip if pattern matches (exclusion)
        
        # Check image condition
        if 'image' in rule:
            if rule['image'] != image:
                continue
        
        # All conditions passed, return the opinion
        if cve == "CVE-2022-27943":
            logging.info(f"DEBUG: Found matching opinion for {cve}: {rule.get('status')}")
        return (rule.get('status'), rule.get('description'))
    
    return None

def opinion_style(opinion):
    """Get CSS style for opinion."""
    if opinion:
        return "background-color: #daffb9; border-top: 1px solid #eee; border-bottom: 1px solid #eee;"
    return "border-top: 1px solid #eee; border-bottom: 1px solid #eee;"

def severity_style(severity):
    """Get CSS style for severity."""
    if severity == "Critical":
        return "background-color: #ffcccc; border-top: 1px solid #eee; border-bottom: 1px solid #eee;"
    elif severity in ["High", "Important"]:
        return "background-color: #ffdab9; border-top: 1px solid #eee; border-bottom: 1px solid #eee;"
    elif severity in ["Medium", "Moderate"]:
        return "background-color: #ffffcc; border-top: 1px solid #eee; border-bottom: 1px solid #eee;"
    return ""

def severity_class(severity):
    """Get CSS class for severity."""
    if severity == "Critical":
        return "severity-Critical"
    elif severity in ["High", "Important"]:
        return "severity-High"
    elif severity in ["Medium", "Moderate"]:
        return "severity-Medium"
    return ""

def generate_modal_html(vulns_list):
    """Generate modal HTML for vulnerabilities."""
    modals = []
    for vulns in vulns_list:
        vuln_id = vulns[0].id
        components = collect_components(vulns)
        locations = collect_locations(vulns)
        opinion = get_opinion(vuln_id, components, locations, image_name)
        
        modal_html = f'''
<div class="modal fade" id="{vuln_id}-modal" tabindex="-1" aria-labelledby="{vuln_id}-modalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg">
        <div class="modal-content">
            <div class="modal-header">
                <h5 class="modal-title" id="{vuln_id}-modalLabel">{image_name}</h5>
                <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
                <h2>Security Advisory: {vuln_id}</h2>
'''
        
        if opinion:
            modal_html += f'''
                <h3>ubi-micro-dev Opinion: </h3>
                {opinion[1]}
'''
        
        modal_html += f'''
                <h3>Description:</h3> {get_description(vulns)}
'''
        
        if locations:
            modal_html += '''
                <h3>Locations:</h3>
                <ul>
'''
            for location in locations:
                modal_html += f'                    <li>{location}</li>\n'
            modal_html += '                </ul>\n'
        
        modal_html += '''
                <h3>References:</h3>
                <ul>
'''
        for url in collect_references(vuln_id, vulns):
            modal_html += f'                    <li><a href="{url}" target="_blank">{url}</a></li>\n'
        
        modal_html += '''
                </ul>
            </div>
        </div>
    </div>
</div>
'''
        modals.append(modal_html)
    
    return '\n'.join(modals)

def generate_page_template(content, title="ubi-micro-dev", index="false"):
    """Generate the full HTML page template."""
    modals_html = generate_modal_html(ordered_vulns)
    
    return f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <link rel="apple-touch-icon" sizes="180x180" href="https://raw.githubusercontent.com/atgreen/scandy/main/images/scandy-180x180.png">
    <link rel="icon" type="image/png" sizes="32x32" href="https://raw.githubusercontent.com/atgreen/scandy/main/images/scandy-32x32.png">
    <link rel="icon" type="image/png" sizes="16x16" href="https://raw.githubusercontent.com/atgreen/scandy/main/images/scandy-16x16.png">
    <meta name="msapplication-TileColor" content="#da532c">
    <meta name="theme-color" content="#ffffff">
    <title>{title}</title>
    <link rel="stylesheet" href="css/bootstrap.min.css">
    <link rel="stylesheet" href="css/jquery.dataTables.min.css">
    <link rel="stylesheet" href="css/buttons.dataTables.min.css">
    <style>
        body {{
            padding-top: 65px;
            margin-bottom: 60px;
            font-family: "Trebuchet MS", Arial, Helvetica, sans-serif;
        }}
        .navbar-brand {{
            font-size: 1.5rem;
        }}
        h1, h2 {{
            margin: 20px 0;
        }}
        table {{
            width: 100%;
        }}
        table th, table td {{
            padding: .75rem;
            text-align: left;
            border: 1px solid #ddd;
        }}
        .bg-critical {{
            background-color: #ff4d4d;
            color: white;
        }}
        .bg-low {{
            background-color: #d4edda;
            color: #155724;
        }}
        tbody tr:nth-child(odd) {{
            background-color: #f9f9f9;
        }}
        tbody tr:nth-child(even) {{
            background-color: #ffffff;
        }}
        tbody tr:hover {{
            background-color: #f1f1f1;
        }}
        .footer {{
            background-color: #f5f5f5;
            padding: 20px 0;
        }}
        .modal-body ul {{
            padding-left: 20px;
        }}
        .modal-body h3 {{
            margin-top: 20px;
        }}
        .dt-buttons {{
            margin-bottom: 10px;
        }}
        .filter-checkbox {{
            margin-left: 10px;
            margin-bottom: 10px;
            display: inline-block;
        }}
        .no-wrap {{
            white-space: nowrap;
            word-break: keep-all;
            overflow-wrap: normal;
        }}
    </style>
</head>
<body>
    <nav class="navbar navbar-expand-md navbar-dark fixed-top bg-dark">
        <div class="container-fluid">
            <a class="navbar-brand" href="https://ubi-micro-dev.github.io/ubi-micro-dev/"><img src="https://raw.githubusercontent.com/ubi-micro-dev/ubi-micro-dev/main/images/scandy-32x32.png" alt="" width="30" height="30"></a>
            <a class="navbar-brand" href="https://ubi-micro-dev.github.io/ubi-micro-dev/">ubi-micro-dev</a>
        </div>
    </nav>
    <main class="container" role="main">
        <div class="row">
            <div class="col">
                {content}
            </div>
        </div>
    </main>
    <footer class="footer">
        <div class="container">
            <div class="text-center py-3">&copy; 2025 <a href="https://linkedin.com/in/green">Anthony Green</a></div>
            <p>ubi-micro-dev is an experiment by <a href="https://linkedin.com/in/green">Anthony Green</a>, the source code for which is available under the terms of the MIT license at <a href="https://github.com/ubi-micro-dev/ubi-micro-dev">https://github.com/ubi-micro-dev</a>. ubi-micro-dev 'opinions' are not comprehensive and in some cases may be incorrect. Submit new opinions as pull requests, and questions or comments as <a href="https://github.com/ubi-micro-dev/ubi-micro-dev/issues/new">github issues</a>.</p>
        </div>
    </footer>
    {modals_html}
    <script src="js/jquery-3.3.1.slim.min.js"></script>
    <script src="js/jquery.dataTables.min.js"></script>
    <script src="js/dataTables.buttons.min.js"></script>
    <script src="js/jszip.min.js"></script>
    <script src="js/buttons.html5.min.js"></script>
    <script src="js/buttons.print.min.js"></script>
    <script src="js/pdfmake.min.js"></script>
    <script src="js/vfs_fonts.js"></script>
    <script src="js/popper.min.js"></script>
    <script src="js/bootstrap.bundle.min.js"></script>
    <script>
        var table;
        
        $(document).ready(function() {{
            // Custom sorting for severity levels
            $.fn.dataTable.ext.type.order['severity-pre'] = function (d) {{
                switch (d) {{
                    case 'Critical': return 1;
                    case 'High': return 2;
                    case 'Important': return 2;
                    case 'Medium': return 3;
                    case 'Moderate': return 3;
                    case 'Low': return 4;
                    default: return 5;
                }}
            }};
            
            // Custom sorting for Age column
            $.fn.dataTable.ext.type.order['age-pre'] = function (d) {{
                return d === '?' ? 999999 : parseInt(d, 10);
            }};
            
            {'table = $("#results").DataTable({' if index != "true" else 'table = $("#results").DataTable({'}
                "paging": false,
                "info": true,
                "searching": true,
                "order": {'[]' if index != "true" else '[[1,"asc"]]'},
                "columnDefs": [
                    {{ "type": "severity", "targets": [{3 if index != "true" else 3}, {4 if index != "true" else ''}, {5 if index != "true" else ''}] }},
                    {{ "type": "age", "targets": [1] }}
                ],
                dom: 'Bfrtip',
                buttons: [
                    'copy', 'csv', 'pdf'
                ]
            }});
            
            $('[data-bs-toggle="tooltip"]').tooltip();
        }});
        
        function filterSeverity(severity) {{
            $('#results').DataTable().search(severity).draw();
        }}
        
        var filterOn = true;
        
        $('#toggle-filter').on('click', function () {{
            filterOn = !filterOn;
            table.draw();
        }});
        
        $.fn.dataTable.ext.search.push(
            function(settings, data, dataIndex) {{
                if (!filterOn) {{
                    return true;
                }}
                return !data[2].includes('kernel-headers');
            }}
        );
        
        document.addEventListener('DOMContentLoaded', (event) => {{
            // Get the server timestamp from the data attribute
            const serverTimestampElement = document.getElementById('server-timestamp');
            const serverTimestamp = serverTimestampElement.getAttribute('data-timestamp');
            
            // Convert server timestamp to local timezone
            const localDate = new Date(serverTimestamp);
            const options = {{
                year: 'numeric', month: 'long', day: 'numeric',
                hour: '2-digit', minute: '2-digit', second: '2-digit',
                timeZoneName: 'short'
            }};
            const localTimestamp = localDate.toLocaleString(undefined, options);
            
            // Display the local timestamp
            serverTimestampElement.textContent = localTimestamp;
        }});
    </script>
</body>
</html>'''

def main():
    """Main function."""
    global db, image_name, ghsa_files, ordered_vulns
    
    if len(sys.argv) < 5:
        print("Usage: python report.py <report_file> <grype_file> <trivy_file> <image_name>")
        sys.exit(1)
    
    report_filename = sys.argv[1]
    grype_filename = sys.argv[2]
    trivy_filename = sys.argv[3]
    image_name = sys.argv[4]
    
    # Load vulnerability data
    with open(grype_filename, 'r') as f:
        grype_json = json.load(f)
    
    with open(trivy_filename, 'r') as f:
        trivy_json = json.load(f)
    
    # Build GHSA files index
    ghsa_files = {}
    logging.info("Scanning github security advisory database")
    advisory_path = Path("advisory-database/advisories/")
    if advisory_path.exists():
        for f in advisory_path.rglob("*.json"):
            ghsa_files[f.stem] = f
    
    logging.info("Establishing database connection")
    get_db_connection()
    
    logging.info("STARTING ANALYSIS")
    
    vuln_table = {}
    
    # Process Grype results
    matches = grype_json.get('matches', [])
    for vuln_json in matches:
        vuln = GrypeVulnerability(vuln_json)
        if vuln.id not in vuln_table:
            vuln_table[vuln.id] = []
        vuln_table[vuln.id].append(vuln)
    
    # Process Trivy results
    results = trivy_json.get('Results', [])
    for vgroup in results:
        vulns = vgroup.get('Vulnerabilities', [])
        for vuln_json in vulns:
            vuln = TrivyVulnerability(vuln_json)
            if vuln.id not in vuln_table:
                vuln_table[vuln.id] = []
            vuln_table[vuln.id].append(vuln)
    
    # Create Red Hat vulnerability records
    for cve_id, vulns in vuln_table.items():
        try:
            rh_data = get_redhat_security_data(cve_id)
            if rh_data and not rh_data.startswith("Red Hat is not tracking"):
                rh_json = json.loads(rh_data)
                rh_vuln = RedHatVulnerability(rh_json)
                vuln_table[cve_id].append(rh_vuln)
        except Exception as e:
            logging.error(f"Error processing Red Hat data for {cve_id}: {traceback.format_exc()}")
    
    logging.info(f"SORTING VULNS: {len(vuln_table)} unique vulnerabilities")
    
    # Sort vulnerabilities using comparison function
    ordered_vulns = sorted(vuln_table.values(), key=functools.cmp_to_key(vuln_sort_key))
    
    # Generate report
    now = datetime.now()
    timestamp = now.isoformat()
    
    table_rows = []
    for vulns in ordered_vulns:
        vuln_id = vulns[0].id
        components = collect_components(vulns)
        locations = collect_locations(vulns)
        opinion = get_opinion(vuln_id, components, locations, image_name)
        
        # Calculate age
        age = "?"
        for v in vulns:
            if v.published_date:
                # Convert published_date to naive datetime if it has timezone info
                pub_date = v.published_date
                if pub_date.tzinfo is not None:
                    pub_date = pub_date.replace(tzinfo=None)
                age_days = (now - pub_date).days
                age = str(age_days)
                
                # Store in database
                cursor = db.cursor()
                cursor.execute(
                    "INSERT INTO vulns (id, age, components, severity, image) VALUES (?, ?, ?, ?, ?)",
                    (vuln_id, age_days, " ".join(components), redhat_severity(vulns), image_name)
                )
                db.commit()
                break
        
        row_html = f'''
        <tr class="{severity_class(redhat_severity(vulns))}" data-bs-toggle="modal" data-bs-target="#{vuln_id}-modal">
            <td class="no-wrap">{vuln_id}</td>
            <td>{age}</td>
            <td>{" ".join(components)}</td>
            <td style="{severity_style(trivy_severity(vulns))}">{trivy_severity(vulns) or ""}</td>
            <td style="{severity_style(grype_severity(vulns))}">{grype_severity(vulns) or ""}</td>
            <td style="{severity_style(redhat_severity(vulns))}">{redhat_severity(vulns) or ""}</td>
            <td style="{opinion_style(opinion)}">{opinion[0] if opinion else ""}</td>
        </tr>'''
        table_rows.append(row_html)
    
    content = f'''
        <h1>{image_name}</h1>
        <h2>With RPM updates as of <span id="server-timestamp" data-timestamp="{timestamp}"></span></h2>
        <div class="dt-buttons btn-group">
            <button class="btn" style="background-color: #bbbbbb; border: 1px solid #000" onclick="filterSeverity('')">All</button>
            <button class="btn" style="background-color: #ffcccc; border: 1px solid #000" onclick="filterSeverity('Critical')">Critical</button>
            <button class="btn" style="background-color: #ffdab9; border: 1px solid #000" onclick="filterSeverity('High')">High</button>
            <button class="btn" style="background-color: #ffffcc; border: 1px solid #000" onclick="filterSeverity('Medium')">Medium</button>
            <button class="btn" style="border: 1px solid #000" onclick="filterSeverity('Low')">Low</button>
            <div class="form-check filter-checkbox">
                <input class="form-check-input" type="checkbox" value="" id="toggle-filter">
                <label class="form-check-label" for="toggle-filter">
                    Show kernel-headers
                </label>
            </div>
        </div>
        <table class="table table-hover" id="results">
            <thead class="thead-dark">
                <tr>
                    <th>ID</th>
                    <th>Age</th>
                    <th>Component</th>
                    <th>Trivy Severity</th>
                    <th>Grype Severity</th>
                    <th>Red Hat Severity</th>
                    <th>ubi-micro-dev Opinion</th>
                </tr>
            </thead>
            <tbody>
                {''.join(table_rows)}
            </tbody>
        </table>'''
    
    html = generate_page_template(content, title="ubi-micro-dev", index="false")
    
    with open(report_filename, 'w') as f:
        f.write(html)
    
    db.close()

def make_index_html():
    """Generate index.html from database."""
    global db
    
    db = sqlite3.connect(SCANDY_DB_FILENAME)
    db.row_factory = sqlite3.Row
    
    cursor = db.cursor()
    cursor.execute("SELECT id, age, components, severity, image FROM vulns WHERE age <= 90 ORDER BY age ASC")
    rows = cursor.fetchall()
    
    vulns = {}
    for row in rows:
        cve_id = row['id']
        age = row['age']
        components = row['components']
        severity = row['severity']
        image = row['image']
        
        if cve_id not in vulns:
            vulns[cve_id] = []
        vulns[cve_id].append((age, components, severity, image))
    
    # Generate index content
    table_rows = []
    for cve_id, data_list in vulns.items():
        # Get unique components
        all_components = set()
        for data in data_list:
            comps = data[1].split()
            all_components.update(comps)
        
        # Get images list
        images_html = []
        for data in data_list:
            image_name = data[3]
            image_file = image_name.replace('/', '--').replace(':', '--') + '.html'
            images_html.append(f'<li><a href="{image_file}">{image_name}</a></li>')
        
        row_html = f'''
        <tr>
            <td class="no-wrap">{cve_id}</td>
            <td>{data_list[0][0]}</td>
            <td><ul>{''.join(f"<li>{comp}</li>" for comp in sorted(all_components) if comp)}</ul></td>
            <td style="{severity_style(data_list[0][2])}">{data_list[0][2]}</td>
            <td><ul>{''.join(images_html)}</ul></td>
        </tr>'''
        table_rows.append(row_html)
    
    content = f'''
        <br>
        <center>
            <a href="https://github.com/ubi-micro-dev/ubi-micro-dev/blob/main/README.md">✨ <b>Start Here: Read About <code>ubi-micro-dev</code> Images</b> ✨</a>
        </center>
        <br>
        <h2>Available Images</h2>
        <table class="table table-hover">
            <thead class="thead-dark">
                <tr><th>Technology</th><th>Images</th></tr>
            </thead>
            <tbody>
                <tr><td>Java</td><td><ul>
                    <li><a href="ghcr.io--ubi-micro-dev--ubi9-micro-dev-openjdk-21--latest.html">ghcr.io/ubi-micro-dev/ubi9-micro-dev-openjdk-21</a></li>
                    <li><a href="ghcr.io--ubi-micro-dev--ubi9-micro-dev-openjdk-17--latest.html">ghcr.io/ubi-micro-dev/ubi9-micro-dev-openjdk-17</a></li>
                    <li><a href="ghcr.io--ubi-micro-dev--ubi9-micro-dev-openjdk-8--latest.html">ghcr.io/ubi-micro-dev/ubi9-micro-dev-openjdk-8</a></li>
                    <li><a href="ghcr.io--ubi-micro-dev--ubi8-micro-dev-openjdk-21--latest.html">ghcr.io/ubi-micro-dev/ubi8-micro-dev-openjdk-21</a></li>
                    <li><a href="ghcr.io--ubi-micro-dev--ubi8-micro-dev-openjdk-17--latest.html">ghcr.io/ubi-micro-dev/ubi8-micro-dev-openjdk-17</a></li>
                    <li><a href="ghcr.io--ubi-micro-dev--ubi8-micro-dev-openjdk-8--latest.html">ghcr.io/ubi-micro-dev/ubi8-micro-dev-openjdk-8</a></li>
                </ul></td></tr>
                <tr><td>Node.js</td><td><ul>
                    <li><a href="ghcr.io--ubi-micro-dev--ubi9-micro-dev-nodejs-22--latest.html">ghcr.io/ubi-micro-dev/ubi9-micro-dev-nodejs-22</a></li>
                    <li><a href="ghcr.io--ubi-micro-dev--ubi9-micro-dev-nodejs-18--latest.html">ghcr.io/ubi-micro-dev/ubi9-micro-dev-nodejs-18</a></li>
                    <li><a href="ghcr.io--ubi-micro-dev--ubi9-micro-dev-nodejs-16--latest.html">ghcr.io/ubi-micro-dev/ubi9-micro-dev-nodejs-16</a></li>
                    <li><a href="ghcr.io--ubi-micro-dev--ubi8-micro-dev-nodejs-22--latest.html">ghcr.io/ubi-micro-dev/ubi8-micro-dev-nodejs-22</a></li>
                    <li><a href="ghcr.io--ubi-micro-dev--ubi8-micro-dev-nodejs-20--latest.html">ghcr.io/ubi-micro-dev/ubi8-micro-dev-nodejs-20</a></li>
                    <li><a href="ghcr.io--ubi-micro-dev--ubi8-micro-dev-nodejs-18--latest.html">ghcr.io/ubi-micro-dev/ubi8-micro-dev-nodejs-18</a></li>
                    <li><a href="ghcr.io--ubi-micro-dev--ubi8-micro-dev-nodejs-16--latest.html">ghcr.io/ubi-micro-dev/ubi8-micro-dev-nodejs-16</a></li>
                </ul></td></tr>
                <tr><td>Python</td><td><ul>
                    <li><a href="ghcr.io--ubi-micro-dev--ubi9-micro-dev-python-3.12--latest.html">ghcr.io/ubi-micro-dev/ubi9-micro-dev-python-3.12</a></li>
                    <li><a href="ghcr.io--ubi-micro-dev--ubi8-micro-dev-python-3.12--latest.html">ghcr.io/ubi-micro-dev/ubi8-micro-dev-python-3.12</a></li>
                </ul></td></tr>
            </tbody>
        </table>
        <br>
        <h2>New CVEs from the last 90 days</h2>
        <div class="form-check filter-checkbox">
            <input class="form-check-input" type="checkbox" value="" id="toggle-filter">
            <label class="form-check-label" for="toggle-filter">
                Show kernel-headers
            </label>
        </div>
        <table class="table table-hover" id="results">
            <thead class="thead-dark">
                <tr><th>ID</th><th>Age</th><th>Components</th><th>Red Hat Severity</th><th>Images</th></tr>
            </thead>
            <tbody>
                {''.join(table_rows)}
            </tbody>
        </table>'''
    
    html = generate_page_template(content, title="ubi-micro-dev", index="true")
    
    with open("index.html", 'w') as f:
        f.write(html)
    
    db.close()

if __name__ == "__main__":
    # Check if called to make index
    if len(sys.argv) == 2 and sys.argv[1] == "make-index":
        make_index_html()
    elif len(sys.argv) == 5:
        # Standard invocation: report.py <output_file> <grype_json> <trivy_json> <image_name>
        main()
    else:
        print("Usage:")
        print("  python report.py <output_file> <grype_json> <trivy_json> <image_name>")
        print("  python report.py make-index")
        sys.exit(1)