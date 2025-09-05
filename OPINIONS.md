# opinions.yaml Documentation

## Overview

The `opinions.yaml` file contains security vulnerability opinions for
the ubi-micro-dev project. These opinions help classify
vulnerabilities as false positives, ignorable issues, or removable
components, providing context and guidance for security assessments.

## File Structure

```yaml
opinions:
  - cve: <string>               # Single CVE identifier
    cves: [<list>]              # Multiple CVE identifiers (OR logic)
    components: [<list>]        # Simple component list (ALL must match)
    all_components: [<list>]    # Explicit: ALL components must be present
    any_components: [<list>]    # Explicit: ANY component can match
    locations: [<list>]         # Exact location matches
    locations_pattern: <string> # Pattern matching for locations
    locations_exclude: <string> # Exclusion pattern for locations
    image: <string>             # Specific container image
    status: <string>            # Opinion status
    description: <string>       # HTML description
```

## Field Descriptions

### CVE Matching

- **`cve`**: Single CVE identifier (e.g., `CVE-2024-12345`)
- **`cves`**: List of CVE identifiers. If ANY of these match, the rule applies

### Component Matching

- **`components`**: Subset match - ALL vulnerability components must be from this set
- **`components_exact`**: Exact match - vulnerability components must be exactly this list (order-independent)
- **`all_components`**: Explicit AND logic - ALL listed components must be present in the vulnerability
- **`any_components`**: OR logic - at least ONE component must match
- **`components_exclude`**: Components that must NOT be present

### Location Matching

- **`locations`**: Exact match for file paths or package locations
- **`locations_pattern`**: Pattern-based matching with format `<type>:<pattern>`
  - `contains:text` - Location contains the text
  - `startswith:text` - Location starts with the text
  - `endswith:text` - Location ends with the text
  - `regex:pattern` - Location matches the regex pattern
- **`locations_exclude`**: Pattern that must NOT match (same format as locations_pattern)

### Other Fields

- **`image`**: Specific container image name (exact match)
- **`status`**: Classification of the opinion
  - `"False Positive"` - Not actually vulnerable
  - `"Ignorable"` - Can be safely ignored
  - `"Removable"` - Component can be removed
  - `"Ignorable & Removable"` - Both apply
- **`description`**: HTML-formatted explanation (supports `<code>`, `<pre>`, `<a>`, etc.)

## Matching Logic

Rules are evaluated in order. The first matching rule is applied. For a rule to match:

1. The CVE must match (single `cve` or one of `cves`)
2. ALL additional conditions must be satisfied
3. Exclusion patterns must NOT match

## Examples

### Simple CVE Match
```yaml
- cve: CVE-2025-32990
  status: "False Positive"
  description: "This vulnerability has been fixed..."
```

### Multiple CVEs with Same Opinion
```yaml
- cves: [CVE-2024-21147, CVE-2024-21217, CVE-2024-21068]
  status: "False Positive"
  description: "These vulnerabilities have been fixed in the upstream..."
```

### Component Requirements
```yaml
# ALL components must be present
- cve: CVE-2022-27943
  all_components: [libgcc, libstdc++]
  status: "False Positive"
  description: "Neither libgcc nor libstdc++ contain..."

# ANY component can match
- cves: [CVE-2025-30749, CVE-2025-50059]
  any_components: [java-17-openjdk-headless, java-21-openjdk-headless]
  status: "False Positive"
  description: "Red Hat is reporting that this CVE was fixed..."
```

### Pattern Matching
```yaml
# Location contains pattern
- cve: CVE-2025-31344
  locations_pattern: "contains:headless"
  status: "False Positive"
  description: "The OpenJDK headless packages..."

# Location must NOT start with pattern
- cve: CVE-2022-41409
  locations_exclude: "startswith:pcre2-tools"
  status: "False Positive"
  description: "Only affects pcre2-tools..."
```

### Complex Rule with Multiple Conditions
```yaml
- cve: CVE-2024-6345
  locations_pattern: "contains:/opt/app-root"
  any_components: [setuptools, python3-setuptools]
  image: registry.redhat.io/ubi8/python-39
  status: "False Positive"
  description: "This container image contains a fixed version..."
```

### Component-Only Rules (No CVE)
```yaml
# Removable components based on component name only
- components: [httpd, httpd-core, mod_ssl]
  status: "Removable"
  description: |
    These Apache packages may not be required. Remove with:
    <pre>
    RUN rpm -e httpd httpd-core mod_ssl
    </pre>
```

## Pattern Types

### contains
Checks if the pattern appears anywhere in the string:
```yaml
locations_pattern: "contains:/usr/lib/jenkins"
```

### startswith
Checks if the string starts with the pattern:
```yaml
locations_pattern: "startswith:python3-"
```

### endswith
Checks if the string ends with the pattern:
```yaml
locations_pattern: "endswith:.jar"
```

### regex
Uses Python regular expressions for complex matching:
```yaml
locations_pattern: "regex:^/opt/jboss/.*/jackson-databind-.*\.jar$"
```

## Best Practices

1. **Order matters**: Place more specific rules before general ones
2. **Use appropriate patterns**: Choose the simplest pattern type that works
3. **Document thoroughly**: Include links and references in descriptions
4. **Test rules**: Verify that rules match intended vulnerabilities
5. **Group related CVEs**: Use `cves` list for multiple CVEs with same fix
6. **Be specific**: Use multiple conditions to avoid false matches
7. **HTML formatting**: Use HTML tags in descriptions for better readability

## Status Types Guide

### False Positive
The vulnerability doesn't actually affect this configuration:
- Vulnerable code not present in the package
- Already fixed but metadata not updated
- Applies to different package from same source

### Ignorable
The vulnerability exists but can be safely ignored:
- Disputed or rejected CVEs
- Documentation-only issues
- Build-time only vulnerabilities

### Removable
The component can be removed to eliminate the vulnerability:
- Optional dependencies
- Development tools in production images
- Unused features

### Ignorable & Removable
Both conditions apply - it's safe to ignore but better to remove.

## Validation

To validate your opinions.yaml:

```python
import yaml

with open('opinions.yaml', 'r') as f:
    data = yaml.safe_load(f)

for rule in data['opinions']:
    # Must have either cve or cves
    if 'cve' not in rule and 'cves' not in rule and 'components' not in rule:
        print(f"Rule missing CVE or component matcher: {rule}")

    # Must have status and description
    if 'status' not in rule or 'description' not in rule:
        print(f"Rule missing status or description: {rule}")
```
