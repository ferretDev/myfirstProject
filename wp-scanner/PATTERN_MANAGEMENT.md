# Malware Pattern Management System

Complete guide to managing, customizing, and updating malware detection patterns in WordPress Security Scanner v2.0

---

## 🎯 Overview

The pattern management system allows you to:
- **View** all default and custom malware patterns
- **Add** custom patterns for specific threats
- **Test** patterns before deployment
- **Export** patterns for backup or sharing
- **Import** patterns from other sources
- **Update** pattern database without modifying core files

---

## 📋 Default Pattern Categories

### 1. Code Patterns
Detects malicious PHP code execution:
- **Obfuscation**: base64_decode, gzinflate, str_rot13, hex encoding
- **PHP Execution**: eval(), assert(), create_function(), system(), exec()
- **File Operations**: file_get_contents(), file_put_contents(), curl
- **Backdoors**: c99shell, r57shell, wso, password backdoors
- **SQL Injection**: UNION SELECT, SQL comments

### 2. Spam Patterns
Identifies spam content:
- **Pharma Spam**: viagra, cialis, prescription drugs
- **Gambling**: casino, poker, betting
- **Adult Content**: explicit keywords
- **Link Spam**: hidden links, excessive anchors
- **SEO Spam**: keyword stuffing

### 3. URL Patterns
Suspicious external connections:
- **Malicious Domains**: Known bad actors
- **C&C Servers**: Command and control
- **Data Exfiltration**: Suspicious outbound connections
- **Remote Scripts**: External code execution

### 4. User Agent Patterns
Malicious crawlers and bots:
- **Attack Tools**: SQLmap, Nikto, Acunetix
- **Scrapers**: Content thieves
- **Vulnerability Scanners**: Automated exploit tools

### 5. OAuth/Credential Patterns
Exposed credentials and API keys:
- **API Keys**: Generic API key patterns
- **OAuth Tokens**: Access tokens, refresh tokens
- **AWS Credentials**: Access keys, secret keys
- **Database Credentials**: Connection strings

---

## 🚀 Command Reference

### List All Patterns
```bash
php scanner.php patterns
# or
php scanner.php list-patterns
```

**Output**:
```json
{
  "version_info": {
    "version": "2.0.0",
    "last_updated": "2025-11-23 15:30:00",
    "pattern_count": 127,
    "custom_patterns": 5
  },
  "pattern_summary": {
    "default_categories": 5,
    "custom_categories": 2,
    "total_default_patterns": 127,
    "total_custom_patterns": 5,
    "categories": {
      "code": {
        "default_count": 42,
        "custom_count": 3,
        "custom_patterns": [...]
      }
    }
  }
}
```

### Add Custom Pattern
```bash
php scanner.php add-pattern <category> <pattern> <description> [severity]
```

**Parameters**:
- `category`: Pattern category (code, spam, backdoor, custom, etc.)
- `pattern`: Regular expression pattern
- `description`: Human-readable description
- `severity`: CRITICAL, HIGH, MEDIUM, LOW (default: HIGH)

**Examples**:

1. **Detect specific backdoor**:
```bash
php scanner.php add-pattern "backdoor" "/myCustomBackdoor/i" "Custom backdoor signature" "CRITICAL"
```

2. **Detect specific spam keyword**:
```bash
php scanner.php add-pattern "spam" "/buy\s+now\s+cheap/i" "Spam buy now phrase" "MEDIUM"
```

3. **Detect malicious function**:
```bash
php scanner.php add-pattern "code" "/dangerous_function\s*\(/i" "Dangerous function call" "HIGH"
```

4. **Detect suspicious domain**:
```bash
php scanner.php add-pattern "urls" "/evil-domain\.com/i" "Known malicious domain" "CRITICAL"
```

### Test Pattern
```bash
php scanner.php test-pattern <pattern> <sample_text>
```

**Example**:
```bash
php scanner.php test-pattern "/eval\(base64_decode/i" "<?php eval(base64_decode('...'))?>"
```

**Output**:
```json
{
  "success": true,
  "matched": true,
  "pattern": "/eval\\(base64_decode/i",
  "matches": [
    "eval(base64_decode"
  ],
  "sample_length": 35
}
```

**Safety**: The test command validates patterns for ReDoS vulnerabilities before testing.

### Export Patterns
```bash
# Export to default location
php scanner.php export-patterns

# Export to specific file
php scanner.php export-patterns /path/to/backup.json
```

**Output**:
```
✓ Patterns exported to: /var/www/html/wp-scanner/data/patterns_backup_2025-11-23_153000.json
ℹ File size: 45.67 KB
```

**Export Format**:
```json
{
  "version": {
    "version": "2.0.0",
    "last_updated": "2025-11-23 15:30:00",
    "pattern_count": 132,
    "custom_patterns": 5
  },
  "exported": "2025-11-23 15:30:00",
  "custom_patterns": {
    "backdoor": [
      {
        "pattern": "/myCustomBackdoor/i",
        "description": "Custom backdoor signature",
        "severity": "CRITICAL",
        "added": "2025-11-23 14:00:00",
        "enabled": true
      }
    ]
  },
  "default_patterns": {
    "code": { ... },
    "spam": { ... }
  }
}
```

### Import Patterns
```bash
# Import and merge with existing patterns
php scanner.php import-patterns /path/to/patterns.json

# Import and replace existing patterns
php scanner.php import-patterns /path/to/patterns.json false
```

**Parameters**:
- `file`: Path to JSON file
- `merge`: true (default) = merge, false = replace

**Output**:
```
✓ Patterns imported successfully
ℹ Imported patterns: 8
ℹ Merge mode: Yes
```

---

## 📝 Custom Pattern Development

### Writing Effective Patterns

**Best Practices**:

1. **Use case-insensitive matching** when appropriate:
   ```regex
   /malware/i  ✓ Matches: malware, MALWARE, MaLwArE
   /malware/   ✗ Only matches: malware
   ```

2. **Escape special characters**:
   ```regex
   /\$_GET\['cmd'\]/i  ✓ Correct
   /$_GET['cmd']/i     ✗ Invalid regex
   ```

3. **Use word boundaries** to avoid false positives:
   ```regex
   /\beval\b/i         ✓ Matches eval() but not evaluation
   /eval/i             ✗ Matches evaluation, medieval, etc.
   ```

4. **Be specific but flexible**:
   ```regex
   /eval\s*\(\s*base64_decode\s*\(/i  ✓ Handles whitespace variations
   /eval(base64_decode(/i             ✗ Misses variations
   ```

5. **Avoid ReDoS vulnerabilities**:
   ```regex
   /^(a+)+$/           ✗ ReDoS vulnerable
   /^a+$/              ✓ Safe
   ```

### Pattern Categories

**Create custom categories** for organization:
```bash
php scanner.php add-pattern "wordpress_specific" "/wp_insert_backdoor/i" "WP backdoor function" "CRITICAL"
php scanner.php add-pattern "custom_theme_exploit" "/theme_vulnerability/i" "Known theme issue" "HIGH"
```

### Testing Patterns

**Always test before deployment**:

```bash
# Test 1: Valid malware
php scanner.php test-pattern "/eval\(base64_decode/i" "<?php eval(base64_decode('ZXZhbCgkX0dFVFsnY21kJ10pOw=='))?>"
# Expected: matched = true

# Test 2: False positive check
php scanner.php test-pattern "/eval\(base64_decode/i" "// This is a comment about eval and base64_decode"
# Expected: matched = true (might need refinement)

# Test 3: Legitimate code
php scanner.php test-pattern "/eval\(base64_decode/i" "function evaluate_input() { return true; }"
# Expected: matched = false
```

---

## 🔧 Advanced Usage

### Sharing Patterns with Team

**Scenario**: You've developed custom patterns for your organization and want to share them.

1. **Export your patterns**:
   ```bash
   php scanner.php export-patterns /tmp/company_patterns.json
   ```

2. **Share the file** with your team

3. **Team members import**:
   ```bash
   php scanner.php import-patterns /tmp/company_patterns.json
   ```

### Version Control for Patterns

**Recommended**: Store custom patterns in version control

```bash
# Export to versioned location
php scanner.php export-patterns /path/to/repo/security/patterns.json

# Commit to git
cd /path/to/repo
git add security/patterns.json
git commit -m "Update security patterns"
git push
```

### Automated Pattern Updates

**Create a script** to pull latest patterns:

```bash
#!/bin/bash
# update_patterns.sh

# Pull latest patterns from central repo
curl -o /tmp/latest_patterns.json https://your-company.com/security/patterns.json

# Import patterns
php /var/www/html/wp-scanner/scanner.php import-patterns /tmp/latest_patterns.json

# Run a test scan
php /var/www/html/wp-scanner/scanner.php scan
```

**Add to cron**:
```cron
0 2 * * 1 /path/to/update_patterns.sh  # Every Monday at 2 AM
```

### Pattern Libraries

**Industry-standard patterns** you can import:

1. **OWASP Patterns**: Common web exploits
2. **WPScan Patterns**: WordPress-specific threats
3. **Community Patterns**: Shared by security researchers

**Example import**:
```bash
# Download community patterns
wget https://example.com/wp-security-patterns.json -O /tmp/community_patterns.json

# Review patterns (important!)
cat /tmp/community_patterns.json | less

# Import if trusted
php scanner.php import-patterns /tmp/community_patterns.json
```

---

## 🛡️ Security Considerations

### Pattern Validation

All patterns are automatically validated for:
- **ReDoS vulnerabilities**: Catastrophic backtracking prevention
- **Invalid regex**: Syntax validation
- **Resource usage**: Maximum pattern complexity

**Example of rejected pattern**:
```bash
php scanner.php add-pattern "test" "/^(a+)+$/" "ReDoS pattern" "HIGH"
# Error: Invalid or potentially dangerous regex pattern
```

### Safe Testing

The `test-pattern` command:
- ✓ Runs in isolated environment
- ✓ Validates regex before execution
- ✓ Limits execution time
- ✓ Prevents code execution
- ✓ Safe for production use

### Pattern Permissions

**File permissions** for pattern files:
```bash
# Custom patterns
chmod 644 wp-scanner/database/patterns/custom_patterns.json

# Pattern directory
chmod 755 wp-scanner/database/patterns/
```

**Recommended**: Only allow authorized users to modify patterns

---

## 📊 Pattern Statistics

### View Pattern Count

```bash
php scanner.php patterns | grep "total_default_patterns"
```

### Analyze Pattern Categories

```bash
php scanner.php patterns | jq '.pattern_summary.categories'
```

### Track Pattern Version

```bash
php scanner.php patterns | jq '.version_info'
```

---

## 🔍 Troubleshooting

### Pattern Not Matching

**Issue**: Pattern doesn't detect known malware

**Solutions**:
1. **Test pattern** against sample:
   ```bash
   php scanner.php test-pattern "/your-pattern/i" "sample malware code"
   ```

2. **Check case sensitivity**:
   ```bash
   # Add /i flag for case-insensitive
   php scanner.php add-pattern "test" "/malware/i" "Case insensitive"
   ```

3. **Verify escaping**:
   ```bash
   # Escape special characters
   /\$_GET\['cmd'\]/i  # Correct
   /$_GET['cmd']/i     # Incorrect
   ```

### False Positives

**Issue**: Pattern matches legitimate code

**Solutions**:
1. **Make pattern more specific**:
   ```bash
   # Too broad
   /eval/i

   # More specific
   /eval\s*\(\s*base64_decode/i
   ```

2. **Use negative lookahead**:
   ```regex
   # Match eval() but not in comments
   /eval\s*\((?!.*\/\*)/i
   ```

3. **Add word boundaries**:
   ```regex
   # Match whole word only
   /\beval\b/i
   ```

### Import Failures

**Issue**: Cannot import patterns from file

**Solutions**:
1. **Validate JSON format**:
   ```bash
   cat patterns.json | jq .
   ```

2. **Check file permissions**:
   ```bash
   chmod 644 patterns.json
   ```

3. **Verify file path**:
   ```bash
   ls -l /path/to/patterns.json
   ```

---

## 📚 Examples

### Example 1: Detect Custom Plugin Backdoor

```bash
# You discovered a backdoor in a pirated plugin
php scanner.php add-pattern "backdoor" "/pirated_plugin_backdoor_v2/i" "Known pirated plugin backdoor" "CRITICAL"

# Test it
php scanner.php test-pattern "/pirated_plugin_backdoor_v2/i" "<?php pirated_plugin_backdoor_v2(); ?>"

# Run scan to detect it
php scanner.php scan
```

### Example 2: Detect Cryptocurrency Mining

```bash
# Add pattern for crypto mining scripts
php scanner.php add-pattern "malware" "/coinhive|cryptoloot|webminer/i" "Cryptocurrency mining script" "HIGH"

# Add pattern for mining JS libraries
php scanner.php add-pattern "malware" "/coin-hive\.min\.js|crypto-loot\.js/i" "Mining JavaScript library" "HIGH"
```

### Example 3: Detect Data Exfiltration

```bash
# Detect suspicious outbound POST requests
php scanner.php add-pattern "exfiltration" "/wp_remote_post.*evil-domain/i" "Data exfiltration to evil-domain" "CRITICAL"

# Detect base64 encoded data transmission
php scanner.php add-pattern "exfiltration" "/curl_exec.*base64_encode/i" "Potential data exfiltration" "HIGH"
```

### Example 4: Detect SEO Spam Injection

```bash
# Detect hidden div spam
php scanner.php add-pattern "spam" "/<div\s+style=['\"]display:\s*none['\"]>.*viagra/i" "Hidden pharma spam" "HIGH"

# Detect cloaking
php scanner.php add-pattern "spam" "/if\s*\(\s*is_admin\(\)\s*\)\s*return;/i" "Admin cloaking technique" "MEDIUM"
```

---

## 🔄 Integration with Scanning

### How Patterns Are Used

1. **Comprehensive Scan**:
   - Loads default patterns
   - Loads enabled custom patterns
   - Merges into single pattern set
   - Scans all content

2. **Pattern Priority**:
   - Custom patterns checked first
   - Default patterns checked second
   - First match wins

3. **Performance**:
   - Patterns compiled once
   - Cached for scan duration
   - Efficient regex matching

### Pattern Updates Don't Require Restart

**Changes take effect immediately**:
```bash
# Add pattern
php scanner.php add-pattern "test" "/new-malware/i" "New threat" "HIGH"

# Run scan (uses new pattern)
php scanner.php scan
```

---

## 📖 Summary

The Pattern Management System provides:

✅ **Flexibility**: Add custom patterns without modifying code
✅ **Safety**: Automatic ReDoS and syntax validation
✅ **Collaboration**: Export/import for team sharing
✅ **Testing**: Safe pattern testing before deployment
✅ **Version Control**: Track pattern changes over time
✅ **Performance**: Efficient pattern matching
✅ **Security**: Protected pattern files with .htaccess

**Best Practices**:
1. Test patterns before deployment
2. Document custom patterns
3. Export patterns regularly for backup
4. Share patterns with your team
5. Review patterns periodically
6. Remove obsolete patterns

For more information, see:
- `README.md` - General scanner documentation
- `COMPREHENSIVE_FEATURES.md` - All scanner features
- `SECURITY_IMPROVEMENTS.md` - Security enhancements
