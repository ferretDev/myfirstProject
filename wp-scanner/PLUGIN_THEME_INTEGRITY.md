# Plugin & Theme Integrity Verification Guide

Complete guide for verifying plugin and theme file integrity to detect unauthorized modifications and malware injection.

## 🎯 Overview

Plugins and themes are the #1 attack vector for WordPress compromises. This system:
- **Verifies repository plugins/themes** against WordPress.org official files
- **Creates baselines** for custom/premium plugins/themes
- **Detects modifications** that could indicate malware injection
- **Checks vulnerabilities** against WPScan database
- **Assesses severity** of file changes

---

## 🔌 Plugin Integrity Checking

### How It Works

1. **Repository Plugins** (from WordPress.org):
   - Fetches official file list from WordPress.org SVN
   - Compares local files against repository
   - Detects modified, extra, and missing files

2. **Custom/Premium Plugins**:
   - Creates hash-based baseline of all files
   - Stores baseline for future comparison
   - Detects any file changes since baseline

### Commands

#### Check All Plugins
```bash
php scanner.php check-plugins
```

**Output**:
```json
{
  "summary": {
    "total_plugins": 12,
    "active_plugins": 8,
    "total_issues": 3,
    "plugins_with_issues": 2,
    "status": "COMPROMISED"
  },
  "plugins": [
    {
      "slug": "woocommerce",
      "name": "WooCommerce",
      "type": "repository",
      "verified": 847,
      "modified": [],
      "extra": [
        {
          "file": "includes/backdoor.php",
          "severity": "CRITICAL"
        }
      ],
      "missing": []
    }
  ]
}
```

#### Create Baselines for Custom Plugins
```bash
php scanner.php create-plugin-baselines
```

This creates hash-based baselines for all plugins not in WordPress.org repository (premium plugins, custom plugins, etc.)

**What Gets Stored**:
- MD5 hash of every file
- File size
- Last modified timestamp
- Creation date of baseline

**Baseline Location**: `wp-scanner/data/plugin_baselines/[plugin-slug].json`

---

## 🎨 Theme Integrity Checking

### How It Works

Themes are verified using baseline comparison since theme SVN access is more limited than plugins.

1. **Repository Themes**: Checked against baseline
2. **Custom Themes**: Checked against baseline
3. **Parent Themes**: Verified separately from child themes

### Commands

#### Check All Themes
```bash
php scanner.php check-themes
```

**Output**:
```json
{
  "summary": {
    "total_themes": 3,
    "active_theme": 1,
    "total_issues": 1,
    "themes_with_issues": 1,
    "status": "COMPROMISED"
  },
  "themes": [
    {
      "slug": "twentytwentyfour",
      "name": "Twenty Twenty-Four",
      "is_active": true,
      "modified": [
        {
          "file": "functions.php",
          "severity": "CRITICAL",
          "baseline_hash": "abc123...",
          "current_hash": "def456..."
        }
      ]
    }
  ]
}
```

#### Create Baselines for All Themes
```bash
php scanner.php create-theme-baselines
```

**Baseline Location**: `wp-scanner/data/theme_baselines/[theme-slug].json`

---

## 🛡️ Vulnerability Detection

### WPScan API Integration

Checks plugins, themes, and WordPress core against the WPScan vulnerability database.

**Features**:
- Checks against 50,000+ known vulnerabilities
- Version-specific vulnerability matching
- CVSS severity scoring
- 24-hour caching to respect API limits
- Works with free tier (50 requests/day)

### Commands

#### Check for Known Vulnerabilities
```bash
php scanner.php check-vulnerabilities
# or shorthand
php scanner.php vulns
```

**Output**:
```json
{
  "summary": {
    "total_vulnerabilities": 3,
    "wp_core_vulns": 0,
    "plugin_vulns": 2,
    "theme_vulns": 1,
    "risk_level": "HIGH"
  },
  "plugins": {
    "vulnerable_plugins": 1,
    "total_vulnerabilities": 2,
    "plugins": [
      {
        "name": "Contact Form 7",
        "slug": "contact-form-7",
        "version": "5.3.0",
        "is_active": true,
        "count": 2,
        "vulnerabilities": [
          {
            "title": "XSS Vulnerability",
            "fixed_in": "5.3.2",
            "severity": "HIGH",
            "vuln_type": "XSS"
          }
        ]
      }
    ]
  }
}
```

### API Configuration (Optional)

For higher API limits, get a free WPScan API token:

1. Register at https://wpscan.com/register
2. Get your API token
3. Add to config:

```php
// config/config.php
'wpscan_api_token' => 'YOUR_TOKEN_HERE',
```

**Free Tier**: 50 requests/day
**Paid Tier**: Unlimited requests

---

## 📊 Severity Levels

### File Change Severity

**CRITICAL**:
- PHP files in plugins/themes
- functions.php modifications
- Files with known backdoor patterns

**HIGH**:
- JavaScript files (can contain malware)
- PHP files in subdirectories
- Configuration files (JSON, XML, INI)

**MEDIUM**:
- CSS files (can contain obfuscated code)
- Template files
- Assets

**LOW**:
- Images
- Documentation files
- README/LICENSE

### Vulnerability Severity (CVSS)

**CRITICAL**: CVSS 9.0-10.0
**HIGH**: CVSS 7.0-8.9
**MEDIUM**: CVSS 4.0-6.9
**LOW**: CVSS 0.1-3.9

---

## 🔍 Real-World Examples

### Example 1: Infected Plugin

```bash
$ php scanner.php check-plugins
```

**Finding**:
```
⚠ WooCommerce: 1 issues found

Extra file: includes/class-backdoor.php (CRITICAL)
```

**Action**:
1. Quarantine the file
2. Restore plugin from WordPress.org
3. Scan for other compromises
4. Change all passwords

### Example 2: Modified Theme

```bash
$ php scanner.php check-themes
```

**Finding**:
```
⚠ Twenty Twenty-Four: 2 issues found

Modified: functions.php (CRITICAL)
Modified: footer.php (HIGH)
```

**Action**:
1. Backup current files
2. Compare changes to identify malicious code
3. Restore from clean backup or baseline
4. Update all themes

### Example 3: Vulnerable Plugin

```bash
$ php scanner.php vulns
```

**Finding**:
```
⚠ Contact Form 7 v5.3.0: 1 vulnerability
  - XSS Vulnerability (HIGH)
  - Fixed in: 5.3.2
  - Update immediately
```

**Action**:
1. Update plugin to 5.3.2+
2. Check logs for exploitation attempts
3. Scan for backdoors (may have been exploited)

---

## 🛠️ Workflow Recommendations

### Initial Setup (First Time)

```bash
# 1. Check for known vulnerabilities first
php scanner.php check-vulnerabilities

# 2. Update any vulnerable components
# (manually update plugins/themes)

# 3. Create baselines for ALL plugins/themes
php scanner.php create-plugin-baselines
php scanner.php create-theme-baselines

# 4. Verify everything is clean
php scanner.php check-plugins
php scanner.php check-themes
```

### Regular Monitoring (Weekly/Monthly)

```bash
# Quick vulnerability check
php scanner.php vulns

# Full integrity check
php scanner.php check-plugins
php scanner.php check-themes
```

### After Plugin/Theme Updates

```bash
# Update baseline after legitimate updates
php scanner.php create-plugin-baselines
php scanner.php create-theme-baselines
```

### After Compromise Detection

```bash
# 1. Create full backup
php scanner.php backup

# 2. Check everything
php scanner.php check-plugins
php scanner.php check-themes
php scanner.php vulns

# 3. Restore from clean backups
# (manual restoration)

# 4. Re-baseline after cleanup
php scanner.php create-plugin-baselines
php scanner.php create-theme-baselines
```

---

## 📁 Baseline File Structure

### Plugin Baseline Example
```json
{
  "slug": "my-custom-plugin",
  "type": "custom",
  "created": "2025-11-23 15:30:00",
  "timestamp": 1700753400,
  "files": {
    "index.php": {
      "hash": "d41d8cd98f00b204e9800998ecf8427e",
      "size": 1024,
      "modified": 1700753000
    },
    "includes/class-main.php": {
      "hash": "098f6bcd4621d373cade4e832627b4f6",
      "size": 5120,
      "modified": 1700753100
    }
  }
}
```

---

## 🚨 Common Attack Patterns

### 1. Injected Backdoor Files

**Pattern**: New PHP files in plugin/theme directories

**Detection**:
```json
"extra": [
  {
    "file": "includes/backdoor.php",
    "severity": "CRITICAL"
  }
]
```

### 2. Modified Core Files

**Pattern**: Changes to main plugin/theme files

**Detection**:
```json
"modified": [
  {
    "file": "plugin-name.php",
    "severity": "CRITICAL"
  }
]
```

### 3. Obfuscated Code in Existing Files

**Pattern**: Base64/eval code injected into legitimate files

**Detection**: Modified hash on existing files

**Investigation**: Compare baseline to current:
```bash
# View the suspicious file
cat wp-content/plugins/my-plugin/index.php | grep -i "eval\|base64"
```

---

## 💡 Best Practices

1. **Create Baselines Immediately**:
   - Right after installation
   - After any legitimate updates
   - Before making custom modifications

2. **Regular Checks**:
   - Weekly vulnerability scans
   - Monthly integrity checks
   - After security incidents

3. **Update Responsibly**:
   - Review changelog before updating
   - Create backup before updates
   - Re-baseline after updates

4. **Verify Downloads**:
   - Only download from official sources
   - Check file hashes when available
   - Baseline immediately after install

5. **Document Custom Changes**:
   - Note all custom modifications
   - Update baseline after changes
   - Keep modification log

---

## 🔧 Troubleshooting

### "No baseline found"

**Issue**: Custom plugin has no baseline

**Solution**:
```bash
php scanner.php create-plugin-baselines
```

### "Could not fetch official file list"

**Issue**: SVN not available or plugin not in repo

**Solution**: Create baseline instead:
```bash
php scanner.php create-plugin-baselines
```

### "API rate limit exceeded"

**Issue**: Too many vulnerability checks

**Solution**:
- Results are cached for 24 hours
- Wait and try again
- Or get free WPScan API token

### False Positives

**Issue**: Legitimate files flagged as "extra"

**Causes**:
- Plugin updates added new files
- Custom modifications
- Cache/temp files

**Solution**: Re-create baseline after verifying files are legitimate

---

## 📊 Integration with Full Scan

The full scanner integrates plugin/theme checks:

```bash
php scanner.php scan
```

Includes:
- ✅ Plugin integrity verification
- ✅ Theme integrity verification
- ✅ Vulnerability detection
- ✅ All other security checks

---

## 🆘 Emergency Response

### If Malware Detected:

1. **Don't Panic**: Document findings first

2. **Isolate**:
   ```bash
   # Create backup of compromised site
   php scanner.php backup
   ```

3. **Identify**:
   ```bash
   # Check all plugins and themes
   php scanner.php check-plugins
   php scanner.php check-themes
   ```

4. **Remove**:
   - Delete compromised plugins/themes
   - Restore from official sources
   - Or restore from clean backup

5. **Verify**:
   ```bash
   # Re-check after cleanup
   php scanner.php check-plugins
   php scanner.php check-themes
   php scanner.php vulns
   ```

6. **Secure**:
   - Change all passwords
   - Update everything
   - Review user accounts
   - Check for backdoors

7. **Monitor**:
   - Weekly scans for 1 month
   - Check logs regularly
   - Enable security logging

---

## 📚 Additional Resources

- **WPScan Vulnerability Database**: https://wpscan.com/
- **WordPress.org Plugin Directory**: https://wordpress.org/plugins/
- **WordPress Security Whitepaper**: https://wordpress.org/about/security/

---

**Remember**: Plugin and theme verification is only one layer of security. Always maintain backups, keep software updated, and follow security best practices!
