# WordPress Scanner - Quick Start Guide

Get up and running with WordPress Security Scanner in 5 minutes.

## 🚀 Quick Installation

### Step 1: Navigate to Your WordPress Directory
```bash
cd /path/to/your/wordpress
```

### Step 2: Make Scanner Executable
```bash
chmod +x wp-scanner/scanner.php
```

### Step 3: Initialize Security Baselines
```bash
php wp-scanner/scanner.php init
```

This creates baseline snapshots of your site's current state for future comparison.

## 🔍 Running Your First Scan

### Full Security Scan (Recommended)
```bash
php wp-scanner/scanner.php scan
```

This comprehensive scan includes:
- ✅ Database malware detection
- ✅ File system integrity checking
- ✅ Permission auditing
- ✅ .htaccess security analysis
- ✅ User role monitoring
- ✅ Anomaly detection

**Time:** ~2-5 minutes (depends on site size)
**Output:** HTML report in `wp-scanner/reports/`

### Quick Scan (Fast)
```bash
php wp-scanner/scanner.php quick
```

Essential security checks only:
- ✅ Critical database checks
- ✅ User account audit
- ✅ Uploads directory scan
- ✅ Permission audit

**Time:** ~30 seconds

## 📊 Viewing Results

After running a scan:

1. **Open the HTML Report:**
```bash
# Report saved to: wp-scanner/reports/security_report_YYYY-MM-DD_HHMMSS.html
open wp-scanner/reports/security_report_*.html  # macOS
xdg-open wp-scanner/reports/security_report_*.html  # Linux
```

2. **Or view JSON output:**
```bash
cat wp-scanner/reports/security_report_*.json | jq
```

## 🎯 Common Use Cases

### Check for Recently Created Admin Accounts
```bash
php wp-scanner/scanner.php users
```

### Monitor File Changes
```bash
php wp-scanner/scanner.php watch
```

### Scan .htaccess for Malicious Changes
```bash
php wp-scanner/scanner.php htaccess
```

### Check File Permissions
```bash
php wp-scanner/scanner.php permissions
```

## ⚠️ Understanding Results

### Risk Levels
- 🔴 **CRITICAL**: Immediate action required - likely compromised
- 🟠 **HIGH**: Urgent attention needed - significant vulnerabilities
- 🟡 **MEDIUM**: Security improvements recommended
- 🟢 **LOW**: Minor issues - site appears secure

### Common Findings

#### PHP Files in Uploads Directory (CRITICAL)
```
Action: Remove immediately or quarantine
Location: wp-content/uploads/
```

#### World-Writable Files (CRITICAL)
```
Action: Fix permissions
Command: chmod 644 filename.php
```

#### Recently Created Admin Accounts (HIGH)
```
Action: Verify legitimacy or delete
Command: php wp-scanner/scanner.php users
```

#### Suspicious .htaccess Redirects (HIGH)
```
Action: Review and remove unauthorized rules
Location: .htaccess file
```

## 🔄 Regular Maintenance

### Daily Quick Scan (Cron)
```bash
# Add to crontab
0 2 * * * php /path/to/wp-scanner/scanner.php quick
```

### Weekly Full Scan (Cron)
```bash
# Add to crontab
0 3 * * 0 php /path/to/wp-scanner/scanner.php scan
```

### Update Baselines After Clean Updates
```bash
# After updating WordPress/plugins
php wp-scanner/scanner.php init
```

## 🛠️ Configuration

Edit `wp-scanner/config/config.php` to customize:

```php
// Enable auto-quarantine for suspicious files
'auto_quarantine' => true,

// Email alerts
'alerts' => [
    'email' => true,
    'email_to' => 'your@email.com',
],

// Whitelist files/directories
'whitelist' => [
    'patterns' => [
        '*/vendor/*',
        '*/node_modules/*',
    ],
],
```

## 📱 Accessing the Dashboard

Open the web interface:
```
http://yoursite.com/wp-scanner/ui/dashboard/
```

*Note: Currently displays CLI commands - full interactive dashboard coming soon*

## 🆘 Troubleshooting

### Permission Denied Errors
```bash
chmod -R 755 wp-scanner/
chmod -R 777 wp-scanner/quarantine/
chmod -R 777 wp-scanner/logs/
```

### Memory Limit Issues
Edit `config/config.php`:
```php
'performance' => [
    'memory_limit' => '512M',
],
```

### No WordPress Database Connection
Ensure you're running from WordPress root or configure database manually.

## 📋 Checklist for New Installation

- [ ] Scanner installed in WordPress directory
- [ ] Made scanner.php executable (`chmod +x`)
- [ ] Initialized baselines (`php scanner.php init`)
- [ ] Ran first full scan (`php scanner.php scan`)
- [ ] Reviewed HTML report
- [ ] Fixed any CRITICAL or HIGH issues
- [ ] Set up scheduled scans (cron)
- [ ] Configured email alerts (optional)

## 🎓 Next Steps

1. **Review the full README**: `wp-scanner/README.md`
2. **Schedule automated scans**: Set up cron jobs
3. **Fix identified issues**: Follow report recommendations
4. **Regular monitoring**: Run weekly scans
5. **Keep baselines updated**: Re-init after major updates

## 💡 Pro Tips

1. **Always backup** before making changes based on scan results
2. **Test in staging** if you have a staging environment
3. **Review quarantined files** before deleting them
4. **Update baselines** after legitimate changes
5. **Monitor trends** - compare reports over time

## 📞 Getting Help

- Read the full documentation: `README.md`
- Check logs: `wp-scanner/logs/scanner.log`
- View quarantined files: `wp-scanner/quarantine/`

---

**Remember**: Security is an ongoing process, not a one-time scan. Run regular scans and stay vigilant! 🔒
