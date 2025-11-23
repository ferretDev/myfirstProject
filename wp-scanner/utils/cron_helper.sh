#!/bin/bash
#
# WordPress Scanner - Cron Helper
#
# This script helps set up automated scans via cron
#

SCANNER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCANNER_BIN="${SCANNER_DIR}/scanner.php"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "======================================"
echo "WordPress Scanner - Cron Setup Helper"
echo "======================================"
echo ""

# Check if scanner exists
if [ ! -f "$SCANNER_BIN" ]; then
    echo -e "${RED}✗ Scanner not found at: $SCANNER_BIN${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Scanner found${NC}"
echo ""

# Generate cron entries
echo "Recommended Cron Schedules:"
echo "============================"
echo ""

echo "1. Daily Vulnerability Check (2 AM):"
echo "   0 2 * * * cd $(dirname $SCANNER_DIR) && /usr/bin/php $SCANNER_BIN check-vulnerabilities >> $SCANNER_DIR/logs/cron.log 2>&1"
echo ""

echo "2. Weekly Full Scan (Sunday 3 AM):"
echo "   0 3 * * 0 cd $(dirname $SCANNER_DIR) && /usr/bin/php $SCANNER_BIN scan >> $SCANNER_DIR/logs/cron.log 2>&1"
echo ""

echo "3. Daily Quick Scan (1 AM):"
echo "   0 1 * * * cd $(dirname $SCANNER_DIR) && /usr/bin/php $SCANNER_BIN quick >> $SCANNER_DIR/logs/cron.log 2>&1"
echo ""

echo "4. Hourly File Watch:"
echo "   0 * * * * cd $(dirname $SCANNER_DIR) && /usr/bin/php $SCANNER_BIN watch >> $SCANNER_DIR/logs/cron.log 2>&1"
echo ""

echo "5. Monthly Full Backup (1st of month, 4 AM):"
echo "   0 4 1 * * cd $(dirname $SCANNER_DIR) && /usr/bin/php $SCANNER_BIN backup >> $SCANNER_DIR/logs/cron.log 2>&1"
echo ""

# Ask if user wants to add to crontab
echo ""
read -p "Would you like to add these to your crontab? (y/n) " -n 1 -r
echo ""

if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Create temporary cron file
    TEMP_CRON=$(mktemp)

    # Export current crontab
    crontab -l > "$TEMP_CRON" 2>/dev/null || true

    # Add scanner cron jobs
    echo "" >> "$TEMP_CRON"
    echo "# WordPress Security Scanner - Auto-generated" >> "$TEMP_CRON"
    echo "0 2 * * * cd $(dirname $SCANNER_DIR) && /usr/bin/php $SCANNER_BIN check-vulnerabilities >> $SCANNER_DIR/logs/cron.log 2>&1" >> "$TEMP_CRON"
    echo "0 3 * * 0 cd $(dirname $SCANNER_DIR) && /usr/bin/php $SCANNER_BIN scan >> $SCANNER_DIR/logs/cron.log 2>&1" >> "$TEMP_CRON"

    # Install new crontab
    crontab "$TEMP_CRON"

    # Remove temp file
    rm "$TEMP_CRON"

    echo -e "${GREEN}✓ Cron jobs added successfully${NC}"
    echo ""
    echo "Current crontab:"
    crontab -l | grep "scanner.php"
else
    echo -e "${YELLOW}ℹ  No changes made${NC}"
    echo "To manually add to crontab, run: crontab -e"
fi

echo ""
echo "Log file location: $SCANNER_DIR/logs/cron.log"
echo ""
echo "To view logs:"
echo "  tail -f $SCANNER_DIR/logs/cron.log"
echo ""
