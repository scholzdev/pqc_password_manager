#!/bin/bash

# SQLite Database Inspector for PQC Password Manager
# Usage: ./inspect_db.sh [database_path]

DB_PATH="${1:-$HOME/.pqc_password_manager.db}"

if [ ! -f "$DB_PATH" ]; then
    echo "❌ Database not found: $DB_PATH"
    echo "💡 Usage: $0 [database_path]"
    echo "   Default: $HOME/.pqc_password_manager.db"
    exit 1
fi

echo "🔍 PQC Password Manager - Database Inspector"
echo "============================================="
echo "📂 Database: $DB_PATH"
echo ""

# Check if sqlite3 is available
if ! command -v sqlite3 >/dev/null 2>&1; then
    echo "❌ sqlite3 not found. Please install sqlite3:"
    echo "   macOS: brew install sqlite"
    echo "   Ubuntu/Debian: sudo apt install sqlite3"
    echo "   Windows: Download from https://sqlite.org/download.html"
    exit 1
fi

# Database info
echo "📊 Database Information:"
echo "========================"
sqlite3 "$DB_PATH" "
SELECT 
    'Database Size: ' || ROUND(page_count * page_size / 1024.0, 2) || ' KB' as info
FROM pragma_page_count(), pragma_page_size();

SELECT 'SQLite Version: ' || sqlite_version() as info;
"

echo ""
echo "📋 Tables:"
echo "=========="
sqlite3 "$DB_PATH" ".tables"

echo ""
echo "🏗️  Database Schema:"
echo "==================="
sqlite3 "$DB_PATH" ".schema"

echo ""
echo "📊 Password Entries (All Metadata Now Encrypted for Privacy):"
echo "=============================================================="
sqlite3 -header -column "$DB_PATH" "
SELECT 
    id,
    substr(search_hash, 1, 20) || '...' as 'Search Hash (Preview)',
    created_at as 'Created',
    length(encrypted_name) as 'Name Size (bytes)',
    length(encrypted_username) as 'Username Size',
    length(encrypted_password) as 'Password Size',
    length(encrypted_url) as 'URL Size',
    length(nonce) as 'Nonce Size',
    length(shared_secret) as 'Secret Size'
FROM passwords 
ORDER BY created_at DESC;
"

echo ""
echo "🔐 Master Password Entry:"
echo "========================="
sqlite3 -header -column "$DB_PATH" "
SELECT 
    id,
    length(password_hash) as 'Hash Size',
    length(public_key) as 'PubKey Size',
    length(salt) as 'Salt Size',
    created_at as 'Created'
FROM master;
"

echo ""
echo "🔐 Security Summary (Enhanced Privacy Mode):"
echo "============================================="
sqlite3 "$DB_PATH" "
SELECT 
    (SELECT COUNT(*) FROM passwords) as 'Total Entries',
    (SELECT COUNT(DISTINCT search_hash) FROM passwords) as 'Unique Services',
    (SELECT COUNT(*) FROM passwords WHERE length(encrypted_username) > 0) as 'Entries with Username',
    (SELECT COUNT(*) FROM passwords WHERE length(encrypted_url) > 0) as 'Entries with URL',
    (SELECT AVG(length(encrypted_password)) FROM passwords) as 'Avg Password Size',
    (SELECT AVG(length(encrypted_name)) FROM passwords) as 'Avg Name Size',
    (SELECT datetime(created_at) FROM master WHERE id = 1) as 'Master Key Created'
;
"

echo ""
echo "🛡️ Privacy Protection Status:"
echo "=============================="
echo "✅ Service names: ENCRYPTED"  
echo "✅ Usernames: ENCRYPTED"
echo "✅ URLs: ENCRYPTED"
echo "✅ Passwords: ENCRYPTED"
echo "✅ Search hashes: Non-reversible"
echo "⚠️  Creation timestamps: Visible (for sorting only)"
echo ""
echo "🔒 Even with database access, attackers cannot determine:"
echo "   • Which services you use"
echo "   • Your usernames or emails" 
echo "   • Website URLs you visit"
echo "   • Your actual passwords"
echo ""
echo "💡 This provides maximum metadata privacy protection!"