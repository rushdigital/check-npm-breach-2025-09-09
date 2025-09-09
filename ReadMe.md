# 🚨 CRITICAL: NPM Package Breach Scanner

## ⚠️ PRIORITY ALERT - September 8, 2025

**18 extremely popular NPM packages were compromised with malicious code that steals cryptocurrency and manipulates wallet transactions.**

### Affected Packages (2+ billion weekly downloads)
- `debug` (357.6M/week), `ansi-styles` (371.41M/week), `chalk` (299.99M/week)
- `strip-ansi`, `supports-color`, `wrap-ansi`, `color-convert`, `color-name`
- `is-arrayish`, `slice-ansi`, `error-ex`, `color-string`, `simple-swizzle`
- `has-ansi`, `supports-hyperlinks`, `chalk-template`, `backslash`, `ansi-regex`

**The malware silently intercepts crypto/web3 activity, manipulates wallet interactions, and redirects funds to attacker-controlled accounts.**

📖 **Full Details**: [Aikido Security Blog - NPM Debug and Chalk Packages Compromised](https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised)

---

## 🔍 Quick Scan with curl

**Scan your project immediately:**

```bash
curl -s https://raw.githubusercontent.com/rushdigital/check-npm-breach-2025-09-09/main/scan.sh | bash
```

### What This Scanner Does

- ✅ **Comprehensive Detection**: Scans all package manager files (npm, yarn, pnpm, bun, deno)
- ✅ **Multi-Format Support**: Handles package.json, lock files, and workspace configurations
- ✅ **Precise Matching**: Identifies exact compromised versions vs safe versions
- ✅ **Detailed Reporting**: Generates timestamped reports with actionable recommendations
- ✅ **Security-First**: Provides clear guidance on remediation steps

### Supported Package Managers

| Package Manager | Files Scanned |
|----------------|---------------|
| **NPM** | `package.json`, `package-lock.json`, `npm-shrinkwrap.json` |
| **Yarn** | `yarn.lock`, `.yarnrc`, `.yarnrc.yml` |
| **pnpm** | `pnpm-lock.yaml`, `pnpm-workspace.yaml`, `.pnpmfile.cjs` |
| **Bun** | `bun.lockb` |
| **Deno** | `deno.lock` |

## 🚨 If Compromised Packages Are Found

**DO NOT:**
- ❌ Use `npm update` or `npm audit fix`
- ❌ Deploy or run the code in production
- ❌ Ignore the warnings

**IMMEDIATE ACTIONS:**
1. 🛑 **STOP** - Halt all deployments
2. 👥 **Contact** your security team
3. 🔍 **Review** affected dependencies
4. 📋 **Document** compromised packages
5. 🔄 **Plan** careful migration to safe versions
6. 🧪 **Test** thoroughly in isolated environments

## 📊 Sample Output

```
🔍 Scanning current directory for compromised NPM packages...
============================================================
Directory: /path/to/your/project
Package Managers: NPM, Yarn, pnpm, Bun, Deno

📁 Found 3 package manager files to scan

Scanning: 📦 NPM package.json
🚨 VULNERABLE: chalk@5.6.1 found in ./package.json
📦 FOUND: debug@4.4.1 in ./package.json (Safe: 4.4.1)

============================================================
📊 Scan Summary:
   Directory: /path/to/your/project
   Files scanned: 3
   Matches found: 2
   Affected files: 1

🚨 CRITICAL SECURITY WARNING: Compromised package versions detected!
```

## 🔧 Manual Installation

If you prefer to download and run locally:

```bash
# Download the scanner
curl -O https://raw.githubusercontent.com/rushdigital/check-npm-breach-2025-09-09/main/scan.sh

# Make executable
chmod +x scan.sh

# Run the scan
./scan.sh
```

## 📋 Compromised Versions

| Package | Compromised Version | Safe Version |
|---------|-------------------|--------------|
| `ansi-styles` | 6.2.2 | 6.2.1 |
| `debug` | 4.4.2 | 4.4.1 |
| `chalk` | 5.6.1 | 5.6.0 |
| `strip-ansi` | 7.1.1 | 7.1.0 |
| `supports-color` | 10.2.1 | 10.2.0 |
| `ansi-regex` | 6.2.1 | 6.1.0 |
| `wrap-ansi` | 9.0.1 | 9.0.0 |
| `color-convert` | 3.1.1 | 3.1.0 |
| `slice-ansi` | 7.1.1 | 7.1.0 |
| `is-arrayish` | 0.3.3 | 0.3.2 |
| `color-name` | 2.0.1 | 2.0.0 |
| `error-ex` | 1.3.3 | 1.3.2 |
| `color-string` | 2.1.1 | 2.1.0 |
| `simple-swizzle` | 0.2.3 | 0.2.2 |
| `has-ansi` | 6.0.1 | 6.0.0 |
| `supports-hyperlinks` | 4.1.1 | 4.1.0 |
| `chalk-template` | 1.1.1 | 1.1.0 |
| `backslash` | 0.2.1 | 0.2.0 |

## 🛡️ About the Attack

The compromised packages contain obfuscated JavaScript that:
- Hooks into browser APIs (`fetch`, `XMLHttpRequest`, wallet APIs)
- Intercepts cryptocurrency transactions
- Replaces legitimate wallet addresses with attacker-controlled ones
- Uses "lookalike" addresses to avoid detection
- Stays hidden by avoiding obvious UI changes when crypto wallets are detected

**Attack Vector**: Maintainer was compromised via phishing email from fake domain `npmjs.help`

## 📞 Need Help?

- **Security Team**: Contact your organization's security team immediately
- **No Security Team?**: Consider consulting with a cybersecurity professional
- **Community**: Check the [Aikido Security Blog](https://www.aikido.dev/blog/npm-debug-and-chalk-packages-compromised) for updates

---

**⚡ Run the scan now - your project's security depends on it!**