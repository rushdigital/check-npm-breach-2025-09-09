# Package manager breach scanner - checks all package manager files in current directory
#!/bin/bash

echo "🔍 Scanning current directory for compromised NPM packages..."
echo "============================================================"
echo "Directory: $(pwd)"
echo "Package Managers: NPM, Yarn, pnpm, Bun, Deno"
echo ""

# Package definitions with compromised and safe versions (Bash 3.2 compatible)
package_data=(
    "backslash:0.2.1:0.2.0"
    "chalk-template:1.1.1:1.1.0"
    "supports-hyperlinks:4.1.1:4.1.0"
    "has-ansi:6.0.1:6.0.0"
    "simple-swizzle:0.2.3:0.2.2"
    "color-string:2.1.1:2.1.0"
    "error-ex:1.3.3:1.3.2"
    "color-name:2.0.1:2.0.0"
    "is-arrayish:0.3.3:0.3.2"
    "slice-ansi:7.1.1:7.1.0"
    "color-convert:3.1.1:3.1.0"
    "wrap-ansi:9.0.1:9.0.0"
    "ansi-regex:6.2.1:6.1.0"
    "supports-color:10.2.1:10.2.0"
    "strip-ansi:7.1.1:7.1.0"
    "chalk:5.6.1:5.6.0"
    "debug:4.4.2:4.4.1"
    "ansi-styles:6.2.2:6.2.1"
    "@duckdb/node-api:1.3.3:1.3.2"
    "@duckdb/duckdb-wasm:1.29.2:1.29.1"
    "@duckdb/node-bindings:1.3.3:1.3.2"
    "duckdb:1.3.3:1.3.2"
    "proto-tinker-wc:0.1.87:0.1.86"
    "@coveops/abi:2.0.1:2.0.0"
)

# Helper functions to get package info
get_compromised_version() {
    local package_name="$1"
    for entry in "${package_data[@]}"; do
        if [[ "$entry" == "$package_name:"* ]]; then
            echo "$entry" | cut -d':' -f2
            return
        fi
    done
}

get_safe_version() {
    local package_name="$1"
    for entry in "${package_data[@]}"; do
        if [[ "$entry" == "$package_name:"* ]]; then
            echo "$entry" | cut -d':' -f3
            return
        fi
    done
}

# Get package names
package_names=()
for entry in "${package_data[@]}"; do
    package_names+=($(echo "$entry" | cut -d':' -f1))
done

found_issues=false
scanned_files=0
total_matches=0

# Arrays to track results
vulnerable_results=()
safe_results=()
affected_files=()

echo "🔎 Finding package manager files in current directory..."

# Find all package manager files in current directory and subdirectories
# Covers npm, yarn, pnpm, and other package managers
# Exclude node_modules to avoid noise from dependencies
package_files=$(find . \( \
    -name "package.json" -o \
    -name "package-lock.json" -o \
    -name "npm-shrinkwrap.json" -o \
    -name "yarn.lock" -o \
    -name ".yarnrc" -o \
    -name ".yarnrc.yml" -o \
    -name "pnpm-lock.yaml" -o \
    -name "pnpm-workspace.yaml" -o \
    -name ".pnpmfile.cjs" -o \
    -name "bun.lockb" -o \
    -name "deno.lock" \
\) 2>/dev/null | grep -v node_modules)

if [ -z "$package_files" ]; then
    echo "❌ No package manager files found in current directory"
    echo "   Looked for: package.json, package-lock.json, yarn.lock, pnpm-lock.yaml, etc."
    exit 0
fi

echo "📁 Found $(echo "$package_files" | wc -l) package manager files to scan"
echo ""

# Check each package file
while IFS= read -r file; do
    if [ -f "$file" ]; then
        scanned_files=$((scanned_files + 1))
        
        # Determine file type for better reporting
        case "$(basename "$file")" in
            "package.json") file_type="📦 NPM" ;;
            "package-lock.json") file_type="🔒 NPM Lock" ;;
            "npm-shrinkwrap.json") file_type="📋 NPM Shrinkwrap" ;;
            "yarn.lock") file_type="🧶 Yarn Lock" ;;
            ".yarnrc"|".yarnrc.yml") file_type="🧶 Yarn Config" ;;
            "pnpm-lock.yaml") file_type="📦 pnpm Lock" ;;
            "pnpm-workspace.yaml") file_type="📦 pnpm Workspace" ;;
            ".pnpmfile.cjs") file_type="📦 pnpm Config" ;;
            "bun.lockb") file_type="🥟 Bun Lock" ;;
            "deno.lock") file_type="🦕 Deno Lock" ;;
            *) file_type="📄 Package" ;;
        esac
        
        echo "Scanning: $file_type $file"
        
        # Skip binary files that can't be searched with grep
        if [[ "$file" == *.lockb ]]; then
            echo "   ⚠️  Skipping binary file (use 'bun install' to regenerate from package.json)"
            continue
        fi
        
        file_has_issues=false
        
        # Check each package from our compromised list
        for package_name in "${package_names[@]}"; do
            compromised_version=$(get_compromised_version "$package_name")
            safe_version=$(get_safe_version "$package_name")
            
            # Find all versions of this package in the file
            versions_found=()
            
            case "$(basename "$file")" in
                "package.json"|"package-lock.json"|"npm-shrinkwrap.json"|"deno.lock")
                    # JSON format: "package": "version" or in node_modules paths
                    while IFS= read -r line; do
                        if [[ -n "$line" ]]; then
                            versions_found+=("$line")
                        fi
                    done < <(grep -o "\"$package_name\"[^\"]*\"[^\"]*\"" "$file" 2>/dev/null | sed 's/.*"\([^"]*\)"/\1/' | grep -E '^[0-9]' || true)
                    
                    # Also check node_modules paths for lockfiles
                    while IFS= read -r line; do
                        if [[ -n "$line" ]]; then
                            versions_found+=("$line")
                        fi
                    done < <(grep -o "node_modules/$package_name\"[^\"]*\"version\"[^\"]*\"[^\"]*\"" "$file" 2>/dev/null | sed 's/.*"version": *"\([^"]*\)".*/\1/' || true)
                    ;;
                "yarn.lock")
                    # Yarn lock format: package@version:
                    while IFS= read -r line; do
                        if [[ -n "$line" ]]; then
                            versions_found+=("$line")
                        fi
                    done < <(grep "^\"\\?$package_name@" "$file" 2>/dev/null | sed "s|^\"\\?$package_name@\\([^:\"]*\\).*|\\1|" || true)
                    ;;
                "pnpm-lock.yaml"|"pnpm-workspace.yaml")
                    # YAML format: /package@version: or package@version:
                    while IFS= read -r line; do
                        if [[ -n "$line" ]]; then
                            versions_found+=("$line")
                        fi
                    done < <(grep "^[[:space:]]*['\"]\\?/\\?$package_name@" "$file" 2>/dev/null | sed "s|.*$package_name@\\([^:'\\\" ]*\\).*|\\1|" || true)
                    ;;
            esac
            
            # Process found versions
            if [ ${#versions_found[@]} -gt 0 ]; then
                # Remove duplicates
                unique_versions=($(printf '%s\n' "${versions_found[@]}" | sort -u))
                
                for version in "${unique_versions[@]}"; do
                    # Clean version (remove any extra characters)
                    clean_version=$(echo "$version" | sed 's/[^0-9.].*$//')
                    
                    if [ "$clean_version" = "$compromised_version" ]; then
                        echo "🚨 VULNERABLE: $package_name@$clean_version found in $file"
                        vulnerable_results+=("$package_name@$clean_version in $file")
                        found_issues=true
                        file_has_issues=true
                        total_matches=$((total_matches + 1))
                    elif [ -n "$clean_version" ]; then
                        echo "📦 FOUND: $package_name@$clean_version in $file (Safe: $safe_version)"
                        safe_results+=("$package_name@$clean_version in $file (Safe: $safe_version)")
                        total_matches=$((total_matches + 1))
                    fi
                done
            fi
        done
        
        
        # Track files that have issues
        if [ "$file_has_issues" = true ]; then
            affected_files+=("$file")
        fi
    fi
done <<< "$package_files"

echo ""
echo "============================================================"
echo "📊 Scan Summary:"
echo "   Directory: $(pwd)"
echo "   Files scanned: $scanned_files"
echo "   Matches found: $total_matches"
echo "   Affected files: ${#affected_files[@]}"
echo ""

# Show detailed breakdown
if [ ${#vulnerable_results[@]} -gt 0 ] || [ ${#safe_results[@]} -gt 0 ]; then
    echo "📋 Detailed Findings:"
    echo ""
    
    if [ ${#vulnerable_results[@]} -gt 0 ]; then
        echo "🚨 VULNERABLE PACKAGES (${#vulnerable_results[@]} found):"
        for result in "${vulnerable_results[@]}"; do
            echo "   • $result"
        done
        echo ""
    fi
    
    if [ ${#safe_results[@]} -gt 0 ]; then
        echo "📦 SAFE PACKAGES FROM COMPROMISED LIST (${#safe_results[@]} found):"
        for result in "${safe_results[@]}"; do
            echo "   • $result"
        done
        echo ""
    fi
    
    if [ ${#affected_files[@]} -gt 0 ]; then
        echo "📁 AFFECTED FILES:"
        for file in "${affected_files[@]}"; do
            echo "   • $file"
        done
        echo ""
    fi
else
    echo "✅ None of the potentially compromised packages are installed in this project."
    echo ""
fi

if [ "$found_issues" = true ]; then
    echo "🚨 CRITICAL SECURITY WARNING: Compromised package versions detected!"
    echo ""
    echo "⚠️  DO NOT use automated fixes like 'npm update' or 'npm audit fix'"
    echo "⚠️  These compromised packages may contain malicious code"
    echo ""
    echo "🔒 REQUIRED SECURITY ACTIONS:"
    echo "   1. 🛑 STOP - Do not deploy or run this code in production"
    echo "   2. 👥 Contact your security team immediately"
    echo "   3. 🔍 Conduct a security review of affected dependencies"
    echo "   4. 📋 Document which packages are compromised and their usage"
    echo "   5. 🔄 Plan a careful, tested migration to safe versions"
    echo "   6. 🧪 Test thoroughly in isolated environments"
    echo "   7. 📊 Consider security scanning of your codebase"
    echo ""
    echo "📞 If you don't have a security team, consider:"
    echo "   • Consulting with a cybersecurity professional"
    echo "   • Engaging your organization's IT security department"
    echo "   • Seeking guidance from the package maintainers"
else
    echo "🎉 No compromised versions detected. Your project appears safe!"
    echo "💡 Continue monitoring for security updates and run this check regularly."
fi

# Generate report filename with timestamp
report_file="npm-breach-scan-$(date +%Y%m%d-%H%M%S).txt"

echo ""
echo "📄 Writing detailed report to: $report_file"

# Write comprehensive report to file
{
    echo "NPM BREACH SCAN REPORT"
    echo "======================"
    echo "Generated: $(date)"
    echo "Directory: $(pwd)"
    echo "Package Managers: NPM, Yarn, pnpm, Bun, Deno"
    echo ""
    
    echo "SCAN SUMMARY"
    echo "============"
    echo "Files scanned: $scanned_files"
    echo "Matches found: $total_matches"
    echo "Affected files: ${#affected_files[@]}"
    echo ""
    
    if [ ${#vulnerable_locations[@]} -gt 0 ] || [ ${#pinning_locations[@]} -gt 0 ]; then
        echo "DETAILED FINDINGS"
        echo "================="
        echo ""
        
        if [ ${#vulnerable_locations[@]} -gt 0 ]; then
            echo "VULNERABLE PACKAGES (${#vulnerable_locations[@]} found):"
            echo "=========================================="
            for location in "${vulnerable_locations[@]}"; do
                echo "• $location"
            done
            echo ""
        fi
        
        if [ ${#pinning_locations[@]} -gt 0 ]; then
            echo "PACKAGES NEEDING PINNING (${#pinning_locations[@]} found):"
            echo "=============================================="
            for location in "${pinning_locations[@]}"; do
                echo "• $location"
            done
            echo ""
        fi
        
        echo "AFFECTED FILES:"
        echo "==============="
        for file in "${affected_files[@]}"; do
            echo "• $file"
        done
        echo ""
        
        echo "IMMEDIATE ACTIONS REQUIRED"
        echo "=========================="
        if [ "$found_issues" = true ]; then
            echo "🚨 COMPROMISED PACKAGES DETECTED IN THIS PROJECT"
            echo ""
            echo "CRITICAL STEPS:"
            echo "1. Do not run this Node.js project until packages are updated"
            echo "2. Update all affected packages immediately"
            echo "3. Run 'npm audit fix' to fix known vulnerabilities"
            echo "4. Run 'npm update' to update to latest safe versions"
            echo "5. Consider running 'npm audit' for additional security checks"
        else
            echo "✅ No vulnerable packages found in this project"
        fi
        echo ""
        
        echo "UNDERSTANDING THE RESULTS"
        echo "========================="
        echo "VULNERABLE: Exact match of compromised version - UPDATE IMMEDIATELY"
        echo "NEEDS PINNING: Safe version but should be pinned to prevent auto-updates"
        echo ""
        
        echo "RECOMMENDED ACTIONS"
        echo "==================="
        echo "• For VULNERABLE packages: Update to latest safe version immediately"
        echo "• For PINNING packages: Pin exact version in package.json (e.g., '1.2.3' not '^1.2.3')"
        echo "• Run 'npm audit' for comprehensive security analysis"
        echo "• Use 'npm ci' instead of 'npm install' for production builds"
        echo "• Consider using 'npm shrinkwrap' to lock dependency versions"
    else
        echo "RESULT"
        echo "======"
        echo "✅ No compromised packages found in scanned files"
        echo ""
        echo "RECOMMENDATIONS"
        echo "==============="
        echo "• Continue regular security audits with 'npm audit'"
        echo "• Keep dependencies updated"
        echo "• Consider using dependency scanning tools in CI/CD"
    fi
    
    echo ""
    echo "SCANNED FILES"
    echo "============="
    while IFS= read -r file; do
        if [ -f "$file" ]; then
            case "$(basename "$file")" in
                "package.json") file_type="NPM Package" ;;
                "package-lock.json") file_type="NPM Lock" ;;
                "npm-shrinkwrap.json") file_type="NPM Shrinkwrap" ;;
                "yarn.lock") file_type="Yarn Lock" ;;
                ".yarnrc"|".yarnrc.yml") file_type="Yarn Config" ;;
                "pnpm-lock.yaml") file_type="pnpm Lock" ;;
                "pnpm-workspace.yaml") file_type="pnpm Workspace" ;;
                ".pnpmfile.cjs") file_type="pnpm Config" ;;
                "bun.lockb") file_type="Bun Lock" ;;
                "deno.lock") file_type="Deno Lock" ;;
                *) file_type="Package File" ;;
            esac
            echo "• $file ($file_type)"
        fi
    done <<< "$package_files"
    
    echo ""
    echo "END OF REPORT"
    echo "============="
    
} > "$report_file"

echo "✅ Report saved successfully!"
echo "📁 Location: $(pwd)/$report_file"