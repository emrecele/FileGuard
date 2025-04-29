# 🔍 FileGuard - Advanced System File Access Auditor

![FileGuard Terminal Screenshot](https://i.ibb.co/trTn1WZ/image.jpg)

FileGuard is a comprehensive security tool designed to audit access permissions for critical system files across multiple platforms. It provides system administrators and security professionals with immediate visibility into potential vulnerabilities.

## ✨ Key Features

### 🔒 Comprehensive Security Scanning
- Scans 50+ critical system files
- Detects unauthorized access permissions
- Identifies world-writable system files

### 📊 Detailed Reporting
- Color-coded risk assessment (Red/Yellow/Green)
- File metadata analysis:
  - Ownership (User:Group)
  - Permission bits (rwx)
  - Last modification time
  - SHA256 hashes for integrity verification

### 🌐 Cross-Platform Support
| Platform | Tested Versions | Status |
|----------|-----------------|--------|
| Linux    | Ubuntu 20.04+, CentOS 7+ | ✅ Fully Supported |
| Windows  | 10, 11, Server 2019+ | ✅ Fully Supported |
| macOS    | Monterey, Ventura | ✅ Fully Supported |

## 🚀 Installation

### Prerequisites
- Python 3.8+
- pip package manager

### Quick Install
```bash
# Clone the repository
git clone https://github.com/yourusername/fileguard.git

# Navigate to project directory
cd fileguard

# Install dependencies
pip install -r requirements.txt

# Run
python3 fileguard.py
