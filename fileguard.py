#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import platform
import sys
import stat
import pwd
import grp
from datetime import datetime
from termcolor import colored
import hashlib

# Sistem bilgisi

SYSTEM = platform.system().lower()
print(SYSTEM)
# Renkli çıktı için Windows ayarı
if SYSTEM == 'windows':
    import colorama

    colorama.init()

# Kritik dosya yolları (Linux, macOS ve Windows için)
CRITICAL_FILES = {
    'linux': [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/sudoers',
        '/root/.bash_history',
        '/var/log/auth.log',
        '/etc/ssh/sshd_config',
        '/etc/hosts',
        '/etc/crontab',
        '/etc/fstab',
        '/boot/vmlinuz',
        '/etc/gshadow',
        '/etc/master.passwd',
        '/etc/security/opasswd',
        '/etc/sudoers.d/',
        '/var/log/secure',
        '/var/spool/cron/'
    ],
    'darwin': [
        '/etc/master.passwd',
        '/etc/sudoers',
        '/var/log/system.log',
        '/Library/Preferences/com.apple.loginwindow.plist',
        '/private/var/db/dslocal/nodes/Default/users/',
        '/private/etc/sudoers',
        '/private/var/at/jobs/',
        '/private/var/root/',
        '/usr/bin/sudo',
        '/usr/sbin/sshd',
        '/System/Library/LaunchDaemons/',
        '/Library/LaunchDaemons/',
        '/private/var/db/.AppleSetupDone',
        '/private/etc/hosts',
        '/private/etc/crontab',
        '/private/var/log/install.log',
        '/private/var/log/accountpolicy.log'
    ],
    'windows': [
        'C:\\Windows\\System32\\config\\SAM',
        'C:\\Windows\\System32\\config\\SYSTEM',
        'C:\\Windows\\System32\\drivers\\etc\\hosts',
        'C:\\Windows\\win.ini',
        'C:\\Windows\\System32\\cmd.exe',
        'C:\\Windows\\System32\\utilman.exe',
        'C:\\Windows\\System32\\sethc.exe',
        'C:\\Windows\\repair\\SAM',
        'C:\\Windows\\System32\\config\\SECURITY',
        'C:\\Windows\\System32\\config\\SOFTWARE',
        'C:\\Windows\\System32\\ntoskrnl.exe',
        'C:\\Windows\\System32\\lsass.exe',
        'C:\\Windows\\System32\\services.exe',
        'C:\\Windows\\System32\\winlogon.exe',
        'C:\\Windows\\System32\\spoolsv.exe'
    ]
}


# Özel kontrol fonksiyonları
def get_file_owner(file_path):
    """Dosya sahibini al"""
    try:
        if SYSTEM in ['linux', 'darwin']:
            stat_info = os.stat(file_path)
            uid = stat_info.st_uid
            gid = stat_info.st_gid
            try:
                owner = pwd.getpwuid(uid).pw_name
            except:
                owner = str(uid)
            try:
                group = grp.getgrgid(gid).gr_name
            except:
                group = str(gid)
            return f"{owner}:{group}"
        else:
            # Windows için basit sahip bilgisi
            import win32security
            sd = win32security.GetFileSecurity(file_path, win32security.OWNER_SECURITY_INFORMATION)
            owner_sid = sd.GetSecurityDescriptorOwner()
            name, domain, _ = win32security.LookupAccountSid(None, owner_sid)
            return f"{domain}\\{name}"
    except Exception as e:
        return f"Error: {str(e)}"


def get_file_permissions(file_path):
    """Dosya izinlerini al"""
    try:
        if SYSTEM in ['linux', 'darwin']:
            mode = os.stat(file_path).st_mode
            perms = {
                'owner_read': bool(mode & stat.S_IRUSR),
                'owner_write': bool(mode & stat.S_IWUSR),
                'owner_exec': bool(mode & stat.S_IXUSR),
                'group_read': bool(mode & stat.S_IRGRP),
                'group_write': bool(mode & stat.S_IWGRP),
                'group_exec': bool(mode & stat.S_IXGRP),
                'others_read': bool(mode & stat.S_IROTH),
                'others_write': bool(mode & stat.S_IWOTH),
                'others_exec': bool(mode & stat.S_IXOTH),
                'suid': bool(mode & stat.S_ISUID),
                'sgid': bool(mode & stat.S_ISGID),
                'sticky': bool(mode & stat.S_ISVTX)
            }
            return perms
        else:
            # Windows için basit izin kontrolü
            perms = {
                'readable': os.access(file_path, os.R_OK),
                'writable': os.access(file_path, os.W_OK),
                'executable': os.access(file_path, os.X_OK)
            }
            return perms
    except Exception as e:
        return f"Error: {str(e)}"


def calculate_file_hash(file_path):
    """Dosya hash'ini hesapla"""
    try:
        if not os.path.isfile(file_path):
            return None

        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    except:
        return None


def check_file_access(file_path):
    """Dosya erişimini detaylı kontrol et"""
    result = {
        'path': file_path,
        'exists': False,
        'type': None,
        'access': None,
        'owner': None,
        'permissions': None,
        'size': None,
        'modified': None,
        'hash': None,
        'details': None
    }

    try:
        # Dosya varlık kontrolü
        if not os.path.exists(file_path):
            result['details'] = 'not_found'
            return result

        result['exists'] = True

        # Dosya tipi
        if os.path.isfile(file_path):
            result['type'] = 'file'
        elif os.path.isdir(file_path):
            result['type'] = 'directory'
        else:
            result['type'] = 'special'

        # Erişim kontrolü
        if SYSTEM == 'windows':
            if os.access(file_path, os.R_OK):
                if os.access(file_path, os.W_OK):
                    result['access'] = 'read_write'
                else:
                    result['access'] = 'read_only'
            else:
                result['access'] = 'no_access'
        else:
            if os.access(file_path, os.R_OK):
                if os.access(file_path, os.W_OK):
                    result['access'] = 'read_write'
                else:
                    result['access'] = 'read_only'
            else:
                result['access'] = 'no_access'

        # Dosya meta verileri
        if result['exists']:
            stat_info = os.stat(file_path)
            result['owner'] = get_file_owner(file_path)
            result['permissions'] = get_file_permissions(file_path)
            result['size'] = stat_info.st_size
            result['modified'] = datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')

            if result['type'] == 'file' and result['size'] < 10 * 1024 * 1024:  # 10MB'den küçük dosyalar için hash
                result['hash'] = calculate_file_hash(file_path)

    except PermissionError:
        result['access'] = 'no_access'
        result['details'] = 'permission_error'
    except Exception as e:
        result['details'] = f'error: {str(e)}'

    return result


def display_permissions(perms):
    """İzinleri görselleştir"""
    if isinstance(perms, str):
        return perms

    if SYSTEM in ['linux', 'darwin']:
        perm_str = ''
        perm_str += 'r' if perms['owner_read'] else '-'
        perm_str += 'w' if perms['owner_write'] else '-'
        perm_str += 'x' if perms['owner_exec'] else '-'
        perm_str += 'r' if perms['group_read'] else '-'
        perm_str += 'w' if perms['group_write'] else '-'
        perm_str += 'x' if perms['group_exec'] else '-'
        perm_str += 'r' if perms['others_read'] else '-'
        perm_str += 'w' if perms['others_write'] else '-'
        perm_str += 'x' if perms['others_exec'] else '-'

        special = ''
        special += 'S' if perms['suid'] else ''
        special += 'G' if perms['sgid'] else ''
        special += 'T' if perms['sticky'] else ''

        return f"{perm_str} {special}" if special else perm_str
    else:
        perm_str = ''
        perm_str += 'R' if perms['readable'] else '-'
        perm_str += 'W' if perms['writable'] else '-'
        perm_str += 'X' if perms['executable'] else '-'
        return perm_str


def generate_report():
    """Detaylı erişim raporu oluştur"""
    print(colored("\n[+] Gelişmiş Kritik Dosya Erişim Kontrol Raporu", 'green', attrs=['bold']))
    print(colored(f"[*] Sistem: {platform.system()} {platform.release()}", 'cyan'))
    print(colored(f"[*] Kullanıcı: {os.getlogin()}", 'cyan'))
    print(colored(f"[*] Çalışma Dizini: {os.getcwd()}", 'cyan'))
    print(colored(f"[*] Zaman: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n", 'cyan'))

    files_to_check = CRITICAL_FILES.get(SYSTEM, [])

    if not files_to_check:
        print(colored("[!] Bu işletim sistemi desteklenmiyor.", 'red'))
        return

    # Tüm dosyaları kontrol et
    results = []
    for file_path in files_to_check:
        results.append(check_file_access(file_path))

    # Raporu yazdır
    for result in results:
        print("\n" + colored(f"=== {result['path']} ===", 'white', attrs=['bold']))

        if not result['exists']:
            print(colored("  [!] Dosya bulunamadı", 'blue'))
            continue

        print(f"  Tip: {result['type']}")
        print(f"  Sahip: {result['owner']}")
        print(f"  İzinler: {display_permissions(result['permissions'])}")
        print(f"  Boyut: {result['size']} bytes")
        print(f"  Değiştirilme: {result['modified']}")

        if result['hash']:
            print(f"  SHA256: {result['hash']}")

        # Erişim durumu
        if result['access'] == 'read_write':
            print(colored("  Erişim: OKUMA/YAZMA", 'green', attrs=['bold']))
        elif result['access'] == 'read_only':
            print(colored("  Erişim: SADECE OKUMA", 'yellow'))
        elif result['access'] == 'no_access':
            print(colored("  Erişim: ERİŞİM YOK", 'red'))
        else:
            print(colored(f"  Erişim: {result['access']}", 'magenta'))

        if result['details']:
            print(colored(f"  Detay: {result['details']}", 'magenta'))

    # Özet
    print("\n" + colored("[+] Özet", 'green', attrs=['bold']))
    total = len(results)
    found = sum(1 for r in results if r['exists'])
    readable = sum(1 for r in results if r['access'] in ['read_only', 'read_write'])
    writable = sum(1 for r in results if r['access'] == 'read_write')

    print(f"  Toplam kontrol edilen: {total}")
    print(f"  Bulunan dosyalar: {found}")
    print(colored(f"  Okunabilir dosyalar: {readable}", 'yellow' if readable > 0 else 'green'))
    print(colored(f"  Yazılabilir dosyalar: {writable}", 'red' if writable > 0 else 'green'))

if __name__ == "__main__":
    generate_report()