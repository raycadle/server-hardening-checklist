# Table of Contents

- **[Introduction](#introduction)**
  * [Status](#status)
  * [Todo](#todo)
  * [Prologue](#prologue)
  * [Levels of priority](#levels-of-priority)
  * [OpenSCAP](#openscap)
- **[Partitioning](#partitioning)**
  * [Separate Volumes](#Separate\ Volumes)
  * [Restrict mount options](#restrict-mount-options)
  * [Polyinstantiated directories](#polyinstantiated-directories)
  * [Shared memory](#shared-memory)
  * [Encrypt partitions](#encrypt-partitions)
  * [Section Checklist](#ballot_box_with_check-summary-checklist)
- **[Physical Access](#physical-access)**
  * [Password for Single User Mode](#password-for-single-user-mode)
  * [Section Checklist](#ballot_box_with_check-summary-checklist-1)
- **[Bootloader](#bootloader)**
  * [Protect bootloader config files](#protect-bootloader-config-files)
  * [Section Checklist](#ballot_box_with_check-summary-checklist-2)
- **[Linux Kernel](#linux-kernel)**
  * [Kernel logs](#kernel-logs)
  * [Kernel pointers](#kernel-pointers)
  * [ExecShield](#execshield)
  * [Memory protection](#memory-protection)
  * [Section Checklist](#ballot_box_with_check-summary-checklist-3)
- **[Logging](#logging)**
  * [Syslog](#syslog)
- **[Users and Groups](#users-and-groups)**
  * [Passwords](#passwords)
  * [Logon Access](#logon-access)
  * [Section Checklist](#ballot_box_with_check-summary-checklist-4)
- **[Filesystem](#filesystem)**
  * [Hardlinks & Symlinks](#hardlinks--symlinks)
  * [Dynamic Mounting and Unmounting](#dynamic-mounting-and-unmounting)
  * [Section Checklist](#ballot_box_with_check-summary-checklist-5)
- **[Permissions](#permissions)**
- **[SELinux & Auditd](#selinux--auditd)**
  * [SELinux Enforcing](#selinux-enforcing)
  * [Section Checklist](#ballot_box_with_check-summary-checklist-6)
- **[System Updates](#system-updates)**
- **[Network](#network)**
  * [TCP/SYN](#tcp-syn)
  * [Routing](#routing)
  * [ICMP Protocol](#icmp-protocol)
  * [Broadcast](#broadcast)
  * [Section Checklist](#ballot_box_with_check-summary-checklist-7)
- **[Services](#services)**
- **[Tools](#tools)**

# Introduction

  > [!Note]
  > In computing, **hardening** is usually the process of securing a system by reducing its surface of vulnerability, which is larger when a system performs more functions; in principle a single-function system is more secure than a multipurpose one. The main goal of systems hardening is to reduce security risk by eliminating potential attack vectors and condensing the system’s attack surface.

This list contains the most important hardening rules for GNU/Linux systems.

## Status

Still work in progress...

### Proposed Order
1. Secure the BIOS/UEFI with a strong passphrase and disable booting from external media.
2. Secure the bootloader using a strong passphrase.
3. Disable unnecessary kernel modules.
4. Uninstall unnecessary software.
5. Configure regular updates.
6. Schedule daily snapshots of system data and realtime syncing of user data.
7. Configure a firewall, an IPS/IDS, and an integrity checker.
8. Enable AppArmor or SELinux.
9. Configure and enable Auditd.
10. Enable disk usage quotas.
11. Tighten permissions.
12. Configure PAM appropriately.
13. Restrict the `wheel` group's commands.
14. Restrict su.
15. Create a privileged admin user and an unprivileged application user.
16. Disable root login.
17. Reboot

## Todo

- [ ] Add rationale (e.g. url's, external resources)
- [ ] Review levels of priority

## Prologue

I'm not advocating throwing your existing hardening and deployment best practices out the door but I recommend is to always turn a feature from this checklist on in pre-production environments instead of jumping directly into production.

## Levels of Priority

All items in this checklist have a priority level:

* ![Static Badge](https://img.shields.io/badge/Priority-Low-green) This item *can* be skipped, but **shouldn't**.
* ![Static Badge](https://img.shields.io/badge/Priority-Medium-yellow) This item **should** be implemented.
* ![Static Badge](https://img.shields.io/badge/Priority-High-red) This item **must** be implemented.

## OpenSCAP

![[openscap_logo.png]]
**SCAP** (*Security Content Automation Protocol*) provides a mechanism to check configurations, manage vulnerability, and evaluate policy compliance for a variety of systems. One of the most popular implementations of SCAP is **OpenSCAP**, and it is very helpful for vulnerability assessment and hardening.

Some of the external audit tools use this standard. For example, Nessus has functionality for authenticated SCAP scans.

  > I tried to make this list compatible with OpenSCAP standard and rules. However, there may be differences.

# Partitioning

We will use logical volumes inside a single encrypted partition to keep our setup simple. This is known as LVM on LUKS, which uses a single encryption key to unlock our disk—as opposed to individual keys per partition.

## Encrypt Partitions

- ![High Priority](https://img.shields.io/badge/Priority-High-red)

- ![Static Badge](https://img.shields.io/badge/Priority-Low-green) Encrypt `swap` partition.

    **Example:**

    ```bash
    # Edit /etc/crypttab:
    sdb1_crypt /dev/sdb1 /dev/urandom cipher=aes-xts-plain64,size=256,swap,discard

    # Edit /etc/fstab:
    /dev/mapper/sdb1_crypt none swap sw 0 0
    ```


## Separate Volumes

- ![Medium Priority](https://img.shields.io/badge/Priority-Medium-yellow)

Critical system directories should be separated as much as practically possible. This compartmentalization allows granular disk space allocation as well as the ability to apply granular security options to the mounts.

## Restrict Mount Options

- ![Medium Priority](https://img.shields.io/badge/Priority-Medium-yellow)

Mount options for all separately mounted directories should be restricted as much as practically possible.

## Recommended Setup
Below is a recommended baseline for secure volume mounts:

| Mount Point | Size | Filesystem | Options |
| --- | --- | --- | --- |
| `/home`| 15% | ext4 | `defaults,nosuid,nodev` |
| `/usr` | 10% | ext4 | `defaults,nodev` |
| `/boot` | 0.1% | ext2 | `defaults,noexec,nosuid,nodev,ro` |
| `/var` | 10% | ext4 | `defaults,nosuid,nodev` |
| `/var/log` | 15% | ext4 | `defaults,noexec,nosuid,nodev` |
| `/var/log/audit` | 15% | ext4 | `defaults,noexec,nosuid,nodev` |
| `/var/tmp` | 10% | ext4 | `defaults,noexec,nosuid,nodev` |
| `/tmp` | 0% | tmpfs |  |
| `swap` | 10% | swap |  |
| `/` | 100%FREE | ext4 | `defaults` |

### Polyinstantiated Directories
#ToDo 

- ![Static Badge](https://img.shields.io/badge/Priority-Medium-yellow) Setting up polyinstantiated `/tmp` and `/var/tmp` directories.
    **Example:**
    ```bash
    # Create new directories:
    mkdir --mode 000 /tmp/tmp-inst
    mkdir --mode 000 /var/tmp/tmp-inst

    # Edit /etc/security/namespace.conf:
    /tmp      /tmp/tmp-inst/          level  root,adm
    /var/tmp  /var/tmp/tmp-inst/  level  root,adm

    # Set correct SELinux context:
    setsebool polyinstantiation_enabled=1
    chcon --reference=/tmp /tmp/tmp-inst
    chcon --reference=/var/tmp/ /var/tmp/tmp-inst
    ```

### System Processes
System processes should only be visible to members of the `proc` group.

- ![Static Badge](https://img.shields.io/badge/Priority-Medium-yellow) `/proc`
    **Example:**
    ```bash
    proc  /proc  proc  defaults,hidepid=2,gid=proc  0 0
    ```

### Shared Memory

- ![Static Badge](https://img.shields.io/badge/Priority-Medium-yellow) `/dev/shm`
    **Example:**
    ```bash
    tmpfs  /dev/shm  tmpfs  rw,nodev,nosuid,noexec,size=1024M,mode=1770,uid=root,gid=shm 0 0
    ```

## Section Checklist


# Physical Access

## Protect Single User Mode

- ![Static Badge](https://img.shields.io/badge/Priority-Low-green) Protect Single User Mode with root password.

    **Example:**

    ```bash
    # Edit /etc/sysconfig/init.
    SINGLE=/sbin/sulogin
    ```

## Section Checklist


# Bootloader
## Protect Bootloader Configuration

- ![Static Badge](https://img.shields.io/badge/Priority-Low-green) Ensure bootloader config files are set properly permissions.

    **Example:**

    ```bash
    # Set the owner and group of /etc/grub.conf to the root user:
    chown root:root /etc/grub.conf
    chown -R root:root /etc/grub.d

    # Set permissions on the /etc/grub.conf or /etc/grub.d file to read and write for root only:
    chmod og-rwx /etc/grub.conf
    chmod -R og-rwx /etc/grub.d
    ```

## Section Checklist


# Linux Kernel
## Kernel logs

- ![Static Badge](https://img.shields.io/badge/Priority-Low-green) Restricting access to kernel logs.

    **Example:**

    ```bash
    echo "kernel.dmesg_restrict = 1" > /etc/sysctl.d/50-dmesg-restrict.conf
    ```

## Kernel pointers

- ![Static Badge](https://img.shields.io/badge/Priority-Low-green) Restricting access to kernel pointers.

    **Example:**

    ```bash
    echo "kernel.kptr_restrict = 1" > /etc/sysctl.d/50-kptr-restrict.conf
    ```

## ExecShield

- ![Static Badge](https://img.shields.io/badge/Priority-Low-green) ExecShield protection.

    **Example:**

    ```bash
    echo "kernel.exec-shield = 2" > /etc/sysctl.d/50-exec-shield.conf
    ```

## Memory protections

- ![Static Badge](https://img.shields.io/badge/Priority-Low-green) Randomise memory space.

    ```bash
    echo "kernel.randomize_va_space=2" > /etc/sysctl.d/50-rand-va-space.conf
    ```

## Modules
   - Disable USB:
        - `# echo "install usb-storage /bin/false" >> /etc/modprobe.d/disable-modules.conf`
    - Disable other unused modules:
        ``` 
        modules=(
        'thunderbolt'
        'firewire-core'
        'dccp'
        'sctp'
        'rds'
        'tipc'
        'n-hdlc'
        'ax25'
        'netrom'
        'x25'
        'rose'
        'decnet'
        'econet'
        'af_802154'
        'ipx'
        'appletalk'
        'psnap'
        'p8023'
        'p8022'
        'can'
        'atm'
        'cramfs'
        'jffs2'
        'hfsplus'
        'udf'
        'freevxfs'
        'hfs'
        'squashfs'
        'uvcvideo'
        'bluetooth'
        'btusb'
        'vivid'
        'gfs2'
        'ksmbd'
        'nfsv4'
        'nfsv3'
        'nfs'
        'cifs'
        )
        for module in ${modules[@]}; do
            echo "install ${module} /bin/false" >> /etc/modprobe.d/disable-modules.conf
        done
        ```

## Section Checklist


# Logging
## Syslog

- ![Static Badge](https://img.shields.io/badge/Priority-Medium-yellow) Ensure syslog service is enabled and running.

    **Example:**

    ```bash
    systemctl enable rsyslog
    systemctl start rsyslog
    ```

- ![Static Badge](https://img.shields.io/badge/Priority-Medium-yellow) Send syslog data to external server.

    **Example:**

    ```bash
    # ELK
    # Logstash
    # Splunk
    # ...
    ```

## Section Checklist


# Users and Groups
## Create Users
    - `# useradd -m -s /bin/bash -G wheel admin && passwd admin`
    - `# useradd -m -s /bin/bash -G users user && passwd user`

## Configure PAM
    - Use `pam_pwquality` to enforce a secure policy for passwords:
        - `# { echo "password required pam_unix.so use_authtok sha512 shadow rounds=65536"; echo "password required pam_pwquality.so retry=2 minlen=15 difok=8 dcredit=-3 ucredit=-2 lcredit=-2 ocredit=-3 enforce_for_root"; } >> /etc/pam.d/passwd`

## Passwords

- ![Static Badge](https://img.shields.io/badge/Priority-Medium-yellow) Update password policy (PAM).

    **Example:**

    ```bash
    authconfig --passalgo=sha512 \
    --passminlen=14 \
    --passminclass=4 \
    --passmaxrepeat=2 \
    --passmaxclassrepeat=2 \
    --enablereqlower \
    --enablerequpper \
    --enablereqdigit \
    --enablereqother \
    --update
    ```

- ![Static Badge](https://img.shields.io/badge/Priority-Medium-yellow) Limit password reuse (PAM).

    **Example:**

    ```bash
    # Edit /etc/pam.d/system-auth

    # For the pam_unix.so case:
    password sufficient pam_unix.so ... remember=5

    # For the pam_pwhistory.so case:
    password requisite pam_pwhistory.so ... remember=5
    ```

- ![Static Badge](https://img.shields.io/badge/Priority-Medium-yellow) Secure `/etc/login.defs` password policy.

    **Example:**

    ```bash
    # Edit /etc/login.defs
    PASS_MIN_LEN 14
    PASS_MIN_DAYS 1
    PASS_MAX_DAYS 60
    PASS_WARN_AGE 14
    ```

## Logon Access

- ![Static Badge](https://img.shields.io/badge/Priority-Low-green) Set auto logout inactive users.

    **Example:**

    ```bash
    echo "readonly TMOUT=900" >> /etc/profile.d/idle-users.sh
    echo "readonly HISTFILE" >> /etc/profile.d/idle-users.sh
    chmod +x /etc/profile.d/idle-users.sh
    ```

- ![Static Badge](https://img.shields.io/badge/Priority-Low-green) Set last logon/access notification.

    **Example:**

    ```bash
    # Edit /etc/pam.d/system-auth
    session required pam_lastlog.so showfailed
    ```

- ![Static Badge](https://img.shields.io/badge/Priority-Medium-yellow) Lock out accounts after a number of incorrect login (PAM).

    **Example:**

    ```bash
    # Edit /etc/pam.d/system-auth and /etc/pam.d/password-auth

    # Add the following line immediately before the pam_unix.so statement in the AUTH section:
    auth required pam_faillock.so preauth silent deny=3 unlock_time=never fail_interval=900

    # Add the following line immediately after the pam_unix.so statement in the AUTH section:
    auth [default=die] pam_faillock.so authfail deny=3 unlock_time=never fail_interval=900

    # Add the following line immediately before the pam_unix.so statement in the ACCOUNT section:
    account required pam_faillock.so
    ```

## Restrict `su` Access
- Restrict usage to only the `wheel` group:
`# echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su`
`# echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su-l`
- Require authentication for su:
`# sed -i -e '/SINGLE/s/sushell/sulogin/' -e '/PROMPT/s/yes/no/' /etc/sysconfig/init`

## Lock `root` Account
- Lock root account:
`$ sudo passwd -l root`
- Remove login shell:
`$ sudo sed -i '|^root.*|s|/bin/bash|/sbin/nologin|' /etc/password`

## Section Checklist


# Filesystem

## Hardlinks & Symlinks

- ![Static Badge](https://img.shields.io/badge/Priority-Low-green) Enable hard/soft link protection.

    **Example:**

    ```bash
    echo "fs.protected_hardlinks = 1" > /etc/sysctl.d/50-fs-hardening.conf
    echo "fs.protected_symlinks = 1" >> /etc/sysctl.d/50-fs-hardening.conf
    ```

## Dynamic Mounting and Unmounting

- ![Static Badge](https://img.shields.io/badge/Priority-Medium-yellow) Disable uncommon filesystems.

    **Example:**

    ```bash
    echo "install cramfs /bin/false" > /etc/modprobe.d/uncommon-fs.conf
    echo "install freevxfs /bin/false" > /etc/modprobe.d/uncommon-fs.conf
    echo "install jffs2 /bin/false" > /etc/modprobe.d/uncommon-fs.conf
    echo "install hfs /bin/false" > /etc/modprobe.d/uncommon-fs.conf
    echo "install hfsplus /bin/false" > /etc/modprobe.d/uncommon-fs.conf
    echo "install squashfs /bin/false" > /etc/modprobe.d/uncommon-fs.conf
    echo "install udf /bin/false" > /etc/modprobe.d/uncommon-fs.conf
    echo "install fat /bin/false" > /etc/modprobe.d/uncommon-fs.conf
    echo "install vfat /bin/false" > /etc/modprobe.d/uncommon-fs.conf
    echo "install nfs /bin/false" > /etc/modprobe.d/uncommon-fs.conf
    echo "install nfsv3 /bin/false" > /etc/modprobe.d/uncommon-fs.conf
    echo "install gfs2 /bin/false" > /etc/modprobe.d/uncommon-fs.conf
    ```

## Section Checklist


# Permissions
- Set a restrictive default umask:
    - `# echo "umask 0077" >> /etc/bash.bashrc`
- Verify that no files are ownerless:
    - `# find / -xdev \( -nouser -o -nogroup \) -print`
- Verify that no files are world-writable:
    - `# find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print`
- Disable SUID for as many binaries as practical:
    - `# find / -type f \( -perm -4000 -o -perm -2000 \) -print`
    - `# chmod g-s $path_to_program`

# SELinux & Auditd
## SELinux Enforcing

- ![Static Badge](https://img.shields.io/badge/Priority-High-red) Set SELinux Enforcing mode.

    **Example:**
    ```bash
    # Edit /etc/selinux/config.
    SELINUXTYPE=enforcing
    ```

## Auditd

## Section Checklist


# System Updates

# Network
## TCP/SYN

- ![Static Badge](https://img.shields.io/badge/Priority-Medium-yellow) Enable TCP SYN Cookie protection.

    **Example:**

    ```bash
    echo "net.ipv4.tcp_syncookies = 1" > /etc/sysctl.d/50-net-stack.conf
    ```

## Routing

- ![Static Badge](https://img.shields.io/badge/Priority-Medium-yellow) Disable IP source routing.

    **Example:**

    ```bash
    echo "net.ipv4.conf.all.accept_source_route = 0" > /etc/sysctl.d/50-net-stack.conf
    ```

## ICMP Protocol

- ![Static Badge](https://img.shields.io/badge/Priority-Medium-yellow) Disable ICMP redirect acceptance.

    **Example:**

    ```bash
    echo "net.ipv4.conf.all.accept_redirects = 0" > /etc/sysctl.d/50-net-stack.conf
    ```

- ![Static Badge](https://img.shields.io/badge/Priority-Medium-yellow) Enable ignoring to ICMP requests.

    **Example:**

    ```bash
    echo "net.ipv4.icmp_echo_ignore_all = 1" > /etc/sysctl.d/50-net-stack.conf
    ```

## Broadcast

- ![Static Badge](https://img.shields.io/badge/Priority-Medium-yellow) Enable ignoring broadcasts request.

    **Example:**

    ```bash
    echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" > /etc/sysctl.d/50-net-stack.conf
    ```

## Section Checklist


# Services
## Securing SSHd
Edit `/etc/ssh/sshd_config` to harden the sshd service, if running.

- Change to a non-standard port (security by obscurity; mainly helps against bot scans on internet-facing servers):
    - `Port 18822`
- Prohibit root login:
    - `PermitRootLogin no`
- Deny logins using passwords:
    - `PasswordAuthentication no`
- Enable public key authentication:
    - `PublicKeyAuthentication yes`
- Prevent empty passwords:
    - `PermitEmptyPasswords no`
- Configure connection timeouts:
    - `ClientAliveInterval 60`
    - `ClientAliveCountMax 5`
- Disable IPv6, if not being used:
    - `AddressFamily inet`
- Whitelist specific users:
    - `AllowUsers admin`
- Set a banner in `/etc/issue` then activate it in sshd_config (mostly cosmetic):
    - `Banner /etc/issue.net`

# Tools
## Useful Tools
Fail2ban – a great tool for automatically banning suspicious IP addresses.
ClamAV – an open-source antivirus engine.
Lynis – open-source auditing tool for Linux
Tripwire/aide/osiris – integrity check
SATAN – netwrok scanner
ISS (internet security scanner)
SNORT

## Other Notes
Ways to access root:
- login at tty
- while logged in as a user, run `su` and use the root password
- if running, login via ssh and use root password or configured key
- while logged in as doas user, run `doas -u root /bin/bash`
- while logged in as sudo user, run `sudo -i`