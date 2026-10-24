#!/bin/bash

#############################################
# CyberPatriot Security Hardening Script
# For Ubuntu 24 / Linux Mint 21
#############################################

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Log file
LOG_FILE="/var/log/cyberpatriot_audit_$(date +%Y%m%d_%H%M%S).log"

# Secure password for admins
SECURE_ADMIN_PASSWORD=""

#############################################
# Utility Functions
#############################################

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

print_header() {
    echo -e "${CYAN}${BOLD}"
    echo "════════════════════════════════════════════════════════════"
    echo "$1"
    echo "════════════════════════════════════════════════════════════"
    echo -e "${NC}"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
    log_message "SUCCESS: $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
    log_message "ERROR: $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
    log_message "WARNING: $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
    log_message "INFO: $1"
}

confirm_action() {
    echo -e -n "${YELLOW}$1 (y/n): ${NC}"
    read -r response
    [[ "$response" =~ ^[Yy]$ ]]
}

press_enter() {
    echo -e "\n${CYAN}Press Enter to continue...${NC}"
    read -r
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

#############################################
# ASCII Art / Splash Screen
#############################################

show_splash() {
    clear
    echo -e "${CYAN}${BOLD}"
    cat << "EOF"
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║    ██████╗ ██████╗ ██████╗      ██████╗ ███╗   ██╗███████╗
    ║   ██╔═══██╗██╔══██╗██╔══██╗    ██╔═══██╗████╗  ██║██╔════╝
    ║   ██║   ██║██║  ██║██║  ██║    ██║   ██║██╔██╗ ██║█████╗  
    ║   ██║   ██║██║  ██║██║  ██║    ██║   ██║██║╚██╗██║██╔══╝  
    ║   ╚██████╔╝██████╔╝██████╔╝    ╚██████╔╝██║ ╚████║███████╗
    ║    ╚═════╝ ╚═════╝ ╚═════╝      ╚═════╝ ╚═╝  ╚═══╝╚══════╝
    ║                                                           ║
    ║            ██████╗ ██╗   ██╗████████╗                    ║
    ║           ██╔═══██╗██║   ██║╚══██╔══╝                    ║
    ║           ██║   ██║██║   ██║   ██║                       ║
    ║           ██║   ██║██║   ██║   ██║                       ║
    ║           ╚██████╔╝╚██████╔╝   ██║                       ║
    ║            ╚═════╝  ╚═════╝    ╚═╝                       ║
    ║                                                           ║
    ║           Security Hardening & Audit Tool                ║
    ║              CyberPatriot Competition                    ║
    ║                   Ubuntu 24 / Mint 21                    ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
EOF
    echo -e "${NC}"
    echo -e "${YELLOW}                    System: $(hostname)${NC}"
    echo -e "${YELLOW}                    Date: $(date)${NC}"
    echo ""
    sleep 1
}

#############################################
# Task 1: User Auditing
#############################################

user_auditing() {
    print_header "USER AUDITING MODULE"
    
    # Show currently logged in users
    echo -e "\n${BOLD}Currently Logged In Users:${NC}"
    print_info "Showing active user sessions with 'w' command"
    echo ""
    w
    echo ""
    press_enter
    
    # Get main username
    echo -e "${CYAN}Enter the main username (currently logged in user):${NC}"
    read -r MAIN_USER
    
    if ! id "$MAIN_USER" &>/dev/null; then
        print_error "User $MAIN_USER does not exist!"
        press_enter
        return 1
    fi
    
    print_success "Main user set to: $MAIN_USER"
    
    # Get secure admin password
    echo -e "\n${CYAN}Enter the secure password for admin accounts:${NC}"
    read -r SECURE_ADMIN_PASSWORD
    echo
    echo -e "${CYAN}Confirm secure password:${NC}"
    read -r SECURE_ADMIN_PASSWORD_CONFIRM
    echo
    
    if [[ "$SECURE_ADMIN_PASSWORD" != "$SECURE_ADMIN_PASSWORD_CONFIRM" ]]; then
        print_error "Passwords do not match!"
        press_enter
        return 1
    fi
    
    print_success "Secure admin password set"
    
    # Get list of authorized admins
    echo -e "\n${CYAN}Enter authorized admin users and their passwords${NC}"
    echo -e "${YELLOW}Format: username (press Enter)${NC}"
    echo -e "${YELLOW}Enter 'done' when finished${NC}\n"
    
    declare -A AUTHORIZED_ADMINS
    while true; do
        echo -e -n "${CYAN}Admin username (or 'done'): ${NC}"
        read -r admin_user
        [[ "$admin_user" == "done" ]] && break
        [[ -z "$admin_user" ]] && continue
        
        echo -e -n "${CYAN}Password for $admin_user: ${NC}"
        read -r admin_pass
        echo
        
        AUTHORIZED_ADMINS["$admin_user"]="$admin_pass"
        print_success "Added admin: $admin_user"
    done
    
    # Get list of authorized regular users
    echo -e "\n${CYAN}Enter authorized regular (non-admin) users${NC}"
    echo -e "${YELLOW}Enter one username per line, 'done' when finished${NC}\n"
    
    AUTHORIZED_USERS=()
    while true; do
        echo -e -n "${CYAN}Username (or 'done'): ${NC}"     
        read -r user
        [[ "$user" == "done" ]] && break
        [[ -z "$user" ]] && continue
        
        AUTHORIZED_USERS+=("$user")
        print_success "Added authorized user: $user"
    done
    
    echo ""
    print_header "AUDIT RESULTS"
    
    # Get all human users on the system (UID >= 1000 and < 65534)
    SYSTEM_USERS=()
    while IFS=: read -r username _ uid _ _ home shell; do
        # Skip system users and nobody
        if [[ $uid -ge 1000 && $uid -lt 65534 && "$shell" != "/usr/sbin/nologin" && "$shell" != "/bin/false" ]]; then
            SYSTEM_USERS+=("$username")
        fi
    done < /etc/passwd
    
    print_info "Found ${#SYSTEM_USERS[@]} human users on the system"
    
    # Check for hidden users (UID 500-999 or users with valid shells in unusual ranges)
    echo -e "\n${BOLD}Checking for hidden users...${NC}"
    HIDDEN_USERS=()
    while IFS=: read -r username _ uid _ _ home shell; do
        # Check for users in the 500-999 range with valid shells
        if [[ $uid -ge 500 && $uid -lt 1000 && "$shell" != "/usr/sbin/nologin" && "$shell" != "/bin/false" && "$shell" != "" ]]; then
            # Common system users to ignore
            if [[ "$username" != "sync" && "$username" != "games" && "$username" != "man" && "$username" != "lp" ]]; then
                HIDDEN_USERS+=("$username:$uid")
                print_warning "POTENTIAL HIDDEN USER: $username (UID: $uid, Shell: $shell)"
            fi
        fi
        
        # Check for users with UID < 500 but with bash/sh shells (suspicious)
        if [[ $uid -lt 500 && "$uid" != "0" ]]; then
            if [[ "$shell" == "/bin/bash" || "$shell" == "/bin/sh" || "$shell" == "/bin/zsh" ]]; then
                HIDDEN_USERS+=("$username:$uid")
                print_warning "SUSPICIOUS SYSTEM USER WITH SHELL: $username (UID: $uid, Shell: $shell)"
            fi
        fi
    done < /etc/passwd
    
    if [[ ${#HIDDEN_USERS[@]} -gt 0 ]]; then
        echo -e "\n${RED}${BOLD}Found ${#HIDDEN_USERS[@]} potential hidden user(s)${NC}"
        print_info "These users have UIDs in unusual ranges or suspicious shell access"
        
        if confirm_action "Review and potentially remove these hidden users?"; then
            for hidden_entry in "${HIDDEN_USERS[@]}"; do
                hidden_user="${hidden_entry%%:*}"
                hidden_uid="${hidden_entry##*:}"
                
                echo -e "\n${YELLOW}User: $hidden_user (UID: $hidden_uid)${NC}"
                groups "$hidden_user"
                
                if confirm_action "Remove hidden user $hidden_user?"; then
                    userdel -r "$hidden_user" 2>/dev/null
                    if [[ $? -eq 0 ]]; then
                        print_success "Removed hidden user: $hidden_user"
                    else
                        print_error "Failed to remove user: $hidden_user"
                    fi
                else
                    print_info "Keeping user: $hidden_user"
                fi
            done
        fi
    else
        print_success "No hidden users detected"
    fi
    
    # Check for unauthorized users
    echo -e "\n${BOLD}Checking for unauthorized users...${NC}"
    UNAUTHORIZED_USERS=()
    
    for sys_user in "${SYSTEM_USERS[@]}"; do
        is_authorized=false
        
        # Check if user is the main user
        if [[ "$sys_user" == "$MAIN_USER" ]]; then
            is_authorized=true
        fi
        
        # Check if user is in admin list
        for admin in "${!AUTHORIZED_ADMINS[@]}"; do
            if [[ "$sys_user" == "$admin" ]]; then
                is_authorized=true
                break
            fi
        done
        
        # Check if user is in regular users list
        for user in "${AUTHORIZED_USERS[@]}"; do
            if [[ "$sys_user" == "$user" ]]; then
                is_authorized=true
                break
            fi
        done
        
        if [[ "$is_authorized" == false ]]; then
            UNAUTHORIZED_USERS+=("$sys_user")
            print_warning "UNAUTHORIZED USER FOUND: $sys_user"
        fi
    done
    
    # Handle unauthorized users
    if [[ ${#UNAUTHORIZED_USERS[@]} -gt 0 ]]; then
        echo -e "\n${RED}${BOLD}Found ${#UNAUTHORIZED_USERS[@]} unauthorized user(s)${NC}"
        if confirm_action "Do you want to remove these unauthorized users?"; then
            for unauth_user in "${UNAUTHORIZED_USERS[@]}"; do
                if confirm_action "Remove user $unauth_user?"; then
                    userdel "$unauth_user" 2>/dev/null
                    if [[ $? -eq 0 ]]; then
                        print_success "Removed user: $unauth_user"
                    else
                        print_error "Failed to remove user: $unauth_user"
                    fi
                fi
            done
        fi
    else
        print_success "No unauthorized users found"
    fi
    
    # Check admin privileges
    echo -e "\n${BOLD}Checking admin privileges...${NC}"
    
    for admin in "${!AUTHORIZED_ADMINS[@]}"; do
        if id "$admin" &>/dev/null; then
            # Check if user is in sudo group
            if groups "$admin" | grep -qw "sudo\|wheel\|admin"; then
                print_success "$admin has admin privileges"
                
                # Update admin password to secure password
                if confirm_action "Update $admin password to the secure password?"; then
                    echo "$admin:$SECURE_ADMIN_PASSWORD" | chpasswd
                    if [[ $? -eq 0 ]]; then
                        print_success "Updated password for $admin"
                        # Force password change on next login (optional)
                        # passwd -e "$admin"
                    else
                        print_error "Failed to update password for $admin"
                    fi
                fi
            else
                print_warning "$admin does NOT have admin privileges"
                if confirm_action "Grant admin privileges to $admin?"; then
                    usermod -aG sudo "$admin"
                    print_success "Granted admin privileges to $admin"
                    
                    # Set secure password
                    echo "$admin:$SECURE_ADMIN_PASSWORD" | chpasswd
                    print_success "Set secure password for $admin"
                fi
            fi
        else
            print_warning "$admin does not exist on the system"
            if confirm_action "Create user $admin with admin privileges?"; then
                useradd -m -s /bin/bash "$admin"
                usermod -aG sudo "$admin"
                echo "$admin:$SECURE_ADMIN_PASSWORD" | chpasswd
                print_success "Created admin user: $admin"
            fi
        fi
    done
    
    # Check regular users don't have admin privileges
    echo -e "\n${BOLD}Checking regular users for incorrect admin privileges...${NC}"
    
    for user in "${AUTHORIZED_USERS[@]}"; do
        if id "$user" &>/dev/null; then
            if groups "$user" | grep -qw "sudo\|wheel\|admin"; then
                print_warning "$user has admin privileges but should NOT"
                if confirm_action "Remove admin privileges from $user?"; then
                    gpasswd -d "$user" sudo 2>/dev/null
                    gpasswd -d "$user" wheel 2>/dev/null
                    gpasswd -d "$user" admin 2>/dev/null
                    print_success "Removed admin privileges from $user"
                fi
            else
                print_success "$user correctly has no admin privileges"
            fi
        else
            print_warning "$user does not exist on the system"
        fi
    done
    
    # Check main user
    echo -e "\n${BOLD}Checking main user...${NC}"
    if groups "$MAIN_USER" | grep -qw "sudo\|wheel\|admin"; then
        print_success "$MAIN_USER has admin privileges"
    else
        print_warning "$MAIN_USER does NOT have admin privileges"
        if confirm_action "Grant admin privileges to $MAIN_USER?"; then
            usermod -aG sudo "$MAIN_USER"
            print_success "Granted admin privileges to $MAIN_USER"
        fi
    fi
    
    # Check for extra UID 0 accounts
    echo -e "\n${BOLD}Checking for Extra UID 0 Accounts...${NC}"
    print_info "Only 'root' should have UID 0"
    
    local uid0_accounts=()
    while IFS=: read -r username _ uid _; do
        if [[ "$uid" == "0" && "$username" != "root" ]]; then
            uid0_accounts+=("$username")
        fi
    done < /etc/passwd
    
    if [[ ${#uid0_accounts[@]} -gt 0 ]]; then
        print_warning "Found ${#uid0_accounts[@]} extra UID 0 account(s)!"
        for account in "${uid0_accounts[@]}"; do
            echo -e "  ${RED}!${NC} $account has UID 0 (root privileges)"
        done
        
        if confirm_action "Remove these extra UID 0 accounts?"; then
            for account in "${uid0_accounts[@]}"; do
                if confirm_action "Delete account: $account?"; then
                    userdel -r "$account" 2>/dev/null
                    if [[ $? -eq 0 ]]; then
                        print_success "Removed UID 0 account: $account"
                        log_message "REMOVED EXTRA UID 0 ACCOUNT: $account"
                    else
                        print_error "Failed to remove: $account"
                    fi
                fi
            done
        fi
    else
        print_success "No extra UID 0 accounts found"
    fi
    
    # Check for unlocked service accounts
    echo -e "\n${BOLD}Checking for Unlocked Service Accounts...${NC}"
    print_info "Service accounts (UID < 1000) should be locked"
    
    local unlocked_services=()
    while IFS=: read -r username _ uid _ _ _ shell; do
        if [[ $uid -lt 1000 && $uid -ne 0 ]]; then
            local passwd_status=$(passwd -S "$username" 2>/dev/null | awk '{print $2}')
            if [[ "$passwd_status" != "L" && "$passwd_status" != "LK" ]]; then
                if [[ "$shell" != "/usr/sbin/nologin" && "$shell" != "/bin/false" && -n "$shell" ]]; then
                    unlocked_services+=("$username:$uid:$shell")
                fi
            fi
        fi
    done < /etc/passwd
    
    if [[ ${#unlocked_services[@]} -gt 0 ]]; then
        print_warning "Found ${#unlocked_services[@]} potentially unlocked service account(s)"
        for entry in "${unlocked_services[@]}"; do
            echo -e "  ${YELLOW}!${NC} $entry"
        done
        
        if confirm_action "Lock these service accounts?"; then
            for entry in "${unlocked_services[@]}"; do
                local svc_user="${entry%%:*}"
                if confirm_action "Lock account: $svc_user?"; then
                    passwd -l "$svc_user" 2>/dev/null
                    usermod -s /usr/sbin/nologin "$svc_user" 2>/dev/null
                    if [[ $? -eq 0 ]]; then
                        print_success "Locked service account: $svc_user"
                        log_message "LOCKED SERVICE ACCOUNT: $svc_user"
                    fi
                fi
            done
        fi
    else
        print_success "No unlocked service accounts found"
    fi
    
    # Check for unauthorized group members in critical groups
    echo -e "\n${BOLD}Checking Critical Group Memberships...${NC}"
    print_info "Reviewing sudo, admin, wheel groups"
    
    local critical_groups=("sudo" "admin" "wheel")
    for group in "${critical_groups[@]}"; do
        if getent group "$group" &>/dev/null; then
            local members=$(getent group "$group" | cut -d: -f4)
            if [[ -n "$members" ]]; then
                echo -e "\n${CYAN}Group '$group' members:${NC} $members"
                
                if confirm_action "Review members of $group?"; then
                    IFS=',' read -ra MEMBER_ARRAY <<< "$members"
                    for member in "${MEMBER_ARRAY[@]}"; do
                        echo -e "\n${YELLOW}User: $member${NC}"
                        id "$member" 2>/dev/null || echo "User not found"
                        
                        if confirm_action "Remove $member from $group?"; then
                            gpasswd -d "$member" "$group" 2>/dev/null
                            if [[ $? -eq 0 ]]; then
                                print_success "Removed $member from $group"
                                log_message "REMOVED FROM GROUP $group: $member"
                            fi
                        fi
                    done
                fi
            else
                print_info "Group '$group' has no members"
            fi
        fi
    done
    
    # Check for SSH authorized_keys
    echo -e "\n${BOLD}Checking SSH Authorized Keys...${NC}"
    print_info "Scanning for SSH keys in user home directories"
    
    local keys_found=0
    while IFS=: read -r username _ uid _ _ homedir _; do
        if [[ $uid -ge 1000 && $uid -lt 65534 ]]; then
            if [[ -f "$homedir/.ssh/authorized_keys" ]]; then
                local key_count=$(wc -l < "$homedir/.ssh/authorized_keys" 2>/dev/null || echo 0)
                if [[ $key_count -gt 0 ]]; then
                    echo -e "\n${YELLOW}User: $username${NC} has $key_count SSH key(s)"
                    ((keys_found++))
                    
                    if confirm_action "Review SSH keys for $username?"; then
                        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                        cat "$homedir/.ssh/authorized_keys"
                        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                        
                        if confirm_action "Remove ALL keys for $username?"; then
                            rm -f "$homedir/.ssh/authorized_keys"
                            print_success "Removed authorized_keys for $username"
                            log_message "REMOVED SSH KEYS: $username"
                        fi
                    fi
                fi
            fi
        fi
    done < /etc/passwd
    
    if [[ $keys_found -eq 0 ]]; then
        print_success "No SSH authorized_keys files found"
    fi
    
    print_header "USER AUDIT COMPLETE"
    press_enter
}

#############################################
# Task 2: Disable Root Login
#############################################

disable_root_login() {
    print_header "DISABLE ROOT LOGIN"
    print_info "This module will disable root login for security"
    
    local changes_made=false
    local ssh_config="/etc/ssh/sshd_config"
    local ssh_config_backup="${ssh_config}.bak.$(date +%Y%m%d_%H%M%S)"
    
    # 1. Disable root login via SSH
    echo -e "\n${BOLD}Configuring SSH to disable root login...${NC}"
    
    if [[ -f "$ssh_config" ]]; then
        # Create backup
        cp "$ssh_config" "$ssh_config_backup"
        print_success "Created backup: $ssh_config_backup"
        
        # Check current PermitRootLogin setting
        if grep -q "^PermitRootLogin" "$ssh_config"; then
            # Setting exists, modify it
            sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$ssh_config"
            print_success "Modified PermitRootLogin to 'no' in $ssh_config"
            changes_made=true
        elif grep -q "^#PermitRootLogin" "$ssh_config"; then
            # Setting is commented, uncomment and set to no
            sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' "$ssh_config"
            print_success "Uncommented and set PermitRootLogin to 'no' in $ssh_config"
            changes_made=true
        else
            # Setting doesn't exist, add it
            echo "PermitRootLogin no" >> "$ssh_config"
            print_success "Added 'PermitRootLogin no' to $ssh_config"
            changes_made=true
        fi
        
        # Verify the change
        if grep -q "^PermitRootLogin no" "$ssh_config"; then
            print_success "Verified: PermitRootLogin is set to 'no'"
        else
            print_error "Failed to set PermitRootLogin to 'no'"
        fi
        
        # Restart SSH service to apply changes
        if confirm_action "Restart SSH service to apply changes?"; then
            if systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null; then
                print_success "SSH service restarted successfully"
            else
                print_error "Failed to restart SSH service"
            fi
        fi
    else
        print_warning "SSH config file not found at $ssh_config"
    fi
    
    # 2. Lock the root password
    echo -e "\n${BOLD}Locking root password...${NC}"
    
    # Check if root password is already locked
    if passwd -S root 2>/dev/null | grep -q "L"; then
        print_info "Root password is already locked"
    else
        if confirm_action "Lock the root password?"; then
            passwd -l root 2>/dev/null
            if [[ $? -eq 0 ]]; then
                print_success "Root password locked successfully"
                changes_made=true
                
                # Verify the lock
                if passwd -S root 2>/dev/null | grep -q "L"; then
                    print_success "Verified: Root password is locked"
                else
                    print_warning "Could not verify root password lock status"
                fi
            else
                print_error "Failed to lock root password"
            fi
        fi
    fi
    
    # 3. Restrict 'su' command to admin group only
    echo -e "\n${BOLD}Restricting 'su' command to admin group...${NC}"
    
    # Determine the admin group (sudo or wheel)
    local admin_group="sudo"
    if ! getent group sudo >/dev/null 2>&1; then
        if getent group wheel >/dev/null 2>&1; then
            admin_group="wheel"
        else
            print_warning "Neither 'sudo' nor 'wheel' group found"
            admin_group="sudo"
        fi
    fi
    
    print_info "Using admin group: $admin_group"
    
    if [[ -f "/bin/su" ]]; then
        # Get current permissions
        local current_perms=$(stat -c "%a" /bin/su 2>/dev/null)
        local current_group=$(stat -c "%G" /bin/su 2>/dev/null)
        
        print_info "Current /bin/su permissions: $current_perms, group: $current_group"
        
        if confirm_action "Restrict /bin/su to root:$admin_group with 4750 permissions?"; then
            # Change ownership and permissions
            chown root:$admin_group /bin/su
            chmod 4750 /bin/su
            
            # Use dpkg-statoverride to make the change permanent
            # First remove any existing override
            dpkg-statoverride --remove /bin/su 2>/dev/null
            
            # Add the new override
            dpkg-statoverride --update --add root $admin_group 4750 /bin/su
            
            if [[ $? -eq 0 ]]; then
                print_success "Restricted /bin/su to root:$admin_group with 4750 permissions"
                print_success "Override registered with dpkg-statoverride"
                changes_made=true
                
                # Verify the change
                local new_perms=$(stat -c "%a" /bin/su 2>/dev/null)
                local new_group=$(stat -c "%G" /bin/su 2>/dev/null)
                print_success "Verified: /bin/su permissions: $new_perms, group: $new_group"
            else
                print_error "Failed to restrict /bin/su"
            fi
        fi
    else
        print_warning "/bin/su not found, checking /usr/bin/su..."
        
        if [[ -f "/usr/bin/su" ]]; then
            if confirm_action "Restrict /usr/bin/su to root:$admin_group with 4750 permissions?"; then
                chown root:$admin_group /usr/bin/su
                chmod 4750 /usr/bin/su
                dpkg-statoverride --remove /usr/bin/su 2>/dev/null
                dpkg-statoverride --update --add root $admin_group 4750 /usr/bin/su
                
                if [[ $? -eq 0 ]]; then
                    print_success "Restricted /usr/bin/su to root:$admin_group with 4750 permissions"
                    changes_made=true
                else
                    print_error "Failed to restrict /usr/bin/su"
                fi
            fi
        else
            print_error "Could not find 'su' binary"
        fi
    fi
    
    # Summary
    echo -e "\n${BOLD}Summary of Root Login Restrictions:${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Check SSH
    if grep -q "^PermitRootLogin no" "$ssh_config" 2>/dev/null; then
        echo -e "${GREEN}✓${NC} SSH root login: DISABLED"
    else
        echo -e "${RED}✗${NC} SSH root login: NOT DISABLED"
    fi
    
    # Check root password
    if passwd -S root 2>/dev/null | grep -q "L"; then
        echo -e "${GREEN}✓${NC} Root password: LOCKED"
    else
        echo -e "${RED}✗${NC} Root password: NOT LOCKED"
    fi
    
    # Check su permissions
    if [[ -f "/bin/su" ]]; then
        local su_perms=$(stat -c "%a" /bin/su 2>/dev/null)
        if [[ "$su_perms" == "4750" ]]; then
            echo -e "${GREEN}✓${NC} /bin/su permissions: RESTRICTED ($su_perms)"
        else
            echo -e "${YELLOW}!${NC} /bin/su permissions: $su_perms"
        fi
    elif [[ -f "/usr/bin/su" ]]; then
        local su_perms=$(stat -c "%a" /usr/bin/su 2>/dev/null)
        if [[ "$su_perms" == "4750" ]]; then
            echo -e "${GREEN}✓${NC} /usr/bin/su permissions: RESTRICTED ($su_perms)"
        else
            echo -e "${YELLOW}!${NC} /usr/bin/su permissions: $su_perms"
        fi
    fi
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if [[ "$changes_made" == true ]]; then
        print_success "Root login has been successfully disabled"
    else
        print_info "No changes were made"
    fi
    
    print_header "ROOT LOGIN DISABLE COMPLETE"
    press_enter
}

#############################################
# Repository Verification Module
#############################################

verify_repositories() {
    print_header "REPOSITORY VERIFICATION MODULE"
    print_info "This module verifies package sources and source code repositories are authorized"
    
    local changes_made=false
    local suspicious_count=0
    
    # ========================================
    # Part 1: Package Repository Verification
    # ========================================
    echo -e "\n${BOLD}${CYAN}═══ PACKAGE REPOSITORY VERIFICATION ═══${NC}"
    print_info "Checking APT package sources for unauthorized repositories"
    
    if confirm_action "Scan for unauthorized package repositories?"; then
        local suspicious_repos=()
        
        # Define authorized domains for package repositories
        local authorized_domains=(
            "ubuntu.com"
            "canonical.com"
            "linuxmint.com"
            "debian.org"
            "google.com"
            "microsoft.com"
            "dl.google.com"
            "packages.microsoft.com"
        )
        
        # Check /etc/apt/sources.list
        echo -e "\n${CYAN}Checking /etc/apt/sources.list...${NC}"
        
        if [[ -f "/etc/apt/sources.list" ]]; then
            while IFS= read -r line; do
                # Skip comments and empty lines
                [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
                
                # Check if line contains any authorized domain
                local is_authorized=false
                for domain in "${authorized_domains[@]}"; do
                    if echo "$line" | grep -q "$domain"; then
                        is_authorized=true
                        break
                    fi
                done
                
                if [[ "$is_authorized" == false ]]; then
                    suspicious_repos+=("/etc/apt/sources.list: $line")
                    ((suspicious_count++))
                fi
            done < /etc/apt/sources.list
        fi
        
        # Check /etc/apt/sources.list.d/
        if [[ -d "/etc/apt/sources.list.d" ]]; then
            echo -e "${CYAN}Checking /etc/apt/sources.list.d/...${NC}"
            
            for repo_file in /etc/apt/sources.list.d/*.list; do
                if [[ -f "$repo_file" ]]; then
                    while IFS= read -r line; do
                        [[ "$line" =~ ^#.*$ || -z "$line" ]] && continue
                        
                        local is_authorized=false
                        for domain in "${authorized_domains[@]}"; do
                            if echo "$line" | grep -q "$domain"; then
                                is_authorized=true
                                break
                            fi
                        done
                        
                        if [[ "$is_authorized" == false ]]; then
                            suspicious_repos+=("$(basename "$repo_file"): $line")
                            ((suspicious_count++))
                        fi
                    done < "$repo_file"
                fi
            done
        fi
        
        # Report findings for package repositories
        if [[ ${#suspicious_repos[@]} -gt 0 ]]; then
            print_warning "Found ${#suspicious_repos[@]} potentially unauthorized package repository entry/entries"
            
            echo -e "\n${YELLOW}Suspicious package repositories:${NC}"
            for repo in "${suspicious_repos[@]}"; do
                echo -e "  ${RED}!${NC} $repo"
            done
            
            if confirm_action "Review and remove unauthorized package repositories?"; then
                echo -e "\n${YELLOW}Opening repository configuration...${NC}"
                print_info "Review the file and remove any unauthorized entries"
                print_info "Press Ctrl+X to exit nano, then Y to save"
                
                if confirm_action "Edit /etc/apt/sources.list?"; then
                    cp /etc/apt/sources.list /etc/apt/sources.list.bak.$(date +%Y%m%d_%H%M%S)
                    nano /etc/apt/sources.list
                    print_success "Repository file backed up and edited"
                    changes_made=true
                fi
                
                if [[ -d "/etc/apt/sources.list.d" ]]; then
                    if confirm_action "Review /etc/apt/sources.list.d/ files?"; then
                        ls -lh /etc/apt/sources.list.d/
                        
                        for repo_file in /etc/apt/sources.list.d/*.list; do
                            if [[ -f "$repo_file" ]]; then
                                echo -e "\n${BOLD}File: $(basename "$repo_file")${NC}"
                                cat "$repo_file"
                                
                                if confirm_action "Edit this file?"; then
                                    cp "$repo_file" "${repo_file}.bak.$(date +%Y%m%d_%H%M%S)"
                                    nano "$repo_file"
                                    changes_made=true
                                fi
                                
                                if confirm_action "Delete this repository file entirely?"; then
                                    rm -f "$repo_file"
                                    print_success "Removed: $(basename "$repo_file")"
                                    changes_made=true
                                    log_message "REMOVED UNAUTHORIZED PACKAGE REPOSITORY: $(basename "$repo_file")"
                                fi
                            fi
                        done
                    fi
                fi
                
                if [[ "$changes_made" == true ]]; then
                    print_info "Updating package lists after repository changes..."
                    apt update
                fi
            fi
        else
            print_success "All package repositories appear to be from authorized sources"
        fi
    fi
    
    # ========================================
    # Summary
    # ========================================
    echo -e "\n${BOLD}Repository Verification Summary:${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}[i]${NC} Total suspicious repositories found: $suspicious_count"
    
    if [[ "$changes_made" == true ]]; then
        print_success "Repository verification and cleanup completed"
        print_info "Changes logged to: $LOG_FILE"
    else
        print_info "No changes were made during verification"
    fi
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    print_header "REPOSITORY VERIFICATION COMPLETE"
    press_enter
}

#############################################
# Task 3: Firewall Configuration
#############################################

configure_firewall() {
    print_header "FIREWALL CONFIGURATION (UFW)"
    print_info "This module will configure UFW firewall with secure defaults"
    
    local changes_made=false
    
    # 1. Check if UFW is installed
    echo -e "\n${BOLD}Checking UFW installation...${NC}"
    
    if ! command -v ufw &> /dev/null; then
        print_warning "UFW is not installed"
        if confirm_action "Install UFW?"; then
            apt update
            apt install -y ufw
            if [[ $? -eq 0 ]]; then
                print_success "UFW installed successfully"
                changes_made=true
            else
                print_error "Failed to install UFW"
                press_enter
                return 1
            fi
        else
            print_error "UFW is required for this module"
            press_enter
            return 1
        fi
    else
        print_success "UFW is already installed"
    fi
    
    # 2. Check current UFW status
    echo -e "\n${BOLD}Current UFW Status:${NC}"
    ufw status verbose
    echo ""
    
    # 3. Configure default policies
    echo -e "${BOLD}Configuring default firewall policies...${NC}"
    
    if confirm_action "Set default policy to REJECT incoming connections?"; then
        ufw default reject incoming
        print_success "Default incoming policy set to REJECT"
        changes_made=true
    fi
    
    if confirm_action "Set default policy to ALLOW outgoing connections?"; then
        ufw default allow outgoing
        print_success "Default outgoing policy set to ALLOW"
        changes_made=true
    fi
    
    # 4. Allow essential services
    echo -e "\n${BOLD}Configuring essential services...${NC}"
    
    # SSH
    if confirm_action "Allow SSH (port 22) through the firewall?"; then
        ufw allow ssh
        print_success "SSH allowed through firewall"
        changes_made=true
    else
        print_warning "SSH not allowed - you may lose remote access!"
    fi
    
    # HTTPS
    if confirm_action "Allow HTTPS (port 443) through the firewall?"; then
        ufw allow https
        print_success "HTTPS allowed through firewall"
        changes_made=true
    fi
    
    # 6. Review rules before enabling
    echo -e "\n${BOLD}Current Firewall Rules:${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    ufw show added
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # 7. Enable UFW
    echo -e "\n${BOLD}Enabling UFW...${NC}"
    
    # Check if already enabled
    if ufw status | grep -q "Status: active"; then
        print_info "UFW is already active"
        if [[ "$changes_made" == true ]]; then
            if confirm_action "Reload UFW to apply changes?"; then
                ufw reload
                print_success "UFW reloaded with new rules"
            fi
        fi
    else
        if confirm_action "Enable UFW firewall now?"; then
            # Enable UFW (with --force to avoid interactive prompt)
            ufw --force enable
            if [[ $? -eq 0 ]]; then
                print_success "UFW enabled successfully"
                changes_made=true
            else
                print_error "Failed to enable UFW"
            fi
        else
            print_warning "UFW is configured but NOT enabled"
            print_info "Run 'sudo ufw enable' manually to activate the firewall"
        fi
    fi
    
    # 8. Display final status
    echo -e "\n${BOLD}Final UFW Status:${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    ufw status verbose
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # 9. Summary
    echo -e "\n${BOLD}Firewall Configuration Summary:${NC}"
    
    if ufw status | grep -q "Status: active"; then
        echo -e "${GREEN}✓${NC} UFW Status: ACTIVE"
    else
        echo -e "${RED}✗${NC} UFW Status: INACTIVE"
    fi
    
    if ufw status verbose | grep -q "Default: reject (incoming)"; then
        echo -e "${GREEN}✓${NC} Default Incoming: REJECT"
    else
        echo -e "${YELLOW}!${NC} Default Incoming: NOT SET TO REJECT"
    fi
    
    if ufw status verbose | grep -q "Default: allow (outgoing)"; then
        echo -e "${GREEN}✓${NC} Default Outgoing: ALLOW"
    else
        echo -e "${YELLOW}!${NC} Default Outgoing: NOT SET TO ALLOW"
    fi
    
    # Count rules
    local rule_count=$(ufw status numbered | grep -c "^\[")
    echo -e "${BLUE}[i]${NC} Total firewall rules: $rule_count"
    
    if [[ "$changes_made" == true ]]; then
        print_success "Firewall configuration completed successfully"
    else
        print_info "No changes were made to the firewall"
    fi
    
    print_header "FIREWALL CONFIGURATION COMPLETE"
    press_enter
}

#############################################
# Task 5: Service Audit & Prohibited Software Removal
#############################################

audit_services() {
    print_header "SERVICE AUDIT & PROHIBITED SOFTWARE REMOVAL"
    print_info "This module will remove prohibited packages and disable unauthorized services"
    
    local changes_made=false
    local packages_removed=0
    local services_disabled=0
    
    # Define prohibited packages (LAMP-aware)
    local prohibited_packages=(
    # Remote Access / Backdoors / RATS
    "telnet"
    "telnetd"
    "rsh-client"
    "rsh-server"
    "tightvncserver"
    "x11vnc"
    "vnc4server"
    "teamviewer"
    "anydesk"

    # Enumeration / Recon / Packet Analysis
    "nmap"
    "masscan"
    "zmap"
    "netcat"
    "netcat-openbsd"
    "netcat-traditional"
    "socat"
    "kismet"
    "aircrack-ng"
    "bettercap"
    "hcxtools"

    # MITM / Sniffing / Attacking Tools
    "ettercap-text-only"
    "ettercap-graphical"
    "ettercap-common"
    "dsniff"
    "arpspoof"
    "responder"

    # Vulnerability Scanners / Exploit Frameworks
    "nikto"
    "hydra"
    "john"
    "ophcrack"
    "hashcat"
    "metasploit-framework"
    "exploitdb"
    "sqlmap"
    "wafw00f"
    "burpsuite"

    # DoS / Packet Crafting Tools
    "hping3"
    "scapy"
    "yersinia"
    "slowloris"
    "boofuzz"

    # Proxies / Anonymity / VPN (usually unnecessary)
    "tor"
    "torsocks"
    "proxychains"

    # Remote Management Daemons (insecure)
    "snmp"
    "snmpd"
    "telnetd"
    "finger"
    "finger-server"

    # Peer-to-peer / sharing (unneeded)
    "bittorrent"
    "deluge"
    "qbittorrent"
    "rtorrent"

    # Other unnecessary packages often removed
    "cups"            # Only disable if print scoring not required
    "cups-browsed"
    "avahi-daemon"    # mDNS, usually disabled in CP
    "bluetooth"
)
    
    # Define prohibited services
    local prohibited_services=(
        # --- Telnet / RLogin / Rsh (insecure remote shells) ---
        "telnet"
        "telnetd"
        "rsh"
        "rsh-server"
        "rlogin"
        "rexec"
        "rinetd"

        # --- SNMP / Monitoring ---
        "snmpd"
        "snmp"
        "snmptrapd"
        "collectd"

        # --- Remote Desktop / VNC ---
        "vncserver"
        "vino"
        "tigervnc"
        "x11vnc"
        "tightvnc"

        # --- Printing & Avahi (not needed unless CP explicitly tests printing) ---
        "cups"
        "cups-browsed"
        "avahi-daemon"

        # --- UPnP / Zeroconf (auto-discovery - security risk) ---
        "avahi-daemon"
        "zeroconf"
        "bonjour"

        # --- Misc insecure / unnecessary ---
        "finger"
        "finger-server"
        "talk"
        "talkd"
        "rpc-statd"
        "rwalld"
        "cupsd"
        "modemmanager"
        "whoopsie"          # crash reporting unnecessary
        "kismet"            # wireless sniffing
        "wireshark"         # not a service, but sometimes has daemons
        "minidlna"          # media servers
        "transmission-daemon" # torrent client daemon (disallowed)
    )

    
    # Check if SSH should be kept
    echo -e "\n${CYAN}SSH Configuration Check${NC}"
    local keep_ssh=false
    if confirm_action "Is SSH/OpenSSH required for this system (check README)?"; then
        keep_ssh=true
        print_info "SSH will be kept and secured"
    else
        print_warning "SSH will be considered for removal"
        prohibited_packages+=("openssh-server" "ssh")
        prohibited_services+=("ssh" "sshd")
    fi
    
    # Part 1: Remove Prohibited Packages (confirm per-package)
    echo -e "\n${BOLD}Step 1: Scanning for prohibited packages...${NC}"
    print_info "Checking for hacking tools, unnecessary servers, and prohibited software"
    
    declare -a found_packages=()
    
    for pkg in "${prohibited_packages[@]}"; do
        if dpkg -l | grep -q "^ii.*$pkg"; then
            found_packages+=("$pkg")
        fi
    done
    
    if [[ ${#found_packages[@]} -eq 0 ]]; then
        print_success "No prohibited packages found!"
    else
        print_warning "Found ${#found_packages[@]} prohibited package(s):"
        for pkg in "${found_packages[@]}"; do
            echo -e "  ${YELLOW}•${NC} $pkg"
        done
        
        # Confirm and remove each package individually
        for pkg in "${found_packages[@]}"; do
            if confirm_action "Remove package: $pkg?"; then
                echo -e "\n${CYAN}Removing: $pkg${NC}"
                
                # Try purge first (removes package and config files)
                if apt purge -y "$pkg" 2>/dev/null; then
                    print_success "Purged: $pkg"
                    ((packages_removed++))
                    changes_made=true
                    log_message "REMOVED PACKAGE: $pkg"
                elif apt remove --purge -y "$pkg" 2>/dev/null; then
                    print_success "Removed: $pkg"
                    ((packages_removed++))
                    changes_made=true
                    log_message "REMOVED PACKAGE: $pkg"
                else
                    print_warning "Could not remove: $pkg (may not be installed or removal failed)"
                fi
            else
                print_info "Skipped removal of: $pkg"
            fi
        done
        
        # Check for netcat in /etc
        echo -e "\n${BOLD}Checking for netcat references in /etc...${NC}"
        if grep -r "netcat" /etc 2>/dev/null | head -5; then
            print_warning "Found netcat references in /etc (shown above)"
            if confirm_action "Review and manually clean netcat references?"; then
                print_info "Use: sudo grep -r netcat /etc"
                print_info "Then manually edit the files to remove references"
            fi
        else
            print_success "No netcat references found in /etc"
        fi
        
        # Run autoremove to clean up dependencies
        echo -e "\n${BOLD}Cleaning up unused dependencies...${NC}"
        if confirm_action "Run apt autoremove to clean up?"; then
            apt autoremove -y
            print_success "Cleaned up unused dependencies"
        fi
    fi
    
    # Part 2: Audit and Disable Prohibited Services (confirm per-service)
    echo -e "\n${BOLD}Step 2: Scanning for prohibited services...${NC}"
    print_info "Checking active services that should be disabled"
    
    declare -a found_services=()
    
    # Get list of active or enabled prohibited services
    for service in "${prohibited_services[@]}"; do
        # Check if service exists and is active
        if systemctl list-units --type=service --state=active 2>/dev/null | grep -q "$service"; then
            found_services+=("$service")
        elif systemctl is-enabled "$service" 2>/dev/null | grep -q "enabled"; then
            found_services+=("$service")
        fi
    done
    
    if [[ ${#found_services[@]} -eq 0 ]]; then
        print_success "No prohibited services found running!"
    else
        print_warning "Found ${#found_services[@]} service(s) that may need disabling:"
        
        for svc in "${found_services[@]}"; do
            # Get service status
            local status=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
            local enabled=$(systemctl is-enabled "$svc" 2>/dev/null || echo "disabled")
            echo -e "  ${YELLOW}•${NC} $svc (status: $status, enabled: $enabled)"
        done
        
        # Confirm and disable/stop each service individually
        for svc in "${found_services[@]}"; do
            local status=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
            local enabled=$(systemctl is-enabled "$svc" 2>/dev/null || echo "disabled")
            echo -e "\n${CYAN}Service: $svc (status: $status, enabled: $enabled)${NC}"
            
            if confirm_action "Disable and stop service: $svc?"; then
                echo -e "${CYAN}Disabling service: $svc${NC}"
                
                # Unmask if masked
                systemctl unmask "$svc" 2>/dev/null
                
                # Disable and stop the service immediately with --now flag
                if systemctl disable --now "$svc" 2>/dev/null; then
                    print_success "Disabled and stopped: $svc"
                    ((services_disabled++))
                    changes_made=true
                    log_message "DISABLED SERVICE: $svc"
                else
                    print_warning "Could not disable: $svc (may not exist or already disabled)"
                fi
                
                # Verify it's stopped and disabled
                local status=$(systemctl is-active "$svc" 2>/dev/null || echo "inactive")
                local enabled=$(systemctl is-enabled "$svc" 2>/dev/null || echo "disabled")
                
                if [[ "$status" == "inactive" && "$enabled" == "disabled" ]]; then
                    print_success "Verified: $svc is stopped and disabled"
                else
                    print_warning "Service state: active=$status, enabled=$enabled"
                fi
                
                # Ask if user wants to purge the package too
                if confirm_action "Also purge/remove the package for $svc?"; then
                    echo -e "${CYAN}Attempting to remove package: $svc${NC}"
                    
                    # Try to find and remove the package
                    if apt purge -y "$svc" 2>/dev/null; then
                        print_success "Purged package: $svc"
                        log_message "PURGED PACKAGE: $svc"
                    elif apt remove --purge -y "$svc" 2>/dev/null; then
                        print_success "Removed package: $svc"
                        log_message "REMOVED PACKAGE: $svc"
                    else
                        print_info "Package $svc not found or already removed"
                    fi
                fi
            else
                print_info "Skipped disabling: $svc"
            fi
        done
    fi
    
    # Part 3: Show all active services for manual review
    echo -e "\n${BOLD}Step 3: Active Services Review${NC}"
    if confirm_action "Display all currently active services for review?"; then
        echo -e "\n${CYAN}Currently Active Services:${NC}"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        systemctl list-units --type=service --state=active --no-pager | grep -v "^UNIT" | head -20
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        
        echo -e "\n${YELLOW}To check a specific service:${NC}"
        echo -e "  sudo systemctl status <service-name>"
        echo -e "${YELLOW}To disable a service manually:${NC}"
        echo -e "  sudo systemctl disable --now <service-name>"
    fi
    
    # Part 5: Enable Security Services
    echo -e "\n${BOLD}Step 4: Security Services${NC}"
    print_info "Enabling critical security services"
    
    # Enable AppArmor
    echo -e "\n${BOLD}Checking AppArmor...${NC}"
    if ! systemctl is-active apparmor &>/dev/null; then
        if confirm_action "Enable and start AppArmor?"; then
            systemctl enable apparmor 2>/dev/null
            systemctl start apparmor 2>/dev/null
            if [[ $? -eq 0 ]]; then
                print_success "AppArmor enabled and started"
                changes_made=true
            else
                print_error "Failed to enable AppArmor (may not be installed)"
            fi
        fi
    else
        print_success "AppArmor already running"
    fi
    
    # Enable rsyslog
    echo -e "\n${BOLD}Checking rsyslog...${NC}"
    if ! systemctl is-active rsyslog &>/dev/null; then
        if confirm_action "Enable and start rsyslog (system logging)?"; then
            systemctl enable rsyslog 2>/dev/null
            systemctl start rsyslog 2>/dev/null
            if [[ $? -eq 0 ]]; then
                print_success "rsyslog enabled and started"
                changes_made=true
            else
                print_error "Failed to enable rsyslog"
            fi
        fi
    else
        print_success "rsyslog already running"
    fi
    
    # Part 6: Network Connections Audit
    echo -e "\n${BOLD}Step 5: Network Connections Audit${NC}"
    print_info "Checking active network connections and listening ports"
    
    if confirm_action "Display active network connections (netstat -tupan)?"; then
        echo -e "\n${CYAN}Active Network Connections:${NC}"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        
        if command -v netstat &>/dev/null; then
            netstat -tupan 2>/dev/null | head -30
        elif command -v ss &>/dev/null; then
            print_info "Using 'ss' (modern replacement for netstat)"
            ss -tupan | head -30
        else
            print_warning "Neither netstat nor ss found - install net-tools"
            print_info "Run: sudo apt install net-tools"
        fi
        
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        
        echo -e "\n${YELLOW}Review the connections above:${NC}"
        echo -e "  - Look for unusual ports or connections"
        echo -e "  - Check PIDs with: ${CYAN}sudo ps aux | grep <PID>${NC}"
        echo -e "  - Kill suspicious processes: ${CYAN}sudo kill -9 <PID>${NC}"
        
        press_enter
    fi
    
    # Part 8: Package Installation History
    echo -e "\n${BOLD}Step 7: Package Installation History${NC}"
    print_info "Reviewing recently installed packages"
    
    if confirm_action "Review /var/log/apt history?"; then
        if [[ -f "/var/log/apt/history.log" ]]; then
            echo -e "\n${CYAN}Recent Package Changes (last 50 lines):${NC}"
            echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            tail -50 /var/log/apt/history.log
            echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            
            echo -e "\n${YELLOW}Look for:${NC}"
            echo -e "  - Unauthorized game installs (goldeneye, pixeldungeon, themole)"
            echo -e "  - Hacking tools (wireshark, nmap, john, hydra)"
            echo -e "  - Suspicious packages installed recently"
            
            press_enter
        else
            print_warning "/var/log/apt/history.log not found"
        fi
        
        if [[ -d "/var/log/apt" ]]; then
            echo -e "\n${CYAN}All APT log files:${NC}"
            ls -lh /var/log/apt/
            
            if confirm_action "View full history.log file?"; then
                less /var/log/apt/history.log
            fi
        fi
    fi
    
    # Final Summary
    echo -e "\n${BOLD}Service Audit Summary:${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}[i]${NC} Prohibited packages removed: $packages_removed"
    echo -e "${BLUE}[i]${NC} Services disabled: $services_disabled"
    
    if [[ "$keep_ssh" == true ]]; then
        echo -e "${GREEN}✓${NC} SSH retained (as required)"
    fi
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if [[ "$changes_made" == true ]]; then
        print_success "Service audit and cleanup completed"
        print_info "Removed packages are logged to: $LOG_FILE"
    else
        print_info "No changes were made"
    fi
    
    print_header "SERVICE AUDIT COMPLETE"
    press_enter
}


#############################################
# Task 6: File Permissions Audit
#############################################

audit_file_permissions() {
    print_header "FILE PERMISSIONS AUDIT"
    print_info "This module will secure critical system file permissions"
    
    local changes_made=false
    
    # 1. Secure critical system file permissions
    echo -e "\n${BOLD}Checking critical system file permissions...${NC}"
    print_info "Verifying permissions on /etc/passwd, /etc/shadow, /etc/group, /etc/gshadow, /etc/sudoers"
    
    local files_fixed=0
    
    # /etc/passwd - should be 644 root:root
    if [[ -f "/etc/passwd" ]]; then
        local current_perms=$(stat -c "%a" /etc/passwd 2>/dev/null)
        local current_owner=$(stat -c "%U:%G" /etc/passwd 2>/dev/null)
        print_info "/etc/passwd - Current: $current_perms $current_owner (Required: 644 root:root)"
        
        if [[ "$current_perms" != "644" ]] || [[ "$current_owner" != "root:root" ]]; then
            if confirm_action "Fix /etc/passwd permissions to 644 root:root?"; then
                chown root:root /etc/passwd && chmod 644 /etc/passwd
                if [[ $? -eq 0 ]]; then
                    print_success "Fixed /etc/passwd permissions"
                    ((files_fixed++))
                    changes_made=true
                else
                    print_error "Failed to fix /etc/passwd permissions"
                fi
            fi
        else
            print_success "/etc/passwd has correct permissions"
        fi
    else
        print_error "/etc/passwd not found!"
    fi
    
    # /etc/shadow - should be 640 root:shadow
    if [[ -f "/etc/shadow" ]]; then
        local current_perms=$(stat -c "%a" /etc/shadow 2>/dev/null)
        local current_owner=$(stat -c "%U:%G" /etc/shadow 2>/dev/null)
        print_info "/etc/shadow - Current: $current_perms $current_owner (Required: 640 root:shadow)"
        
        if [[ "$current_perms" != "640" ]] || [[ "$current_owner" != "root:shadow" ]]; then
            if confirm_action "Fix /etc/shadow permissions to 640 root:shadow?"; then
                chown root:shadow /etc/shadow && chmod 640 /etc/shadow
                if [[ $? -eq 0 ]]; then
                    print_success "Fixed /etc/shadow permissions"
                    ((files_fixed++))
                    changes_made=true
                else
                    print_error "Failed to fix /etc/shadow permissions"
                fi
            fi
        else
            print_success "/etc/shadow has correct permissions"
        fi
    else
        print_error "/etc/shadow not found!"
    fi
    
    # /etc/group - should be 644 root:root
    if [[ -f "/etc/group" ]]; then
        local current_perms=$(stat -c "%a" /etc/group 2>/dev/null)
        local current_owner=$(stat -c "%U:%G" /etc/group 2>/dev/null)
        print_info "/etc/group - Current: $current_perms $current_owner (Required: 644 root:root)"
        
        if [[ "$current_perms" != "644" ]] || [[ "$current_owner" != "root:root" ]]; then
            if confirm_action "Fix /etc/group permissions to 644 root:root?"; then
                chown root:root /etc/group && chmod 644 /etc/group
                if [[ $? -eq 0 ]]; then
                    print_success "Fixed /etc/group permissions"
                    ((files_fixed++))
                    changes_made=true
                else
                    print_error "Failed to fix /etc/group permissions"
                fi
            fi
        else
            print_success "/etc/group has correct permissions"
        fi
    else
        print_error "/etc/group not found!"
    fi
    
    # /etc/gshadow - should be 640 root:shadow
    if [[ -f "/etc/gshadow" ]]; then
        local current_perms=$(stat -c "%a" /etc/gshadow 2>/dev/null)
        local current_owner=$(stat -c "%U:%G" /etc/gshadow 2>/dev/null)
        print_info "/etc/gshadow - Current: $current_perms $current_owner (Required: 640 root:shadow)"
        
        if [[ "$current_perms" != "640" ]] || [[ "$current_owner" != "root:shadow" ]]; then
            if confirm_action "Fix /etc/gshadow permissions to 640 root:shadow?"; then
                chown root:shadow /etc/gshadow && chmod 640 /etc/gshadow
                if [[ $? -eq 0 ]]; then
                    print_success "Fixed /etc/gshadow permissions"
                    ((files_fixed++))
                    changes_made=true
                else
                    print_error "Failed to fix /etc/gshadow permissions"
                fi
            fi
        else
            print_success "/etc/gshadow has correct permissions"
        fi
    else
        print_error "/etc/gshadow not found!"
    fi
    
    # /etc/sudoers - should be 440 root:root
    if [[ -f "/etc/sudoers" ]]; then
        local current_perms=$(stat -c "%a" /etc/sudoers 2>/dev/null)
        local current_owner=$(stat -c "%U:%G" /etc/sudoers 2>/dev/null)
        print_info "/etc/sudoers - Current: $current_perms $current_owner (Required: 440 root:root)"
        
        if [[ "$current_perms" != "440" ]] || [[ "$current_owner" != "root:root" ]]; then
            if confirm_action "Fix /etc/sudoers permissions to 440 root:root?"; then
                chown root:root /etc/sudoers && chmod 440 /etc/sudoers
                if [[ $? -eq 0 ]]; then
                    print_success "Fixed /etc/sudoers permissions"
                    ((files_fixed++))
                    changes_made=true
                else
                    print_error "Failed to fix /etc/sudoers permissions"
                fi
            fi
        else
            print_success "/etc/sudoers has correct permissions"
        fi
    else
        print_error "/etc/sudoers not found!"
    fi
    
    if [[ $files_fixed -gt 0 ]]; then
        print_success "Fixed permissions on $files_fixed critical system file(s)"
    else
        print_success "All critical system files have correct permissions"
    fi
    
    # 2. Configure sudoers file
    echo -e "\n${BOLD}Configuring sudoers file...${NC}"
    print_info "This will open visudo to verify secure sudo configuration"
    print_warning "Recommended settings:"
    echo -e "  ${CYAN}Defaults authenticate${NC}"
    echo -e "  ${CYAN}root ALL=(ALL:ALL) ALL${NC}"
    echo -e "  ${CYAN}%admin ALL=(ALL) ALL${NC}"
    echo -e "  ${CYAN}%sudo ALL=(ALL:ALL) ALL${NC}"
    
    if confirm_action "Open visudo to review/edit sudoers file?"; then
        print_warning "Remove unauthorized entries, keep @includedir and Defaults lines"
        visudo
        print_success "Finished editing sudoers"
        changes_made=true
    fi
    
    # Check for direct user entries in sudoers
    echo -e "\n${BOLD}Checking for Direct /etc/sudoers Entries...${NC}"
    print_info "Users should be in sudo group, not directly in sudoers file"
    
    if [[ -f "/etc/sudoers" ]]; then
        local direct_entries=$(grep -E "^[a-zA-Z].*ALL.*ALL" /etc/sudoers 2>/dev/null | grep -v "^root" | grep -v "^%")
        
        if [[ -n "$direct_entries" ]]; then
            print_warning "Found direct user entries in /etc/sudoers:"
            echo -e "${YELLOW}$direct_entries${NC}"
            print_info "These should be removed - users should be in sudo group instead"
            
            if confirm_action "Open sudoers to remove direct user entries?"; then
                visudo
                changes_made=true
            fi
        else
            print_success "No direct user entries in /etc/sudoers"
        fi
    fi
    
    # Scan for unauthorized SETUID/SETGID binaries
    echo -e "\n${BOLD}Scanning for SETUID/SETGID Binaries...${NC}"
    print_info "This scans for binaries with elevated privileges"
    
    if confirm_action "Scan for SETUID/SETGID files?"; then
        local suid_files="/tmp/suid_scan_$(date +%s).txt"
        
        print_info "Scanning filesystem (this may take a minute)..."
        find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null > "$suid_files"
        
        local suid_count=$(wc -l < "$suid_files")
        print_info "Found $suid_count SETUID/SETGID files"
        
        # Known legitimate setuid binaries
        local legitimate_suid=(
            "/usr/bin/sudo"
            "/usr/bin/su"
            "/usr/bin/passwd"
            "/usr/bin/chfn"
            "/usr/bin/chsh"
            "/usr/bin/newgrp"
            "/usr/bin/gpasswd"
            "/usr/bin/mount"
            "/usr/bin/umount"
            "/usr/bin/pkexec"
            "/usr/lib/openssh/ssh-keysign"
            "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
            "/usr/lib/policykit-1/polkit-agent-helper-1"
        )
        
        echo -e "\n${CYAN}Checking for suspicious SETUID/SETGID files:${NC}"
        local suspicious_found=false
        
        while IFS= read -r line; do
            local filepath=$(echo "$line" | awk '{print $NF}')
            local is_legit=false
            
            for legit in "${legitimate_suid[@]}"; do
                if [[ "$filepath" == "$legit" ]]; then
                    is_legit=true
                    break
                fi
            done
            
            if [[ "$is_legit" == false ]]; then
                echo -e "  ${YELLOW}⚠${NC}  $filepath"
                suspicious_found=true
            fi
        done < "$suid_files"
        
        if [[ "$suspicious_found" == false ]]; then
            print_success "All SETUID/SETGID files appear legitimate"
        else
            echo -e "\n${YELLOW}Review suspicious files above${NC}"
            echo -e "To remove SETUID bit: ${CYAN}sudo chmod u-s <file>${NC}"
            echo -e "To remove SETGID bit: ${CYAN}sudo chmod g-s <file>${NC}"
            
            if confirm_action "View full SETUID/SETGID file list?"; then
                less "$suid_files"
            fi
        fi
        
        rm -f "$suid_files"
    fi
    
    # Summary
    echo -e "\n${BOLD}File Permissions Audit Summary:${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Check all critical system files
    if [[ -f "/etc/passwd" ]]; then
        local passwd_perms=$(stat -c "%a" /etc/passwd 2>/dev/null)
        local passwd_owner=$(stat -c "%U:%G" /etc/passwd 2>/dev/null)
        if [[ "$passwd_perms" == "644" && "$passwd_owner" == "root:root" ]]; then
            echo -e "${GREEN}✓${NC} /etc/passwd: 644 root:root (secure)"
        else
            echo -e "${YELLOW}!${NC} /etc/passwd: $passwd_perms $passwd_owner"
        fi
    fi
    
    if [[ -f "/etc/shadow" ]]; then
        local shadow_perms=$(stat -c "%a" /etc/shadow 2>/dev/null)
        local shadow_owner=$(stat -c "%U:%G" /etc/shadow 2>/dev/null)
        if [[ "$shadow_perms" == "640" && "$shadow_owner" == "root:shadow" ]]; then
            echo -e "${GREEN}✓${NC} /etc/shadow: 640 root:shadow (secure)"
        else
            echo -e "${YELLOW}!${NC} /etc/shadow: $shadow_perms $shadow_owner"
        fi
    fi
    
    if [[ -f "/etc/group" ]]; then
        local group_perms=$(stat -c "%a" /etc/group 2>/dev/null)
        local group_owner=$(stat -c "%U:%G" /etc/group 2>/dev/null)
        if [[ "$group_perms" == "644" && "$group_owner" == "root:root" ]]; then
            echo -e "${GREEN}✓${NC} /etc/group: 644 root:root (secure)"
        else
            echo -e "${YELLOW}!${NC} /etc/group: $group_perms $group_owner"
        fi
    fi
    
    if [[ -f "/etc/gshadow" ]]; then
        local gshadow_perms=$(stat -c "%a" /etc/gshadow 2>/dev/null)
        local gshadow_owner=$(stat -c "%U:%G" /etc/gshadow 2>/dev/null)
        if [[ "$gshadow_perms" == "640" && "$gshadow_owner" == "root:shadow" ]]; then
            echo -e "${GREEN}✓${NC} /etc/gshadow: 640 root:shadow (secure)"
        else
            echo -e "${YELLOW}!${NC} /etc/gshadow: $gshadow_perms $gshadow_owner"
        fi
    fi
    
    if [[ -f "/etc/sudoers" ]]; then
        local sudoers_perms=$(stat -c "%a" /etc/sudoers 2>/dev/null)
        local sudoers_owner=$(stat -c "%U:%G" /etc/sudoers 2>/dev/null)
        if [[ "$sudoers_perms" == "440" && "$sudoers_owner" == "root:root" ]]; then
            echo -e "${GREEN}✓${NC} /etc/sudoers: 440 root:root (secure)"
        else
            echo -e "${YELLOW}!${NC} /etc/sudoers: $sudoers_perms $sudoers_owner"
        fi
    fi
    
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if [[ "$changes_made" == true ]]; then
        print_success "File permissions audit completed successfully"
    else
        print_info "No changes were made"
    fi
    
    print_header "FILE PERMISSIONS AUDIT COMPLETE"
    press_enter
}

#############################################
# Task 7: Update System
#############################################

update_system() {
    print_header "SYSTEM UPDATE"
    print_info "This module will update the system and configure automatic updates"
    
    local changes_made=false
    
    # 1. Configure automatic updates (FAST)
    echo -e "\n${BOLD}Step 1: Configure Automatic Security Updates${NC}"
    print_info "Configuring unattended-upgrades for automatic security updates"
    
    if confirm_action "Enable automatic security updates?"; then
        # Install unattended-upgrades if not present
        if ! dpkg -l | grep -q "^ii.*unattended-upgrades"; then
            print_info "Installing unattended-upgrades..."
            apt install -y unattended-upgrades apt-listchanges 2>/dev/null
        fi
        
        # Configure automatic update intervals
        local auto_upgrades="/etc/apt/apt.conf.d/20auto-upgrades"
        cat > "$auto_upgrades" << 'EOF'
APT::Periodic::Enable "1";
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF
        print_success "Configured automatic update intervals (daily)"
        changes_made=true
        
        # Enable and start the service
        systemctl enable unattended-upgrades 2>/dev/null
        systemctl start unattended-upgrades 2>/dev/null
        print_success "Enabled automatic security updates service"
    fi

    # 2. Update package lists (REQUIRED)
    echo -e "\n${BOLD}Step 2: Update Package Lists${NC}"
    if confirm_action "Update apt package lists?"; then
        apt update
        if [[ $? -eq 0 ]]; then
            print_success "Package lists updated"
            changes_made=true
        else
            print_error "Failed to update package lists"
        fi
    fi
    
    # 3. Upgrade packages (COMBINED for speed)
    echo -e "\n${BOLD}Step 3: Upgrade Packages${NC}"
    if confirm_action "Perform full system upgrade (apt upgrade + dist-upgrade)?"; then
        print_info "Running combined upgrade (this may take a few minutes)..."
        apt upgrade -y && apt dist-upgrade -y
        if [[ $? -eq 0 ]]; then
            print_success "System upgraded successfully"
            changes_made=true
        else
            print_error "Upgrade encountered errors"
        fi
    fi
    
    # 4. Cleanup (FAST)
    echo -e "\n${BOLD}Step 4: Cleanup${NC}"
    if confirm_action "Remove unused packages and clean cache?"; then
        apt autoremove -y && apt autoclean
        print_success "Cleanup completed"
        changes_made=true
    fi
    
    # 5. Reboot check
    echo -e "\n${BOLD}Step 5: Reboot Check${NC}"
    if [[ -f /var/run/reboot-required ]]; then
        echo -e "${RED}!${NC} System reboot is required"
        if [[ -f /var/run/reboot-required.pkgs ]]; then
            echo -e "${YELLOW}Packages requiring reboot:${NC}"
            cat /var/run/reboot-required.pkgs | sed 's/^/  - /'
        fi
        print_info "Please reboot the system when convenient"
    else
        print_success "No reboot required"
    fi
    
    # Summary
    echo -e "\n${BOLD}System Update Summary:${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if [[ "$changes_made" == true ]]; then
        echo -e "${GREEN}✓${NC} System has been updated"
        echo -e "${GREEN}✓${NC} Automatic security updates configured"
        echo -e "${GREEN}✓${NC} Update check interval: Daily"
        echo -e "${GREEN}✓${NC} Security updates: Download and install automatically"
    else
        echo -e "${BLUE}[i]${NC} No updates were performed"
    fi
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    print_header "SYSTEM UPDATE COMPLETE"
    press_enter
}

#############################################
# Task 8: Remove Prohibited Software
#############################################

remove_prohibited_software() {
    print_header "REMOVE PROHIBITED SOFTWARE & MEDIA FILES"
    
    local changes_made=false
    
    # Part 4.5: Backdoor Detection
    echo -e "\n${BOLD}Step 3.5: Backdoor Detection${NC}"
    print_info "Scanning for common backdoors and suspicious scripts"
    
    if confirm_action "Scan for backdoors?"; then
        local backdoors_found=0
        
        # Check for netcat backdoors (listening netcat processes)
        echo -e "\n${CYAN}Checking for netcat backdoors...${NC}"
        if pgrep -f "nc.*-l" &>/dev/null || pgrep -f "ncat.*-l" &>/dev/null; then
            print_warning "Found listening netcat process - potential backdoor!"
            ps aux | grep -E "nc.*-l|ncat.*-l" | grep -v grep
            
            if confirm_action "Kill netcat listening processes?"; then
                pkill -f "nc.*-l"
                pkill -f "ncat.*-l"
                print_success "Killed netcat processes"
                changes_made=true
                ((backdoors_found++))
            fi
        else
            print_success "No netcat backdoors detected"
        fi
        
        # Check for python backdoors (reverse shells, suspicious listening scripts)
        echo -e "\n${CYAN}Checking for Python backdoors...${NC}"
        
        # Search for suspicious Python scripts in common locations
        local suspicious_python_scripts=()
        
        # Check for python scripts with socket/subprocess usage (common in backdoors)
        while IFS= read -r -d '' file; do
            if grep -l "socket\|subprocess\|os.system\|eval\|exec" "$file" &>/dev/null; then
                # Further check for suspicious patterns
                if grep -q "socket.*connect\|socket.*bind\|subprocess.*shell=True\|os.system.*bash" "$file"; then
                    suspicious_python_scripts+=("$file")
                fi
            fi
        done < <(find /home /tmp /var/tmp -type f -name "*.py" -print0 2>/dev/null)
        
        if [[ ${#suspicious_python_scripts[@]} -gt 0 ]]; then
            print_warning "Found ${#suspicious_python_scripts[@]} suspicious Python script(s)"
            
            for script in "${suspicious_python_scripts[@]}"; do
                echo -e "\n${YELLOW}Suspicious script: $script${NC}"
                echo -e "${BOLD}Owner:${NC} $(stat -c "%U" "$script" 2>/dev/null)"
                echo -e "${BOLD}Modified:${NC} $(stat -c "%y" "$script" 2>/dev/null | cut -d' ' -f1)"
                
                if confirm_action "View this script?"; then
                    head -20 "$script"
                    echo "..."
                fi
                
                if confirm_action "Remove this Python script?"; then
                    rm -f "$script"
                    print_success "Removed: $script"
                    changes_made=true
                    ((backdoors_found++))
                    log_message "REMOVED PYTHON BACKDOOR: $script"
                fi
            done
        else
            print_success "No suspicious Python scripts detected"
        fi
        
        # Check for unauthorized SSH keys
        echo -e "\n${CYAN}Checking for unauthorized SSH keys...${NC}"
        
        for home_dir in /home/*; do
            if [[ -d "$home_dir/.ssh" ]]; then
                local username=$(basename "$home_dir")
                
                if [[ -f "$home_dir/.ssh/authorized_keys" ]]; then
                    local key_count=$(wc -l < "$home_dir/.ssh/authorized_keys")
                    
                    if [[ $key_count -gt 0 ]]; then
                        echo -e "\n${YELLOW}User $username has $key_count SSH key(s)${NC}"
                        
                        if confirm_action "Review SSH keys for $username?"; then
                            cat "$home_dir/.ssh/authorized_keys"
                            
                            if confirm_action "Remove ALL SSH keys for $username?"; then
                                rm -f "$home_dir/.ssh/authorized_keys"
                                print_success "Removed SSH keys for $username"
                                changes_made=true
                                ((backdoors_found++))
                            fi
                        fi
                    fi
                fi
            fi
        done
        
        # Check for suspicious listening ports
        echo -e "\n${CYAN}Checking for suspicious listening ports...${NC}"
        print_info "Common backdoor ports: 1337, 31337, 4444, 5555, 6666, 8888"
        
        local suspicious_ports=(1337 31337 4444 5555 6666 8888 12345)
        local suspicious_found=false
        
        for port in "${suspicious_ports[@]}"; do
            if ss -tlnp | grep -q ":$port "; then
                print_warning "Found process listening on port $port (common backdoor port)"
                ss -tlnp | grep ":$port "
                suspicious_found=true
            fi
        done
        
        if [[ "$suspicious_found" == false ]]; then
            print_success "No processes listening on common backdoor ports"
        fi
        
        # Check for suspicious files in /tmp and /var/tmp
        echo -e "\n${CYAN}Checking /tmp and /var/tmp for backdoors...${NC}"
        
        local suspicious_files=(
            "/tmp/.ICE-unix/backdoor"
            "/tmp/.X11-unix/backdoor"
            "/var/tmp/.backdoor"
            "/dev/shm/backdoor"
        )
        
        for file in /tmp/.* /tmp/* /var/tmp/.* /var/tmp/* /dev/shm/*; do
            if [[ -f "$file" ]] && file "$file" 2>/dev/null | grep -q "executable\|script"; then
                # Check if it's a shell script or executable
                if [[ -x "$file" ]] || head -1 "$file" 2>/dev/null | grep -q "^#!"; then
                    echo -e "\n${YELLOW}Suspicious executable: $file${NC}"
                    ls -lh "$file"
                    
                    if confirm_action "Remove this file?"; then
                        rm -f "$file"
                        print_success "Removed: $file"
                        changes_made=true
                        ((backdoors_found++))
                    fi
                fi
            fi
        done
        
        echo -e "\n${BOLD}Backdoor Scan Summary:${NC}"
        if [[ $backdoors_found -gt 0 ]]; then
            echo -e "${YELLOW}!${NC} Found and removed $backdoors_found potential backdoor(s)"
        else
            print_success "No backdoors detected"
        fi
    fi

    # Part 5: Audit Cronjobs
    echo -e "\n${BOLD}Step 4: Cronjob Audit${NC}"
    print_info "Checking for scheduled tasks (cronjobs) on the system"
    
    if ! confirm_action "Scan and review cronjobs?"; then
        print_info "Cronjob audit skipped"
        print_header "MEDIA FILE REMOVAL COMPLETE"
        press_enter
        return
    fi
    
    local cron_changes=false
    local crons_removed=0
    
    # Check system-wide crontabs
    echo -e "\n${CYAN}Scanning system-wide crontabs...${NC}"
    
    # 1. Check /etc/crontab
    if [[ -f "/etc/crontab" ]]; then
        echo -e "\n${BOLD}System Crontab (/etc/crontab):${NC}"
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        cat /etc/crontab
        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
        
        if confirm_action "Edit /etc/crontab to remove suspicious entries?"; then
            print_warning "Opening /etc/crontab in nano - remove any suspicious lines"
            nano /etc/crontab
            print_success "Finished editing /etc/crontab"
            cron_changes=true
        fi
    fi
    
    # 2. Check /etc/cron.d/*
    if [[ -d "/etc/cron.d" ]] && [[ -n "$(ls -A /etc/cron.d 2>/dev/null)" ]]; then
        echo -e "\n${BOLD}Cron Jobs in /etc/cron.d/:${NC}"
        for cronfile in /etc/cron.d/*; do
            if [[ -f "$cronfile" ]]; then
                echo -e "\n${YELLOW}File: $cronfile${NC}"
                echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                cat "$cronfile"
                echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                
                if confirm_action "Delete this cron file: $(basename $cronfile)?"; then
                    if rm -f "$cronfile" 2>/dev/null; then
                        print_success "Deleted: $cronfile"
                        ((crons_removed++))
                        cron_changes=true
                        log_message "REMOVED CRON FILE: $cronfile"
                    else
                        print_error "Failed to delete: $cronfile"
                    fi
                fi
            fi
        done
    else
        print_info "No files in /etc/cron.d/"
    fi
    
    # 3. Check user crontabs
    echo -e "\n${BOLD}User Crontabs:${NC}"
    local found_user_crons=false
    
    # Get list of users with crontabs
    for user_cron in /var/spool/cron/crontabs/*; do
        if [[ -f "$user_cron" ]]; then
            found_user_crons=true
            local username=$(basename "$user_cron")
            
            echo -e "\n${YELLOW}Crontab for user: $username${NC}"
            echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            crontab -u "$username" -l 2>/dev/null || cat "$user_cron"
            echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
            
            if confirm_action "Edit crontab for user $username?"; then
                print_warning "Opening crontab editor - delete suspicious entries or remove all"
                crontab -u "$username" -e
                print_success "Finished editing crontab for $username"
                cron_changes=true
            fi
            
            if confirm_action "Remove ALL cronjobs for user $username?"; then
                crontab -u "$username" -r 2>/dev/null
                if [[ $? -eq 0 ]]; then
                    print_success "Removed all cronjobs for $username"
                    ((crons_removed++))
                    cron_changes=true
                    log_message "REMOVED ALL CRONTABS FOR USER: $username"
                else
                    print_error "Failed to remove crontabs for $username"
                fi
            fi
        fi
    done
    
    if [[ "$found_user_crons" == false ]]; then
        print_success "No user crontabs found"
    fi
    
    # 4. Check periodic cron directories
    for cron_dir in /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly; do
        if [[ -d "$cron_dir" ]] && [[ -n "$(ls -A $cron_dir 2>/dev/null)" ]]; then
            echo -e "\n${BOLD}Scripts in $cron_dir:${NC}"
            ls -lh "$cron_dir"
            
            for script in "$cron_dir"/*; do
                if [[ -f "$script" ]] && [[ -x "$script" ]]; then
                    echo -e "\n${YELLOW}Script: $(basename $script)${NC}"
                    
                    if confirm_action "View contents of $(basename $script)?"; then
                        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                        head -20 "$script"
                        echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
                    fi
                    
                    if confirm_action "Delete this script: $(basename $script)?"; then
                        if rm -f "$script" 2>/dev/null; then
                            print_success "Deleted: $script"
                            ((crons_removed++))
                            cron_changes=true
                            log_message "REMOVED CRON SCRIPT: $script"
                        else
                            print_error "Failed to delete: $script"
                        fi
                    fi
                fi
            done
        fi
    done
    
    # Summary
    echo -e "\n${BOLD}Cronjob Audit Summary:${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BLUE}[i]${NC} Cronjobs/scripts removed: $crons_removed"
    
    if [[ "$cron_changes" == true ]]; then
        echo -e "${GREEN}✓${NC} Cronjob audit completed with changes"
        
        # Restart cron service to apply changes
        if confirm_action "Restart cron service to apply changes?"; then
            systemctl restart cron 2>/dev/null || systemctl restart crond 2>/dev/null
            print_success "Cron service restarted"
        fi
    else
        echo -e "${BLUE}[i]${NC} No changes made to cronjobs"
    fi
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    print_header "MEDIA FILE REMOVAL COMPLETE"
    press_enter
}

#############################################
# Task 9: SSH Hardening
#############################################

harden_ssh() {
    print_header "SSH HARDENING"
    print_info "This module will harden SSH configuration"
    
    local changes_made=false
    local ssh_config="/etc/ssh/sshd_config"
    
    # Check if SSH is installed
    if [[ ! -f "$ssh_config" ]]; then
        print_warning "SSH is not installed or config file not found"
        press_enter
        return 1
    fi
    
    # Backup config
    cp "$ssh_config" "${ssh_config}.bak.$(date +%Y%m%d_%H%M%S)"
    print_success "Created backup of sshd_config"
    
    # Helper function to set SSH config parameter
    set_ssh_param() {
        local param=$1
        local value=$2
        
        if grep -q "^${param}" "$ssh_config"; then
            sed -i "s/^${param}.*/${param} ${value}/" "$ssh_config"
        elif grep -q "^#${param}" "$ssh_config"; then
            sed -i "s/^#${param}.*/${param} ${value}/" "$ssh_config"
        else
            echo "${param} ${value}" >> "$ssh_config"
        fi
    }
    
    echo -e "\n${BOLD}Configuring SSH security settings...${NC}"
    
    if confirm_action "Apply comprehensive SSH hardening?"; then
        # Disable root login
        set_ssh_param "PermitRootLogin" "no"
        print_success "Set PermitRootLogin no"
        
        # Disable X11 forwarding
        set_ssh_param "X11Forwarding" "no"
        print_success "Set X11Forwarding no"
        
        # Enable PAM
        set_ssh_param "UsePAM" "yes"
        print_success "Set UsePAM yes"
        
        # Additional security settings
        set_ssh_param "PermitEmptyPasswords" "no"
        set_ssh_param "MaxAuthTries" "3"
        set_ssh_param "HostbasedAuthentication" "no"
        set_ssh_param "IgnoreRhosts" "yes"
        set_ssh_param "PasswordAuthentication" "yes"
        set_ssh_param "PubkeyAuthentication" "yes"
        
        print_success "Applied additional SSH security settings"
        changes_made=true
    fi
    
    # AllowUsers / DenyUsers configuration
    echo -e "\n${BOLD}Configuring SSH user access...${NC}"
    print_warning "You can restrict SSH access to specific users"
    
    if confirm_action "Configure AllowUsers (whitelist specific users)?"; then
        echo -e "${CYAN}Enter usernames to allow (space-separated), or leave empty to skip:${NC}"
        read -r allowed_users
        
        if [[ -n "$allowed_users" ]]; then
            # Remove existing AllowUsers/DenyUsers lines
            sed -i '/^AllowUsers/d' "$ssh_config"
            sed -i '/^DenyUsers/d' "$ssh_config"
            
            echo "AllowUsers $allowed_users" >> "$ssh_config"
            print_success "Set AllowUsers: $allowed_users"
            changes_made=true
        fi
    fi
    
    # Display final config
    echo -e "\n${BOLD}Current SSH Configuration:${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    grep "^Protocol\|^Port\|^AddressFamily\|^PermitRootLogin\|^X11Forwarding\|^UsePAM\|^AllowUsers\|^DenyUsers\|^PermitEmptyPasswords\|^MaxAuthTries" "$ssh_config"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Restart SSH
    if [[ "$changes_made" == true ]]; then
        echo -e "\n${BOLD}Restarting SSH service...${NC}"
        if confirm_action "Restart SSH service to apply changes?"; then
            systemctl restart sshd 2>/dev/null || systemctl restart ssh 2>/dev/null
            if [[ $? -eq 0 ]]; then
                print_success "SSH service restarted"
            else
                print_error "Failed to restart SSH service"
            fi
        fi
    fi
    
    print_header "SSH HARDENING COMPLETE"
    press_enter
}

#############################################
# Task 9b: FTP Server Hardening
#############################################

harden_ftp() {
    print_header "FTP SERVER HARDENING (VSFTPD)"
    print_info "This module will harden FTP server configuration"
    print_warning "FTP is inherently insecure - consider using SFTP instead"
    
    local changes_made=false
    local vsftpd_config="/etc/vsftpd.conf"
    
    # Check if vsftpd is installed
    if [[ ! -f "$vsftpd_config" ]]; then
        print_warning "vsftpd is not installed or config file not found"
            press_enter
            return 1
    fi
    
    # Backup config
    cp "$vsftpd_config" "${vsftpd_config}.bak.$(date +%Y%m%d_%H%M%S)"
    print_success "Created backup of vsftpd.conf"
    
    # Helper function to set vsftpd config parameter
    set_ftp_param() {
        local param=$1
        local value=$2
        
        if grep -q "^${param}=" "$vsftpd_config"; then
            sed -i "s/^${param}=.*/${param}=${value}/" "$vsftpd_config"
        elif grep -q "^#${param}=" "$vsftpd_config"; then
            sed -i "s/^#${param}=.*/${param}=${value}/" "$vsftpd_config"
        else
            echo "${param}=${value}" >> "$vsftpd_config"
        fi
    }
    
    echo -e "\n${BOLD}Configuring FTP security settings...${NC}"
    
    if confirm_action "Apply comprehensive FTP hardening?"; then
        # Anonymous login
        echo -e "\n${BOLD}1. Anonymous Access${NC}"
        set_ftp_param "anonymous_enable" "NO"
        print_success "Disabled anonymous FTP access"
        
        # Local users
        echo -e "\n${BOLD}2. Local User Access${NC}"
        set_ftp_param "local_enable" "YES"
        set_ftp_param "write_enable" "YES"
        print_success "Enabled local user access with write permissions"
        
        # Chroot jail for security
        echo -e "\n${BOLD}3. Chroot Jail (Restrict users to home directory)${NC}"
        set_ftp_param "chroot_local_user" "YES"
        set_ftp_param "allow_writeable_chroot" "YES"
        print_success "Enabled chroot jail for local users"
        
        # SSL/TLS encryption
        echo -e "\n${BOLD}4. SSL/TLS Encryption${NC}"
        if confirm_action "Enable SSL/TLS for FTP (FTPS)?"; then
            set_ftp_param "ssl_enable" "YES"
            set_ftp_param "allow_anon_ssl" "NO"
            set_ftp_param "force_local_data_ssl" "YES"
            set_ftp_param "force_local_logins_ssl" "YES"
            set_ftp_param "ssl_tlsv1" "YES"
            set_ftp_param "ssl_sslv2" "NO"
            set_ftp_param "ssl_sslv3" "NO"
            set_ftp_param "require_ssl_reuse" "NO"
            set_ftp_param "ssl_ciphers" "HIGH"
            
            # Generate self-signed certificate if doesn't exist
            if [[ ! -f "/etc/ssl/private/vsftpd.pem" ]]; then
                print_info "Generating self-signed SSL certificate..."
                openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                    -keyout /etc/ssl/private/vsftpd.pem \
                    -out /etc/ssl/private/vsftpd.pem \
                    -subj "/C=US/ST=State/L=City/O=Organization/CN=ftp.local" 2>/dev/null
                
                if [[ $? -eq 0 ]]; then
                    chmod 600 /etc/ssl/private/vsftpd.pem
                    print_success "Generated SSL certificate"
                fi
            fi
            
            set_ftp_param "rsa_cert_file" "/etc/ssl/private/vsftpd.pem"
            set_ftp_param "rsa_private_key_file" "/etc/ssl/private/vsftpd.pem"
            print_success "Enabled SSL/TLS encryption (FTPS)"
        fi
        
        # Passive mode configuration
        echo -e "\n${BOLD}5. Passive Mode (for NAT/Firewall)${NC}"
        if confirm_action "Configure passive mode?"; then
            set_ftp_param "pasv_enable" "YES"
            set_ftp_param "pasv_min_port" "40000"
            set_ftp_param "pasv_max_port" "50000"
            print_success "Configured passive mode (ports 40000-50000)"
            print_warning "Remember to allow ports 40000-50000 in firewall!"
        fi
        
        # User restrictions
        echo -e "\n${BOLD}6. User Access Control${NC}"
        
        # Create userlist file if doesn't exist
        touch /etc/vsftpd.userlist
        touch /etc/vsftpd.deny_users
        
        set_ftp_param "userlist_enable" "YES"
        set_ftp_param "userlist_deny" "NO"
        set_ftp_param "userlist_file" "/etc/vsftpd.userlist"
        print_success "Enabled user access control (whitelist mode)"
        print_info "Add allowed users to: /etc/vsftpd.userlist"
        
        # Deny specific users from FTP
        if confirm_action "Configure deny list for specific users?"; then
            echo -e "\n${CYAN}Enter username to deny FTP access (or 'done'):${NC}"
            while true; do
                echo -e -n "${CYAN}Username to deny (or 'done'): ${NC}"
                read -r deny_user
                [[ "$deny_user" == "done" || -z "$deny_user" ]] && break
                
                if ! grep -q "^${deny_user}$" /etc/vsftpd.deny_users 2>/dev/null; then
                    echo "$deny_user" >> /etc/vsftpd.deny_users
                    print_success "Added $deny_user to deny list"
                else
                    print_info "$deny_user already in deny list"
                fi
            done
        fi
        
        # Logging
        echo -e "\n${BOLD}7. Logging${NC}"
        set_ftp_param "xferlog_enable" "YES"
        set_ftp_param "xferlog_std_format" "YES"
        set_ftp_param "xferlog_file" "/var/log/vsftpd.log"
        set_ftp_param "log_ftp_protocol" "YES"
        print_success "Enabled comprehensive FTP logging"
        
        # Connection limits
        echo -e "\n${BOLD}8. Connection Limits${NC}"
        set_ftp_param "max_clients" "50"
        set_ftp_param "max_per_ip" "5"
        print_success "Set connection limits (50 total, 5 per IP)"
        
        # Timeouts
        echo -e "\n${BOLD}9. Timeouts${NC}"
        set_ftp_param "idle_session_timeout" "600"
        set_ftp_param "data_connection_timeout" "120"
        print_success "Set session timeout (600s) and data timeout (120s)"
        
        # Banner
        echo -e "\n${BOLD}10. Login Banner${NC}"
        set_ftp_param "ftpd_banner" "Authorized access only. All activity is monitored."
        print_success "Set security banner"
        
        # Disable write commands for specific users
        echo -e "\n${BOLD}11. Write Command Restrictions${NC}"
        if confirm_action "Create write-denied user list?"; then
            touch /etc/vsftpd.readonly_users
            echo -e "\n${CYAN}Enter username to deny write access (or 'done'):${NC}"
            
            while true; do
                echo -e -n "${CYAN}Username for read-only (or 'done'): ${NC}"
                read -r ro_user
                [[ "$ro_user" == "done" || -z "$ro_user" ]] && break
                
                if ! grep -q "^${ro_user}$" /etc/vsftpd.readonly_users 2>/dev/null; then
                    echo "$ro_user" >> /etc/vsftpd.readonly_users
                    print_success "Added $ro_user to read-only list"
                else
                    print_info "$ro_user already in read-only list"
                fi
            done
            
            # Add per-user config directory
            mkdir -p /etc/vsftpd/user_conf
            set_ftp_param "user_config_dir" "/etc/vsftpd/user_conf"
            
            # Create config files for read-only users
            while IFS= read -r ro_user; do
                if [[ -n "$ro_user" ]]; then
                    echo "write_enable=NO" > "/etc/vsftpd/user_conf/${ro_user}"
                    echo "cmds_allowed=FEAT,REST,CWD,LIST,MDTM,MKD,NLST,PASS,PASV,PORT,PWD,QUIT,RETR,SIZE,STOR,TYPE,USER,ACCT,APPE,CDUP,HELP,MODE,NOOP,REIN,STAT,STOU,STRU,SYST" > "/etc/vsftpd/user_conf/${ro_user}"
                    # Remove write commands
                    sed -i 's/,STOR,/,/' "/etc/vsftpd/user_conf/${ro_user}"
                    sed -i 's/,DELE,/,/' "/etc/vsftpd/user_conf/${ro_user}"
                    sed -i 's/,RMD,/,/' "/etc/vsftpd/user_conf/${ro_user}"
                    sed -i 's/,RNFR,/,/' "/etc/vsftpd/user_conf/${ro_user}"
                    sed -i 's/,RNTO,/,/' "/etc/vsftpd/user_conf/${ro_user}"
                    sed -i 's/,APPE,/,/' "/etc/vsftpd/user_conf/${ro_user}"
                fi
            done < /etc/vsftpd.readonly_users
            
            print_success "Configured per-user write restrictions"
        fi
        
        # Additional security settings
        echo -e "\n${BOLD}12. Additional Security${NC}"
        set_ftp_param "hide_ids" "YES"
        set_ftp_param "use_localtime" "YES"
        set_ftp_param "secure_chroot_dir" "/var/run/vsftpd/empty"
        print_success "Applied additional security settings"
        
        changes_made=true
    fi
    
    # Display current configuration
    echo -e "\n${BOLD}Current FTP Configuration Summary:${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    grep "^anonymous_enable\|^local_enable\|^write_enable\|^chroot_local_user\|^ssl_enable\|^pasv_enable\|^userlist_enable\|^max_clients\|^max_per_ip" "$vsftpd_config" 2>/dev/null || echo "Config file may be empty"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    # Restart FTP service
    if [[ "$changes_made" == true ]]; then
        echo -e "\n${BOLD}Restarting FTP service...${NC}"
        if confirm_action "Restart vsftpd service to apply changes?"; then
            systemctl enable vsftpd 2>/dev/null
            systemctl restart vsftpd 2>/dev/null
            if [[ $? -eq 0 ]]; then
                print_success "vsftpd service restarted and enabled"
                
                echo -e "\n${YELLOW}Post-Configuration Steps:${NC}"
                echo -e "  1. Add allowed users to ${CYAN}/etc/vsftpd.userlist${NC}"
                echo -e "  2. If using SSL, clients must connect with FTPS (not plain FTP)"
                echo -e "  3. Open firewall ports: ${CYAN}sudo ufw allow 20,21,40000:50000/tcp${NC}"
                echo -e "  4. Test FTP connection: ${CYAN}ftp localhost${NC}"
                echo -e "  5. Monitor logs: ${CYAN}tail -f /var/log/vsftpd.log${NC}"
            else
                print_error "Failed to restart vsftpd service"
            fi
        fi
    fi
    
    print_header "FTP HARDENING COMPLETE"
    press_enter
}

#############################################
# Task 10: Enable Security Features
#############################################

enable_security_features() {
    print_header "ENABLE SECURITY FEATURES"
    print_info "This module will enable various system security features"
    
    local changes_made=false
    
    # 1. Enable ASLR (Address Space Layout Randomization)
    echo -e "\n${BOLD}Checking ASLR (Address Space Layout Randomization)...${NC}"
    
    local aslr_value=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
    print_info "Current ASLR value: $aslr_value (0=disabled, 1=partial, 2=full)"
    
    if [[ "$aslr_value" != "2" ]]; then
        if confirm_action "Enable full ASLR (randomize_va_space=2)?"; then
            sysctl -w kernel.randomize_va_space=2
            
            # Make it permanent
            if ! grep -q "^kernel.randomize_va_space" /etc/sysctl.conf; then
                echo "kernel.randomize_va_space=2" >> /etc/sysctl.conf
            else
                sed -i 's/^kernel.randomize_va_space.*/kernel.randomize_va_space=2/' /etc/sysctl.conf
            fi
            
            sysctl -p
            print_success "ASLR enabled (full randomization)"
            changes_made=true
        fi
    else
        print_success "ASLR already enabled (full randomization)"
    fi
    
    # 2. Configure /etc/sysctl.conf for network security
    echo -e "\n${BOLD}Configuring sysctl network security settings...${NC}"
    
    if confirm_action "Apply comprehensive sysctl security settings?"; then
        local sysctl_conf="/etc/sysctl.conf"
        cp "$sysctl_conf" "${sysctl_conf}.bak.$(date +%Y%m%d_%H%M%S)"
        print_success "Created backup of sysctl.conf"
        
        # Network security parameters
        local sysctl_params=(
            "net.ipv4.conf.all.rp_filter=1"
            "net.ipv4.conf.default.rp_filter=1"
            "net.ipv4.icmp_echo_ignore_broadcasts=1"
            "net.ipv4.conf.all.accept_source_route=0"
            "net.ipv6.conf.all.accept_source_route=0"
            "net.ipv4.conf.default.accept_source_route=0"
            "net.ipv6.conf.default.accept_source_route=0"
            "net.ipv4.conf.all.send_redirects=0"
            "net.ipv4.conf.default.send_redirects=0"
            "net.ipv4.tcp_syncookies=1"
            "net.ipv4.tcp_max_syn_backlog=2048"
            "net.ipv4.tcp_synack_retries=2"
            "net.ipv4.tcp_syn_retries=5"
            "net.ipv4.conf.all.log_martians=1"
            "net.ipv4.icmp_ignore_bogus_error_responses=1"
            "net.ipv4.conf.all.accept_redirects=0"
            "net.ipv6.conf.all.accept_redirects=0"
            "net.ipv4.conf.default.accept_redirects=0"
            "net.ipv6.conf.default.accept_redirects=0"
            "net.ipv4.ip_forward=0"
            "net.ipv4.tcp_rfc1337=1"
            "kernel.yama.ptrace_scope=1"
            "kernel.pid_max=32768"
            "fs.protected_symlinks=1"
            "fs.protected_fifos=1"
        )
        
        echo -e "\n# CyberPatriot Security Settings - $(date +%Y-%m-%d)" >> "$sysctl_conf"
        
        for param in "${sysctl_params[@]}"; do
            local key="${param%%=*}"
            local value="${param##*=}"
            
            # Remove existing entry if present
            sed -i "/^${key}/d" "$sysctl_conf"
            sed -i "/^#${key}/d" "$sysctl_conf"
            
            # Add new entry
            echo "$param" >> "$sysctl_conf"
        done
        
        # Apply settings
        sysctl -p
        print_success "Applied sysctl security settings"
        changes_made=true
    fi
    
    # 4. Check for insecure sudo configurations
    echo -e "\n${BOLD}Checking sudo configuration for security issues...${NC}"
    
    local sudoers_file="/etc/sudoers"
    local insecure_sudo=false
    
    # Check for NOPASSWD entries
    if grep -rq "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null; then
        print_warning "Found NOPASSWD entries in sudo configuration"
        insecure_sudo=true
        
        echo -e "\n${YELLOW}Insecure sudo entries:${NC}"
        grep -r "NOPASSWD" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#"
        
        if confirm_action "Remove NOPASSWD entries from sudo configuration?"; then
            # Backup sudoers
            cp "$sudoers_file" "${sudoers_file}.bak.$(date +%Y%m%d_%H%M%S)"
            
            # Remove NOPASSWD from main sudoers file
            sed -i 's/NOPASSWD://g' "$sudoers_file"
            
            # Remove NOPASSWD from sudoers.d files
            for file in /etc/sudoers.d/*; do
                if [[ -f "$file" ]]; then
                    sed -i 's/NOPASSWD://g' "$file"
                fi
            done
            
            print_success "Removed NOPASSWD entries from sudo configuration"
            changes_made=true
        fi
    else
        print_success "No insecure NOPASSWD entries found in sudo configuration"
    fi
    
    # Check for overly permissive sudo rules
    if grep -rq "ALL=(ALL:ALL) ALL" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#" | grep -v "%sudo"; then
        print_warning "Found potentially overly permissive sudo rules"
        echo -e "\n${YELLOW}Review these sudo rules:${NC}"
        grep -r "ALL=(ALL:ALL) ALL" /etc/sudoers /etc/sudoers.d/ 2>/dev/null | grep -v "^#" | grep -v "%sudo"
    fi
    
    # 5. Install and configure Fail2Ban
    echo -e "\n${BOLD}Configuring Fail2Ban...${NC}"
    
    if ! command -v fail2ban-client &>/dev/null; then
        if confirm_action "Install Fail2Ban for intrusion prevention?"; then
            apt install -y fail2ban
            if [[ $? -eq 0 ]]; then
                print_success "Fail2Ban installed"
                changes_made=true
            else
                print_error "Failed to install Fail2Ban"
            fi
        fi
    else
        print_success "Fail2Ban already installed"
    fi
    
    if command -v fail2ban-client &>/dev/null; then
        if confirm_action "Configure Fail2Ban for SSH protection?"; then
            local jail_local="/etc/fail2ban/jail.local"
            
            cat > "$jail_local" << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled  = true
port     = ssh,2222
filter   = sshd
logpath  = /var/log/auth.log
maxretry = 3
EOF
            
            print_success "Configured Fail2Ban for SSH"
            
            systemctl enable fail2ban
            systemctl restart fail2ban
            print_success "Fail2Ban enabled and restarted"
            changes_made=true
        fi
    fi
    
    # 8. Configure DNS (if BIND is installed)
    if [[ -f "/etc/bind/named.conf.options" ]]; then
        echo -e "\n${BOLD}Configuring DNS (BIND) security...${NC}"
        
        if confirm_action "Disable DNS recursion and hide version?"; then
            cp /etc/bind/named.conf.options /etc/bind/named.conf.options.bak.$(date +%Y%m%d_%H%M%S)
            
            # Add to options section if not present
            if ! grep -q "recursion no;" /etc/bind/named.conf.options; then
                sed -i '/options {/a \    recursion no;' /etc/bind/named.conf.options
                print_success "Disabled DNS recursion"
            fi
            
            if ! grep -q "version" /etc/bind/named.conf.options; then
                sed -i '/options {/a \    version "Not Disclosed";' /etc/bind/named.conf.options
                print_success "Hidden BIND version"
            fi
            
            systemctl restart bind9 2>/dev/null
            print_success "BIND9 restarted"
            changes_made=true
        fi
    fi
    
    # 9. Web Server Security (ask first if it should be configured or disabled)
    echo -e "\n${BOLD}Web Server Configuration${NC}"
    
    local is_web_server=false
    if confirm_action "Is this system a WEB SERVER (check README)?"; then
        is_web_server=true
    fi
    
    # Apache Configuration
    if systemctl is-active apache2 &>/dev/null || [[ -d "/etc/apache2" ]]; then
        if [[ "$is_web_server" == true ]]; then
            echo -e "\n${BOLD}Hardening Apache...${NC}"
            
            if confirm_action "Apply Apache security hardening?"; then
                local apache_security="/etc/apache2/conf-enabled/security.conf"
                
                if [[ -f "$apache_security" ]]; then
                    cp "$apache_security" "${apache_security}.bak.$(date +%Y%m%d_%H%M%S)"
                    
                    # Set ServerTokens to Prod (least information disclosure)
                    sed -i 's/^ServerTokens.*/ServerTokens Prod/' "$apache_security"
                    if ! grep -q "^ServerTokens" "$apache_security"; then
                        echo "ServerTokens Prod" >> "$apache_security"
                    fi
                    print_success "Set ServerTokens to Prod (least verbose)"
                    
                    # Disable ServerSignature
                    sed -i 's/^ServerSignature.*/ServerSignature Off/' "$apache_security"
                    if ! grep -q "^ServerSignature" "$apache_security"; then
                        echo "ServerSignature Off" >> "$apache_security"
                    fi
                    print_success "Disabled Apache server signature"
                    
                    print_success "Configured Apache security settings"
                    
                    systemctl restart apache2
                    print_success "Apache restarted"
                    changes_made=true
                else
                    print_warning "Apache security.conf not found"
                fi
            fi
            
            # WordPress configuration
            if [[ -f "/var/www/html/wp-config.php" ]]; then
                if confirm_action "Disable WordPress debugging?"; then
                    sed -i "s/define('WP_DEBUG', true);/define('WP_DEBUG', false);/" /var/www/html/wp-config.php
                    sed -i "s/define( 'WP_DEBUG', true );/define('WP_DEBUG', false);/" /var/www/html/wp-config.php
                    print_success "Disabled WordPress debugging"
                    changes_made=true
                fi
            fi
        else
            print_warning "System is NOT a web server - Apache should be disabled"
            print_info "Use 'Audit Services' menu option to disable Apache"
        fi
    fi
    
    # Nginx Configuration
    if systemctl is-active nginx &>/dev/null || [[ -d "/etc/nginx" ]]; then
        if [[ "$is_web_server" == true ]]; then
            echo -e "\n${BOLD}Hardening Nginx...${NC}"
            
            if confirm_action "Apply Nginx security hardening?"; then
                local nginx_conf="/etc/nginx/nginx.conf"
                
                if [[ -f "$nginx_conf" ]]; then
                    cp "$nginx_conf" "${nginx_conf}.bak.$(date +%Y%m%d_%H%M%S)"
                    
                    # Add server_tokens off if not present
                    if ! grep -q "server_tokens off;" "$nginx_conf"; then
                        sed -i '/http {/a \    server_tokens off;' "$nginx_conf"
                        print_success "Configured Nginx to hide version"
                        
                        systemctl restart nginx
                        print_success "Nginx restarted"
                        changes_made=true
                    else
                        print_success "Nginx already configured"
                    fi
                else
                    print_warning "Nginx configuration not found"
                fi
            fi
        else
            print_warning "System is NOT a web server - Nginx should be disabled"
            print_info "Use 'Audit Services' menu option to disable Nginx"
        fi
    fi
    
    # Squid Configuration
    if systemctl is-active squid &>/dev/null || [[ -f "/etc/squid/squid.conf" ]]; then
        if [[ "$is_web_server" == true ]]; then
            echo -e "\n${BOLD}Hardening Squid...${NC}"
            
            if confirm_action "Apply Squid security hardening?"; then
                local squid_conf="/etc/squid/squid.conf"
                
                if [[ -f "$squid_conf" ]]; then
                    cp "$squid_conf" "${squid_conf}.bak.$(date +%Y%m%d_%H%M%S)"
                    
                    # Add security settings if not present
                    
                    # Disable X-Forwarded-For headers
                    if ! grep -q "^forwarded_for" "$squid_conf"; then
                        echo "forwarded_for delete" >> "$squid_conf"
                        print_success "Disabled X-Forwarded-For headers"
                    fi
                    
                    # Disable Via headers
                    if ! grep -q "^via" "$squid_conf"; then
                        echo "via off" >> "$squid_conf"
                        print_success "Disabled Via headers"
                    fi
                    
                    # Don't send Squid version
                    if ! grep -q "^httpd_suppress_version_string" "$squid_conf"; then
                        echo "httpd_suppress_version_string on" >> "$squid_conf"
                        print_success "Suppressed Squid version in headers"
                    fi
                    
                    # Ignore unknown nameservers
                    if ! grep -q "^ignore_unknown_nameservers" "$squid_conf"; then
                        echo "ignore_unknown_nameservers on" >> "$squid_conf"
                        print_success "Enabled ignore unknown nameservers"
                    fi
                    
                    # Disable SNMP
                    if ! grep -q "^snmp_port 0" "$squid_conf"; then
                        sed -i 's/^snmp_port.*/snmp_port 0/' "$squid_conf" 2>/dev/null || echo "snmp_port 0" >> "$squid_conf"
                        print_success "Disabled SNMP (set port to 0)"
                    fi
                    
                    print_success "Configured Squid security settings"
                    
                    systemctl restart squid
                    print_success "Squid restarted"
                    changes_made=true
                else
                    print_warning "Squid configuration not found"
                fi
            fi
        else
            print_warning "System is NOT a web server - Squid should be disabled"
            print_info "Use 'Audit Services' menu option to disable Squid"
        fi
    fi
    
    # Summary
    echo -e "\n${BOLD}Security Features Summary:${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    local aslr_current=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
    if [[ "$aslr_current" == "2" ]]; then
        echo -e "${GREEN}✓${NC} ASLR: Enabled (full)"
    else
        echo -e "${YELLOW}!${NC} ASLR: $aslr_current"
    fi
    
    if grep -q "^net.ipv4.tcp_syncookies=1" /etc/sysctl.conf; then
        echo -e "${GREEN}✓${NC} Network hardening: Configured"
    else
        echo -e "${YELLOW}!${NC} Network hardening: Not configured"
    fi
    
    if systemctl is-active apparmor &>/dev/null; then
        echo -e "${GREEN}✓${NC} AppArmor: Active"
    else
        echo -e "${YELLOW}!${NC} AppArmor: Inactive"
    fi
    
    if systemctl is-active rsyslog &>/dev/null; then
        echo -e "${GREEN}✓${NC} rsyslog: Active"
    else
        echo -e "${YELLOW}!${NC} rsyslog: Inactive"
    fi
    
    if systemctl is-active fail2ban &>/dev/null; then
        echo -e "${GREEN}✓${NC} Fail2Ban: Active"
    else
        echo -e "${YELLOW}!${NC} Fail2Ban: Not active"
    fi
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if [[ "$changes_made" == true ]]; then
        print_success "Security features enabled successfully"
        print_warning "Some changes require a reboot to take full effect"
    else
        print_info "No changes were made"
    fi
    
    print_header "SECURITY FEATURES CONFIGURATION COMPLETE"
    press_enter
}

#############################################
# Task 14: OS Settings Configuration
#############################################

configure_os_settings() {
    print_header "OPERATING SYSTEM SETTINGS CONFIGURATION"
    print_info "This module configures system-level security settings"
    echo ""
    
    local changes_made=false
    
    # 5. System Logging Configuration
    echo -e "\n${BOLD}5. System Logging Configuration${NC}"
    print_info "Verifying system logging services"
    
    # Check rsyslog
    if systemctl list-unit-files rsyslog.service &>/dev/null; then
        local rsyslog_status=$(systemctl is-active rsyslog.service 2>/dev/null)
        print_info "rsyslog status: $rsyslog_status"
        
        if [[ "$rsyslog_status" != "active" ]]; then
            if confirm_action "Enable rsyslog for system logging?"; then
                systemctl enable rsyslog.service
                systemctl start rsyslog.service
                print_success "Enabled rsyslog"
                changes_made=true
            fi
        else
            print_success "rsyslog is active"
        fi
    fi
    
    # Check auditd
    if systemctl list-unit-files auditd.service &>/dev/null; then
        local auditd_status=$(systemctl is-active auditd.service 2>/dev/null)
        print_info "auditd status: $auditd_status"
        
        if [[ "$auditd_status" != "active" ]]; then
            print_warning "auditd is not active - advanced security auditing unavailable"
            if confirm_action "Install and enable auditd for security auditing?"; then
                apt-get install -y auditd audispd-plugins
                systemctl enable auditd.service
                systemctl start auditd.service
                print_success "Enabled auditd"
                changes_made=true
            fi
        else
            print_success "auditd is active"
        fi
    else
        if confirm_action "Install auditd for security auditing?"; then
            apt-get install -y auditd audispd-plugins
            systemctl enable auditd.service
            systemctl start auditd.service
            print_success "Installed and enabled auditd"
            changes_made=true
        fi
    fi
    
    # 6. Kernel Parameters (sysctl) Hardening
    echo -e "\n${BOLD}6. Kernel Parameter Hardening${NC}"
    print_info "Configuring kernel security parameters via sysctl"
    
    if confirm_action "Apply kernel security hardening?"; then
        local sysctl_conf="/etc/sysctl.d/99-cyberpatriot-hardening.conf"
        
        cat > "$sysctl_conf" << 'EOF'
# CyberPatriot Kernel Hardening Parameters

# IP Forwarding (disable unless this is a router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable source packet routing
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Disable ICMP redirect acceptance
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0

# Enable IP spoofing protection (reverse path filtering)
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Log suspicious packets (Martians)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_all = 0
net.ipv6.icmp.echo_ignore_all = 0

# Ignore broadcast pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Protect against tcp time-wait assassination hazards
net.ipv4.tcp_rfc1337 = 1

# Enable SYN cookies (SYN flood protection)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096

# Disable IPv6 (if not needed)
# net.ipv6.conf.all.disable_ipv6 = 1
# net.ipv6.conf.default.disable_ipv6 = 1

# Increase system file descriptor limits
fs.file-max = 65535

# Restrict access to kernel logs
kernel.dmesg_restrict = 1

# Restrict access to kernel pointers in /proc
kernel.kptr_restrict = 2

# Enable ASLR (Address Space Layout Randomization)
kernel.randomize_va_space = 2

# Restrict core dumps
fs.suid_dumpable = 0
kernel.core_uses_pid = 1

# Protect hard and symbolic links
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
EOF
        
        # Apply sysctl settings
        sysctl -p "$sysctl_conf" >/dev/null 2>&1
        
        if [[ $? -eq 0 ]]; then
            print_success "Applied kernel hardening parameters"
            print_info "  - IP forwarding: disabled"
            print_info "  - Source routing: disabled"
            print_info "  - ICMP redirects: disabled"
            print_info "  - Reverse path filtering: enabled"
            print_info "  - SYN cookies: enabled"
            print_info "  - Kernel pointer restrictions: enabled"
            print_info "  - ASLR: enabled"
            print_info "  - Core dump restrictions: enabled"
            changes_made=true
        else
            print_error "Failed to apply some sysctl parameters"
        fi
    fi
    
    # 8. AppArmor/SELinux Status
    echo -e "\n${BOLD}8. Mandatory Access Control (AppArmor/SELinux)${NC}"
    print_info "Checking MAC system status"
    
    # Check AppArmor (common on Ubuntu/Mint)
    if command -v aa-status &>/dev/null; then
        print_info "AppArmor detected"
        
        local apparmor_enabled=$(aa-status --enabled 2>/dev/null && echo "yes" || echo "no")
        if [[ "$apparmor_enabled" == "yes" ]]; then
            print_success "AppArmor is enabled"
            
            if confirm_action "View AppArmor status?"; then
                aa-status
                press_enter
            fi
            
            # Check for profiles in complain mode
            local complain_count=$(aa-status 2>/dev/null | grep "profiles are in complain mode" | grep -oP '\d+' | head -1)
            if [[ -n "$complain_count" && "$complain_count" -gt 0 ]]; then
                print_warning "$complain_count AppArmor profiles in complain mode (should be enforce mode)"
                
                if confirm_action "Switch complain mode profiles to enforce mode?"; then
                    for profile in /etc/apparmor.d/*; do
                        if [[ -f "$profile" && ! "$profile" =~ \.dpkg|cache|disable|local ]]; then
                            aa-enforce "$profile" 2>/dev/null
                        fi
                    done
                    print_success "Switched profiles to enforce mode"
                    changes_made=true
                fi
            fi
        else
            print_warning "AppArmor is NOT enabled"
            if confirm_action "Enable AppArmor?"; then
                systemctl enable apparmor.service
                systemctl start apparmor.service
                print_success "Enabled AppArmor"
                print_warning "Reboot required for full AppArmor activation"
                changes_made=true
            fi
        fi
    # Check SELinux (less common on Ubuntu/Mint)
    elif command -v getenforce &>/dev/null; then
        print_info "SELinux detected"
        local selinux_status=$(getenforce 2>/dev/null)
        print_info "SELinux status: $selinux_status"
        
        if [[ "$selinux_status" == "Disabled" ]]; then
            print_warning "SELinux is disabled"
            print_info "Enabling SELinux requires /etc/selinux/config edit and reboot"
        elif [[ "$selinux_status" == "Permissive" ]]; then
            print_warning "SELinux is in permissive mode (should be enforcing)"
            if confirm_action "Set SELinux to enforcing mode?"; then
                setenforce 1
                print_success "Set SELinux to enforcing mode for current session"
                print_info "Edit /etc/selinux/config to make permanent"
                changes_made=true
            fi
        else
            print_success "SELinux is in enforcing mode"
        fi
    else
        print_warning "No MAC system (AppArmor/SELinux) detected"
        print_info "Consider installing AppArmor: apt-get install apparmor apparmor-utils"
    fi
    
    # 10. Additional execution restrictions
    echo -e "\n${BOLD}10. Additional Execution Restrictions${NC}"
    print_info "Restricting execution in temporary directories"
    
    if confirm_action "Restrict execution in /tmp, /var/tmp, /dev/shm?"; then
        local fstab="/etc/fstab"
        cp "$fstab" "${fstab}.bak.$(date +%Y%m%d_%H%M%S)"
        
        local needs_remount=false
        
        # /tmp with noexec, nosuid, nodev
        if ! grep -q "/tmp.*noexec" "$fstab"; then
            echo "tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev,mode=1777 0 0" >> "$fstab"
            print_success "Added /tmp with noexec to fstab"
            needs_remount=true
        fi
        
        # /var/tmp with noexec, nosuid, nodev
        if ! grep -q "/var/tmp.*noexec" "$fstab"; then
            echo "tmpfs /var/tmp tmpfs defaults,noexec,nosuid,nodev,mode=1777 0 0" >> "$fstab"
            print_success "Added /var/tmp with noexec to fstab"
            needs_remount=true
        fi
        
        # /dev/shm with noexec, nosuid, nodev
        if ! grep -q "/dev/shm.*noexec" "$fstab"; then
            if grep -q "^tmpfs /dev/shm" "$fstab"; then
                sed -i 's|^tmpfs /dev/shm tmpfs.*|tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0|' "$fstab"
            else
                echo "tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0" >> "$fstab"
            fi
            print_success "Added /dev/shm with noexec to fstab"
            needs_remount=true
        fi
        
        if [[ "$needs_remount" == "true" ]]; then
            print_warning "Filesystem changes require reboot to take effect"
            print_info "Or remount manually:"
            echo -e "  ${CYAN}mount -o remount /tmp${NC}"
            echo -e "  ${CYAN}mount -o remount /var/tmp${NC}"
            echo -e "  ${CYAN}mount -o remount /dev/shm${NC}"
            changes_made=true
        else
            print_info "Execution restrictions already configured in fstab"
        fi
    fi
    
    # Summary
    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}"
    if [[ "$changes_made" == "true" ]]; then
        print_success "OS Settings configuration completed with changes"
        print_warning "Some changes may require a system reboot to take effect"
    else
        print_info "No changes were made"
    fi
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    
    press_enter
}

#############################################
# Task 15: Application Security Hardening
#############################################

harden_application_security() {
    print_header "APPLICATION SECURITY HARDENING"
    print_info "This module hardens application-specific security settings"
    echo ""
    
    local changes_made=false
    
    # Detect which applications are installed
    echo -e "${BOLD}Detecting Installed Applications...${NC}"
    
    local has_apache=false
    local has_nginx=false
    local has_mysql=false
    local has_mariadb=false
    local has_postgresql=false
    
    if command -v apache2 &>/dev/null || systemctl list-unit-files apache2.service &>/dev/null; then
        print_info "Apache detected"
        has_apache=true
    fi
    
    if command -v nginx &>/dev/null || systemctl list-unit-files nginx.service &>/dev/null; then
        print_info "Nginx detected"
        has_nginx=true
    fi
    
    if command -v mysql &>/dev/null || systemctl list-unit-files mysql.service &>/dev/null; then
        print_info "MySQL detected"
        has_mysql=true
    fi
    
    if command -v mariadb &>/dev/null || systemctl list-unit-files mariadb.service &>/dev/null; then
        print_info "MariaDB detected"
        has_mariadb=true
    fi
    
    if command -v psql &>/dev/null || systemctl list-unit-files postgresql.service &>/dev/null; then
        print_info "PostgreSQL detected"
        has_postgresql=true
    fi
    
    if [[ "$has_apache" == false && "$has_nginx" == false && "$has_mysql" == false && "$has_mariadb" == false && "$has_postgresql" == false ]]; then
        print_warning "No supported applications detected"
        print_info "Supported: Apache, Nginx, MySQL, MariaDB, PostgreSQL"
        press_enter
        return
    fi
    
    echo ""
    
    # Nginx Hardening
    if [[ "$has_nginx" == true ]]; then
        echo -e "\n${BOLD}════════════════════════════════════════════════════════════${NC}"
        echo -e "${BOLD}NGINX WEB SERVER HARDENING${NC}"
        echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
        
        if confirm_action "Harden Nginx configuration?"; then
            local nginx_conf="/etc/nginx/nginx.conf"
            
            if [[ -f "$nginx_conf" ]]; then
                cp "$nginx_conf" "${nginx_conf}.bak.$(date +%Y%m%d_%H%M%S)"
                
                # 1. Hide version number
                if ! grep -q "server_tokens off;" "$nginx_conf"; then
                    sed -i '/http {/a \    server_tokens off;' "$nginx_conf"
                    print_success "Disabled server version disclosure"
                fi
                
                # 2. Client body size limit
                if ! grep -q "client_max_body_size" "$nginx_conf"; then
                    sed -i '/http {/a \    client_max_body_size 10M;' "$nginx_conf"
                    print_success "Limited client body size to 10MB"
                fi
                
                # 4. Timeout settings
                if ! grep -q "client_body_timeout" "$nginx_conf"; then
                    sed -i '/http {/a \    client_body_timeout 10;\n    client_header_timeout 10;\n    keepalive_timeout 5 5;\n    send_timeout 10;' "$nginx_conf"
                    print_success "Configured security timeouts"
                fi
                
                # 5. Create security headers file
                cat > /etc/nginx/conf.d/security-headers.conf << 'EOF'
# Security Headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;
EOF
                print_success "Configured security headers"
                
                # 6. SSL/TLS Configuration
                cat > /etc/nginx/conf.d/ssl-hardening.conf << 'EOF'
# SSL/TLS Hardening
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers HIGH:!aNULL:!MD5:!3DES:!RC4:!EXPORT;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 10m;

# HSTS
add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
EOF
                print_success "Configured SSL/TLS hardening"
                
                # Test configuration and restart
                if nginx -t &>/dev/null; then
                    systemctl restart nginx
                    print_success "Nginx configuration valid - restarted service"
                else
                    print_error "Nginx configuration test failed - NOT restarted"
                    print_info "Run 'nginx -t' to see errors"
                fi
                
                changes_made=true
            else
                print_error "Nginx configuration file not found"
            fi
        fi
    fi
    
    # PostgreSQL Hardening
    if [[ "$has_postgresql" == true ]]; then
        echo -e "\n${BOLD}════════════════════════════════════════════════════════════${NC}"
        echo -e "${BOLD}POSTGRESQL DATABASE HARDENING${NC}"
        echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
        
        if confirm_action "Harden PostgreSQL configuration?"; then
            # Find PostgreSQL version and config directory
            local pg_version=$(psql --version 2>/dev/null | grep -oP '\d+' | head -1)
            local pg_conf="/etc/postgresql/$pg_version/main/postgresql.conf"
            local pg_hba="/etc/postgresql/$pg_version/main/pg_hba.conf"
            
            if [[ -f "$pg_conf" ]]; then
                cp "$pg_conf" "${pg_conf}.bak.$(date +%Y%m%d_%H%M%S)"
                
                # 1. Listen on localhost only
                if confirm_action "Configure PostgreSQL to listen on localhost only?"; then
                    if grep -q "^listen_addresses" "$pg_conf"; then
                        sed -i "s/^listen_addresses.*/listen_addresses = 'localhost'/" "$pg_conf"
                    else
                        echo "listen_addresses = 'localhost'" >> "$pg_conf"
                    fi
                    print_success "PostgreSQL listening on localhost only"
                fi
                
                # 2. Enable SSL
                if ! grep -q "^ssl = on" "$pg_conf"; then
                    sed -i "s/^#ssl = off/ssl = on/" "$pg_conf"
                    sed -i "s/^ssl = off/ssl = on/" "$pg_conf"
                    print_success "Enabled SSL for PostgreSQL"
                fi
                
                # 3. Configure logging
                if ! grep -q "^log_connections" "$pg_conf"; then
                    echo "log_connections = on" >> "$pg_conf"
                    echo "log_disconnections = on" >> "$pg_conf"
                    echo "log_duration = on" >> "$pg_conf"
                    print_success "Enabled connection logging"
                fi
                
                # 4. Connection limits
                if ! grep -q "^max_connections" "$pg_conf"; then
                    echo "max_connections = 100" >> "$pg_conf"
                    print_success "Limited max connections to 100"
                fi
                
                changes_made=true
            fi
            
            # Configure pg_hba.conf
            if [[ -f "$pg_hba" ]]; then
                cp "$pg_hba" "${pg_hba}.bak.$(date +%Y%m%d_%H%M%S)"
                
                print_info "PostgreSQL authentication configuration:"
                print_info "  - Ensure only 'md5' or 'scram-sha-256' auth methods are used"
                print_info "  - Remove 'trust' authentication if present"
                
                if confirm_action "Review pg_hba.conf now?"; then
                    nano "$pg_hba"
                    print_info "Review complete"
                fi
            fi
            
            # Restart PostgreSQL
            systemctl restart postgresql
            print_success "PostgreSQL restarted"
        fi
    fi
    
    # Summary
    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}"
    if [[ "$changes_made" == true ]]; then
        print_success "Application security hardening completed"
        print_info "Services have been restarted where needed"
    else
        print_info "No changes were made"
    fi
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    
    press_enter
}

#############################################
# Task 16: LAMP Stack - Apache Hardening
#############################################

harden_apache() {
    print_header "APACHE WEB SERVER HARDENING"
    print_info "Comprehensive Apache security hardening for LAMP stack"
    echo ""
    
    # Check if Apache is installed
    if ! command -v apache2 &>/dev/null && ! systemctl list-unit-files apache2.service &>/dev/null; then
        print_warning "Apache is not installed on this system"
        press_enter
        return
    fi
    
    local changes_made=false
    local apache_security="/etc/apache2/conf-available/security.conf"
    local apache_conf="/etc/apache2/apache2.conf"
    
    echo -e "${BOLD}This will apply comprehensive Apache hardening.${NC}"
    echo -e "${CYAN}Safe operations will be applied automatically.${NC}"
    echo -e "${YELLOW}Potentially breaking changes will be skipped or prompted.${NC}"
    echo ""
    
    if ! confirm_action "Apply Apache security hardening?"; then
        print_info "Skipping Apache hardening"
        press_enter
        return
    fi
    
    # Backup configs
    [[ -f "$apache_security" ]] && cp "$apache_security" "${apache_security}.bak.$(date +%Y%m%d_%H%M%S)"
    [[ -f "$apache_conf" ]] && cp "$apache_conf" "${apache_conf}.bak.$(date +%Y%m%d_%H%M%S)"
    
    echo -e "\n${BOLD}═══ SAFE OPERATIONS (Auto-applying) ═══${NC}"
    
    # === SAFE: ServerTokens Prod ===
    if [[ -f "$apache_security" ]]; then
        if grep -q "^ServerTokens" "$apache_security"; then
            sed -i 's/^ServerTokens.*/ServerTokens Prod/' "$apache_security"
        else
            echo "ServerTokens Prod" >> "$apache_security"
        fi
        print_success "ServerTokens set to Prod (hide version)"
        
        # === SAFE: ServerSignature Off ===
        if grep -q "^ServerSignature" "$apache_security"; then
            sed -i 's/^ServerSignature.*/ServerSignature Off/' "$apache_security"
        else
            echo "ServerSignature Off" >> "$apache_security"
        fi
        print_success "ServerSignature disabled"
        
        # === SAFE: TraceEnable Off ===
        if ! grep -q "^TraceEnable" "$apache_security"; then
            echo "TraceEnable Off" >> "$apache_security"
        else
            sed -i 's/^TraceEnable.*/TraceEnable Off/' "$apache_security"
        fi
        print_success "TRACE method disabled (XST protection)"
        
        # === SAFE: FileETag None (obscure - prevents inode disclosure) ===
        if ! grep -q "^FileETag" "$apache_security"; then
            echo "FileETag None" >> "$apache_security"
        fi
        print_success "FileETag disabled (inode disclosure protection)"
        
        # === SAFE: Timeout ===
        if ! grep -q "^Timeout" "$apache_security"; then
            echo "Timeout 60" >> "$apache_security"
        fi
        print_success "Connection timeout set to 60 seconds"
        
        # === SAFE: LimitRequestBody ===
        if ! grep -q "^LimitRequestBody" "$apache_security"; then
            echo "LimitRequestBody 10485760" >> "$apache_security"
        fi
        print_success "Request body limit set to 10MB"
        
        # === SAFE: LimitRequestFields ===
        if ! grep -q "^LimitRequestFields" "$apache_security"; then
            echo "LimitRequestFields 100" >> "$apache_security"
        fi
        print_success "Request header count limited to 100"
        
        # === SAFE: LimitRequestFieldSize ===
        if ! grep -q "^LimitRequestFieldSize" "$apache_security"; then
            echo "LimitRequestFieldSize 8190" >> "$apache_security"
        fi
        print_success "Request header size limited to 8KB"
        
        # === SAFE: LimitRequestLine ===
        if ! grep -q "^LimitRequestLine" "$apache_security"; then
            echo "LimitRequestLine 8190" >> "$apache_security"
        fi
        print_success "Request line (URL) size limited to 8KB"
        
        changes_made=true
    fi
    
    # === SAFE: Security Headers ===
    echo -e "\n${BOLD}Configuring security headers...${NC}"
    cat > /etc/apache2/conf-available/security-headers.conf << 'EOF'
# CyberPatriot Security Headers Configuration
<IfModule mod_headers.c>
    # Prevent clickjacking
    Header always set X-Frame-Options "SAMEORIGIN"
    
    # XSS Protection
    Header always set X-XSS-Protection "1; mode=block"
    
    # Prevent MIME sniffing
    Header always set X-Content-Type-Options "nosniff"
    
    # Referrer Policy
    Header always set Referrer-Policy "strict-origin-when-cross-origin"
    
    # Permissions Policy (obscure - often missed)
    Header always set Permissions-Policy "geolocation=(), microphone=(), camera=()"
    
    # Cross-domain policy (obscure - Flash/PDF)
    Header always set X-Permitted-Cross-Domain-Policies "none"
    
    # Remove version disclosure headers
    Header always unset X-Powered-By
    Header unset X-Powered-By
</IfModule>
EOF
    a2enconf security-headers &>/dev/null
    print_success "Security headers configured"
    
    # === SAFE: Enable required modules ===
    a2enmod headers &>/dev/null && print_success "Enabled mod_headers"
    a2enmod rewrite &>/dev/null && print_success "Enabled mod_rewrite"
    
    # === SAFE: Disable info-leaking modules ===
    a2dismod status &>/dev/null 2>&1 && print_success "Disabled mod_status (info leak)"
    a2dismod info &>/dev/null 2>&1 && print_success "Disabled mod_info (info leak)"
    
    # === SAFE: Disable directory listing in main config ===
    if [[ -f "$apache_conf" ]]; then
        if grep -q "Options Indexes" "$apache_conf"; then
            sed -i 's/Options Indexes/Options -Indexes/g' "$apache_conf"
            print_success "Disabled directory listing (Options -Indexes)"
        fi
    fi
    
    # === SAFE: KeepAlive settings ===
    if [[ -f "$apache_conf" ]]; then
        if grep -q "^MaxKeepAliveRequests" "$apache_conf"; then
            sed -i 's/^MaxKeepAliveRequests.*/MaxKeepAliveRequests 100/' "$apache_conf"
        elif grep -q "^#MaxKeepAliveRequests" "$apache_conf"; then
            sed -i 's/^#MaxKeepAliveRequests.*/MaxKeepAliveRequests 100/' "$apache_conf"
        fi
        
        if grep -q "^KeepAliveTimeout" "$apache_conf"; then
            sed -i 's/^KeepAliveTimeout.*/KeepAliveTimeout 5/' "$apache_conf"
        elif grep -q "^#KeepAliveTimeout" "$apache_conf"; then
            sed -i 's/^#KeepAliveTimeout.*/KeepAliveTimeout 5/' "$apache_conf"
        fi
        print_success "KeepAlive settings optimized"
    fi
    
    echo -e "\n${BOLD}═══ CAUTION OPERATIONS ═══${NC}"
    
    # === CAUTION: Disable autoindex (could break if no index file) ===
    if a2query -m autoindex &>/dev/null 2>&1; then
        print_warning "mod_autoindex provides directory listing fallback"
        if confirm_action "Disable mod_autoindex? (Only if index.php/html exists everywhere)"; then
            a2dismod autoindex &>/dev/null
            print_success "Disabled mod_autoindex"
        fi
    fi
    
    # === CAUTION: Disable userdir (~user directories) ===
    if a2query -m userdir &>/dev/null 2>&1; then
        a2dismod userdir &>/dev/null
        print_success "Disabled mod_userdir (~user directories)"
    fi
    
    # === CAUTION: Disable negotiation (can leak file info) ===
    if a2query -m negotiation &>/dev/null 2>&1; then
        a2dismod negotiation &>/dev/null
        print_success "Disabled mod_negotiation (file info leak)"
    fi
    
    # === Enable security config ===
    a2enconf security &>/dev/null
    
    # Test and restart
    echo -e "\n${BOLD}Testing Apache configuration...${NC}"
    if apache2ctl configtest 2>&1 | grep -q "Syntax OK"; then
        print_success "Apache configuration syntax OK"
        systemctl restart apache2
        print_success "Apache restarted"
    else
        print_error "Apache configuration has errors!"
        apache2ctl configtest
        print_warning "Apache NOT restarted - fix errors first"
    fi
    
    # Summary
    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}"
    print_success "Apache hardening complete"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    
    press_enter
}

#############################################
# Task 17: LAMP Stack - MySQL Hardening
#############################################

harden_mysql() {
    print_header "MYSQL/MARIADB DATABASE HARDENING"
    print_info "Comprehensive MySQL security hardening for LAMP stack"
    echo ""
    
    # Check if MySQL/MariaDB is installed
    local has_mysql=false
    local has_mariadb=false
    local mysql_conf=""
    
    if command -v mysql &>/dev/null || systemctl list-unit-files mysql.service &>/dev/null 2>&1; then
        has_mysql=true
        mysql_conf="/etc/mysql/mysql.conf.d/mysqld.cnf"
        [[ ! -f "$mysql_conf" ]] && mysql_conf="/etc/mysql/my.cnf"
    fi
    
    if command -v mariadb &>/dev/null || systemctl list-unit-files mariadb.service &>/dev/null 2>&1; then
        has_mariadb=true
        mysql_conf="/etc/mysql/mariadb.conf.d/50-server.cnf"
        [[ ! -f "$mysql_conf" ]] && mysql_conf="/etc/mysql/my.cnf"
    fi
    
    if [[ "$has_mysql" == false && "$has_mariadb" == false ]]; then
        print_warning "MySQL/MariaDB is not installed on this system"
        press_enter
        return
    fi
    
    local changes_made=false
    local db_type="MySQL"
    [[ "$has_mariadb" == true ]] && db_type="MariaDB"
    
    print_info "Detected: $db_type"
    echo ""
    
    if ! confirm_action "Apply $db_type security hardening?"; then
        print_info "Skipping MySQL hardening"
        press_enter
        return
    fi
    
    # Backup config
    [[ -f "$mysql_conf" ]] && cp "$mysql_conf" "${mysql_conf}.bak.$(date +%Y%m%d_%H%M%S)"
    
    echo -e "\n${BOLD}═══ SAFE OPERATIONS (Auto-applying) ═══${NC}"
    
    if [[ -f "$mysql_conf" ]]; then
        # === SAFE: Disable local-infile ===
        if ! grep -q "^local-infile" "$mysql_conf"; then
            echo "local-infile = 0" >> "$mysql_conf"
        fi
        print_success "Disabled LOCAL INFILE (SQL injection vector)"
        
        # === SAFE: Disable symbolic-links ===
        if ! grep -q "^symbolic-links" "$mysql_conf"; then
            echo "symbolic-links = 0" >> "$mysql_conf"
        fi
        print_success "Disabled symbolic links"
        
        # === SAFE: skip-show-database ===
        if ! grep -q "^skip-show-database" "$mysql_conf"; then
            echo "skip-show-database" >> "$mysql_conf"
        fi
        print_success "Hidden database list from non-admins"
        
        # === SAFE: Error logging ===
        if ! grep -q "^log-error" "$mysql_conf"; then
            echo "log-error = /var/log/mysql/error.log" >> "$mysql_conf"
        fi
        print_success "Error logging enabled"
        
        # === SAFE: Slow query log (obscure - security monitoring) ===
        if ! grep -q "^slow_query_log" "$mysql_conf"; then
            echo "slow_query_log = 1" >> "$mysql_conf"
            echo "slow_query_log_file = /var/log/mysql/slow.log" >> "$mysql_conf"
            echo "long_query_time = 2" >> "$mysql_conf"
        fi
        print_success "Slow query logging enabled"
        
        # === SAFE: Connection limits ===
        if ! grep -q "^max_connections" "$mysql_conf"; then
            echo "max_connections = 100" >> "$mysql_conf"
        fi
        print_success "Max connections limited to 100"
        
        # === SAFE: Connection timeouts ===
        if ! grep -q "^connect_timeout" "$mysql_conf"; then
            echo "connect_timeout = 10" >> "$mysql_conf"
            echo "wait_timeout = 600" >> "$mysql_conf"
            echo "interactive_timeout = 600" >> "$mysql_conf"
            echo "net_read_timeout = 30" >> "$mysql_conf"
            echo "net_write_timeout = 30" >> "$mysql_conf"
        fi
        print_success "Connection timeouts configured"
        
        changes_made=true
    fi
    
    echo -e "\n${BOLD}═══ DATABASE CLEANUP ═══${NC}"
    
    # Check if we can connect to MySQL
    if mysql -e "SELECT 1" &>/dev/null 2>&1; then
        print_success "Connected to $db_type"
        
        # === Check for anonymous users ===
        local anon_count=$(mysql -N -e "SELECT COUNT(*) FROM mysql.user WHERE User='';" 2>/dev/null)
        if [[ "$anon_count" -gt 0 ]]; then
            print_warning "Found $anon_count anonymous user(s)"
            if confirm_action "Remove anonymous users?"; then
                mysql -e "DELETE FROM mysql.user WHERE User='';"
                mysql -e "FLUSH PRIVILEGES;"
                print_success "Removed anonymous users"
            fi
        else
            print_success "No anonymous users found"
        fi
        
        # === Check for remote root ===
        local remote_root=$(mysql -N -e "SELECT COUNT(*) FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');" 2>/dev/null)
        if [[ "$remote_root" -gt 0 ]]; then
            print_warning "Found $remote_root remote root account(s)"
            if confirm_action "Remove remote root access?"; then
                mysql -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost', '127.0.0.1', '::1');"
                mysql -e "FLUSH PRIVILEGES;"
                print_success "Removed remote root access"
            fi
        else
            print_success "No remote root access found"
        fi
        
        # === Check for test database ===
        local test_db=$(mysql -N -e "SELECT COUNT(*) FROM information_schema.SCHEMATA WHERE SCHEMA_NAME='test';" 2>/dev/null)
        if [[ "$test_db" -gt 0 ]]; then
            print_warning "Test database exists"
            if confirm_action "Drop test database?"; then
                mysql -e "DROP DATABASE IF EXISTS test;"
                mysql -e "DELETE FROM mysql.db WHERE Db='test' OR Db='test\\_%';"
                mysql -e "FLUSH PRIVILEGES;"
                print_success "Dropped test database"
            fi
        else
            print_success "No test database found"
        fi
        
        # === Check for users with % host (obscure) ===
        echo -e "\n${BOLD}Checking for wildcard host users...${NC}"
        local wildcard_users=$(mysql -N -e "SELECT CONCAT(User,'@',Host) FROM mysql.user WHERE Host='%';" 2>/dev/null)
        if [[ -n "$wildcard_users" ]]; then
            print_warning "Found users with wildcard (%) host access:"
            echo "$wildcard_users" | while read user; do
                echo -e "  ${YELLOW}!${NC} $user"
            done
            print_info "Review these manually - they can connect from anywhere"
        else
            print_success "No wildcard host users found"
        fi
        
        # === Check for users with excessive privileges (obscure) ===
        echo -e "\n${BOLD}Checking for excessive privileges...${NC}"
        local priv_users=$(mysql -N -e "SELECT CONCAT(User,'@',Host) FROM mysql.user WHERE (Super_priv='Y' OR File_priv='Y' OR Process_priv='Y') AND User != 'root' AND User != 'mysql.sys' AND User != 'debian-sys-maint';" 2>/dev/null)
        if [[ -n "$priv_users" ]]; then
            print_warning "Found non-root users with elevated privileges:"
            echo "$priv_users" | while read user; do
                echo -e "  ${YELLOW}!${NC} $user"
            done
            print_info "Consider revoking SUPER, FILE, PROCESS privileges"
        else
            print_success "No excessive privileges found"
        fi
        
    else
        print_warning "Cannot connect to $db_type - skipping database cleanup"
        print_info "Run 'sudo mysql_secure_installation' manually"
    fi
    
    # Restart service
    echo -e "\n${BOLD}Restarting $db_type...${NC}"
    if [[ "$has_mysql" == true ]]; then
        systemctl restart mysql && print_success "MySQL restarted"
    elif [[ "$has_mariadb" == true ]]; then
        systemctl restart mariadb && print_success "MariaDB restarted"
    fi
    
    # === Suggest mysql_secure_installation ===
    echo -e "\n${BOLD}═══ MANUAL STEP ═══${NC}"
    print_warning "Recommended: Run 'sudo mysql_secure_installation' for additional hardening"
    if confirm_action "Run mysql_secure_installation now?"; then
        mysql_secure_installation
    fi
    
    # Summary
    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}"
    print_success "$db_type hardening complete"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    
    press_enter
}

#############################################
# Task 18: LAMP Stack - PHP Hardening
#############################################

harden_php() {
    print_header "PHP CONFIGURATION HARDENING"
    print_info "Comprehensive PHP security hardening for LAMP stack"
    echo ""
    
    # Find PHP installations
    local php_versions=()
    for dir in /etc/php/*/; do
        if [[ -d "$dir" ]]; then
            local ver=$(basename "$dir")
            php_versions+=("$ver")
        fi
    done
    
    if [[ ${#php_versions[@]} -eq 0 ]]; then
        print_warning "No PHP installations found in /etc/php/"
        press_enter
        return
    fi
    
    print_info "Found PHP version(s): ${php_versions[*]}"
    echo ""
    
    if ! confirm_action "Apply PHP security hardening?"; then
        print_info "Skipping PHP hardening"
        press_enter
        return
    fi
    
    local changes_made=false
    
    for ver in "${php_versions[@]}"; do
        echo -e "\n${BOLD}════════════════════════════════════════════════════════════${NC}"
        echo -e "${BOLD}Hardening PHP $ver${NC}"
        echo -e "${BOLD}════════════════════════════════════════════════════════════${NC}"
        
        # Find php.ini files for this version
        local php_ini_files=(
            "/etc/php/$ver/apache2/php.ini"
            "/etc/php/$ver/fpm/php.ini"
            "/etc/php/$ver/cli/php.ini"
        )
        
        for php_ini in "${php_ini_files[@]}"; do
            if [[ -f "$php_ini" ]]; then
                echo -e "\n${CYAN}Configuring: $php_ini${NC}"
                cp "$php_ini" "${php_ini}.bak.$(date +%Y%m%d_%H%M%S)"
                
                echo -e "\n${BOLD}═══ SAFE OPERATIONS (Auto-applying) ═══${NC}"
                
                # === SAFE: expose_php (hide version) ===
                sed -i 's/^expose_php.*/expose_php = Off/' "$php_ini"
                print_success "expose_php = Off (hide PHP version)"
                
                # === SAFE: display_errors (never show to users) ===
                sed -i 's/^display_errors.*/display_errors = Off/' "$php_ini"
                print_success "display_errors = Off"
                
                # === SAFE: display_startup_errors ===
                sed -i 's/^display_startup_errors.*/display_startup_errors = Off/' "$php_ini"
                print_success "display_startup_errors = Off"
                
                # === SAFE: log_errors ===
                sed -i 's/^log_errors.*/log_errors = On/' "$php_ini"
                print_success "log_errors = On"
                
                # === SAFE: html_errors ===
                sed -i 's/^html_errors.*/html_errors = Off/' "$php_ini"
                print_success "html_errors = Off"
                
                # === SAFE: error_log ===
                if ! grep -q "^error_log = /var/log/php" "$php_ini"; then
                    sed -i 's|^;error_log = syslog|error_log = /var/log/php_errors.log|' "$php_ini"
                fi
                print_success "error_log configured"
                
                # === SAFE: allow_url_include (RFI protection) ===
                sed -i 's/^allow_url_include.*/allow_url_include = Off/' "$php_ini"
                print_success "allow_url_include = Off (RFI protection)"
                
                # === SAFE: session security ===
                sed -i 's/^session.cookie_httponly.*/session.cookie_httponly = 1/' "$php_ini"
                sed -i 's/^;session.cookie_httponly.*/session.cookie_httponly = 1/' "$php_ini"
                print_success "session.cookie_httponly = 1"
                
                sed -i 's/^session.use_strict_mode.*/session.use_strict_mode = 1/' "$php_ini"
                sed -i 's/^;session.use_strict_mode.*/session.use_strict_mode = 1/' "$php_ini"
                print_success "session.use_strict_mode = 1 (session fixation protection)"
                
                sed -i 's/^session.use_only_cookies.*/session.use_only_cookies = 1/' "$php_ini"
                print_success "session.use_only_cookies = 1"
                
                # === SAFE: session.cookie_samesite (obscure - CSRF protection) ===
                if grep -q "^session.cookie_samesite" "$php_ini"; then
                    sed -i 's/^session.cookie_samesite.*/session.cookie_samesite = Lax/' "$php_ini"
                elif grep -q "^;session.cookie_samesite" "$php_ini"; then
                    sed -i 's/^;session.cookie_samesite.*/session.cookie_samesite = Lax/' "$php_ini"
                else
                    echo "session.cookie_samesite = Lax" >> "$php_ini"
                fi
                print_success "session.cookie_samesite = Lax (CSRF protection)"
                
                # === SAFE: cgi.fix_pathinfo (obscure - path traversal) ===
                sed -i 's/^cgi.fix_pathinfo.*/cgi.fix_pathinfo = 0/' "$php_ini"
                sed -i 's/^;cgi.fix_pathinfo.*/cgi.fix_pathinfo = 0/' "$php_ini"
                print_success "cgi.fix_pathinfo = 0 (path traversal protection)"
                
                # === SAFE: mail.add_x_header (obscure - info leak) ===
                sed -i 's/^mail.add_x_header.*/mail.add_x_header = Off/' "$php_ini"
                sed -i 's/^;mail.add_x_header.*/mail.add_x_header = Off/' "$php_ini"
                print_success "mail.add_x_header = Off (hide mail source)"
                
                # === SAFE: Resource limits ===
                sed -i 's/^max_execution_time.*/max_execution_time = 30/' "$php_ini"
                sed -i 's/^max_input_time.*/max_input_time = 60/' "$php_ini"
                sed -i 's/^memory_limit.*/memory_limit = 128M/' "$php_ini"
                sed -i 's/^upload_max_filesize.*/upload_max_filesize = 10M/' "$php_ini"
                sed -i 's/^post_max_size.*/post_max_size = 10M/' "$php_ini"
                sed -i 's/^max_input_vars.*/max_input_vars = 1000/' "$php_ini"
                print_success "Resource limits configured"
                
                # === SAFE: enable_dl (obscure) ===
                sed -i 's/^enable_dl.*/enable_dl = Off/' "$php_ini"
                sed -i 's/^;enable_dl.*/enable_dl = Off/' "$php_ini"
                print_success "enable_dl = Off (disable dynamic loading)"
                
                # === SAFE: assert.active (obscure - disable assert) ===
                if grep -q "^assert.active" "$php_ini"; then
                    sed -i 's/^assert.active.*/assert.active = 0/' "$php_ini"
                elif grep -q "^;assert.active" "$php_ini"; then
                    sed -i 's/^;assert.active.*/assert.active = 0/' "$php_ini"
                else
                    echo "assert.active = 0" >> "$php_ini"
                fi
                print_success "assert.active = 0"
                
                changes_made=true
            fi
        done
    done
    
    echo -e "\n${BOLD}═══ CAUTION OPERATIONS ═══${NC}"
    
    # === CAUTION: allow_url_fopen (breaks some plugins) ===
    print_warning "allow_url_fopen = Off would break plugins that fetch remote files"
    print_info "Skipping allow_url_fopen change (OrangeHRM may need it)"
    
    # === CAUTION: open_basedir (may break includes) ===
    print_warning "open_basedir restriction skipped (may break OrangeHRM)"
    
    # === CAUTION: disable_functions ===
    print_warning "disable_functions skipped (may break OrangeHRM functionality)"
    print_info "Manual review: Consider disabling: exec,passthru,shell_exec,system,proc_open,popen"
    
    # Restart Apache/PHP-FPM
    echo -e "\n${BOLD}Restarting services...${NC}"
    if systemctl is-active apache2 &>/dev/null; then
        systemctl restart apache2 && print_success "Apache restarted"
    fi
    for ver in "${php_versions[@]}"; do
        if systemctl is-active "php$ver-fpm" &>/dev/null 2>&1; then
            systemctl restart "php$ver-fpm" && print_success "PHP-FPM $ver restarted"
        fi
    done
    
    # Summary
    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}"
    print_success "PHP hardening complete"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    
    press_enter
}

#############################################
# Task 19: Kernel Debug & SysRq Hardening
#############################################

harden_kernel_debug() {
    print_header "KERNEL DEBUG & SYSRQ HARDENING"
    echo ""
    
    local sysctl_conf="/etc/sysctl.d/99-kernel-hardening.conf"
    local changes_made=false
    
    if ! confirm_action "Apply kernel debugging restrictions?"; then
        print_info "Skipping kernel hardening"
        press_enter
        return
    fi
    
    echo -e "\n${BOLD}═══ SAFE OPERATIONS (Auto-applying) ═══${NC}"
    
    # Create/update sysctl config
    cat > "$sysctl_conf" << 'EOF'
# CyberPatriot Kernel Hardening - Debug & SysRq Restrictions

# === CRITICAL: Disable Magic SysRq Key ===
kernel.sysrq = 0

# === Restrict Kernel Information Disclosure ===
# Restrict dmesg to root only
kernel.dmesg_restrict = 1

# Hide kernel pointers from all users
kernel.kptr_restrict = 2

# Reduce console message verbosity
kernel.printk = 3 3 3 3

# === Performance/Debug Restrictions ===
# Restrict perf_events (obscure - often missed)
kernel.perf_event_paranoid = 3

# Disable unprivileged BPF (obscure)
kernel.unprivileged_bpf_disabled = 1

# Harden BPF JIT (obscure)
net.core.bpf_jit_harden = 2

# Disable kexec (prevents kernel memory dumping)
kernel.kexec_load_disabled = 1

# Disable unprivileged user namespaces (container escape prevention)
kernel.unprivileged_userns_clone = 0

# Disable userfaultfd for unprivileged users (obscure)
vm.unprivileged_userfaultfd = 0

# Prevent TTY line discipline auto-loading (obscure)
dev.tty.ldisc_autoload = 0

# === Ptrace Restrictions ===
# Restrict ptrace (debugging)
kernel.yama.ptrace_scope = 1

# === Memory Protection ===
# Full ASLR
kernel.randomize_va_space = 2

# Null pointer dereference protection
vm.mmap_min_addr = 65536

# No core dumps for SUID
fs.suid_dumpable = 0

# === Symlink/Hardlink Protection ===
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_fifos = 2
fs.protected_regular = 2
EOF
    
    print_success "Created kernel hardening sysctl config"
    print_success "kernel.sysrq = 0 (DISABLED as requested)"
    print_success "kernel.dmesg_restrict = 1"
    print_success "kernel.kptr_restrict = 2"
    print_success "kernel.perf_event_paranoid = 3"
    print_success "kernel.unprivileged_bpf_disabled = 1"
    print_success "kernel.kexec_load_disabled = 1"
    print_success "net.core.bpf_jit_harden = 2"
    print_success "vm.unprivileged_userfaultfd = 0"
    print_success "dev.tty.ldisc_autoload = 0"
    
    # Apply sysctl settings
    echo -e "\n${BOLD}Applying kernel parameters...${NC}"
    sysctl -p "$sysctl_conf" 2>&1 | grep -v "^$" || true
    print_success "Kernel parameters applied"
    
    changes_made=true
    
    echo -e "\n${BOLD}═══ VERIFICATION ═══${NC}"
    
    # Verify SysRq is disabled
    local sysrq_val=$(cat /proc/sys/kernel/sysrq 2>/dev/null)
    if [[ "$sysrq_val" == "0" ]]; then
        echo -e "${GREEN}✓${NC} kernel.sysrq = 0 (DISABLED)"
    else
        echo -e "${YELLOW}!${NC} kernel.sysrq = $sysrq_val (should be 0, will apply on reboot)"
    fi
    
    local dmesg_val=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null)
    if [[ "$dmesg_val" == "1" ]]; then
        echo -e "${GREEN}✓${NC} kernel.dmesg_restrict = 1"
    else
        echo -e "${YELLOW}!${NC} kernel.dmesg_restrict = $dmesg_val"
    fi
    
    local kptr_val=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null)
    if [[ "$kptr_val" == "2" ]]; then
        echo -e "${GREEN}✓${NC} kernel.kptr_restrict = 2"
    else
        echo -e "${YELLOW}!${NC} kernel.kptr_restrict = $kptr_val"
    fi
    
    # Summary
    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}"
    print_success "Kernel debug hardening complete"
    print_warning "Some settings require reboot to fully apply"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    
    press_enter
}

#############################################
# Task 20: OrangeHRM Application Hardening
#############################################

harden_orangehrm() {
    print_header "ORANGEHRM APPLICATION HARDENING"
    print_info "Security hardening for OrangeHRM HRM system"
    echo ""
    
    # Find OrangeHRM installation
    local orangehrm_paths=(
        "/var/www/html/orangehrm"
        "/var/www/orangehrm"
        "/var/www/html"
    )
    
    local orangehrm_path=""
    for path in "${orangehrm_paths[@]}"; do
        if [[ -d "$path" ]] && [[ -f "$path/lib/confs/Conf.php" || -f "$path/symfony/config/databases.yml" ]]; then
            orangehrm_path="$path"
            break
        fi
    done
    
    if [[ -z "$orangehrm_path" ]]; then
        print_warning "OrangeHRM installation not found in standard locations"
        echo -e "${CYAN}Searched:${NC}"
        for path in "${orangehrm_paths[@]}"; do
            echo "  - $path"
        done
        
        echo -e -n "${CYAN}Enter OrangeHRM path (or 'skip'): ${NC}"
        read -r custom_path
        
        if [[ "$custom_path" == "skip" || -z "$custom_path" ]]; then
            print_info "Skipping OrangeHRM hardening"
            press_enter
            return
        fi
        
        orangehrm_path="$custom_path"
    fi
    
    print_success "Found OrangeHRM at: $orangehrm_path"
    echo ""
    
    if ! confirm_action "Apply OrangeHRM security hardening?"; then
        print_info "Skipping OrangeHRM hardening"
        press_enter
        return
    fi
    
    local changes_made=false
    
    echo -e "\n${BOLD}═══ SAFE OPERATIONS (Auto-applying) ═══${NC}"
    
    # === SAFE: Remove installer directory ===
    if [[ -d "$orangehrm_path/installer" ]]; then
        print_warning "Installer directory found - security risk!"
        if confirm_action "Remove installer directory?"; then
            rm -rf "$orangehrm_path/installer"
            print_success "Removed installer directory"
            changes_made=true
        fi
    else
        print_success "Installer directory already removed"
    fi
    
    # === SAFE: Remove info disclosure files ===
    local info_files=("CHANGELOG.txt" "README.txt" "LICENSE.txt" "INSTALL.txt" "UPGRADE.txt" "readme.md" "README.md")
    for file in "${info_files[@]}"; do
        if [[ -f "$orangehrm_path/$file" ]]; then
            rm -f "$orangehrm_path/$file"
            print_success "Removed $file (info disclosure)"
            changes_made=true
        fi
    done
    
    # === SAFE: Secure configuration files ===
    if [[ -f "$orangehrm_path/lib/confs/Conf.php" ]]; then
        chmod 640 "$orangehrm_path/lib/confs/Conf.php"
        chown www-data:www-data "$orangehrm_path/lib/confs/Conf.php"
        print_success "Secured Conf.php permissions (640)"
    fi
    
    if [[ -f "$orangehrm_path/symfony/config/databases.yml" ]]; then
        chmod 640 "$orangehrm_path/symfony/config/databases.yml"
        chown www-data:www-data "$orangehrm_path/symfony/config/databases.yml"
        print_success "Secured databases.yml permissions (640)"
    fi
    
    # === SAFE: Secure uploads directory ===
    if [[ -d "$orangehrm_path/uploads" ]]; then
        chmod 750 "$orangehrm_path/uploads"
        chown -R www-data:www-data "$orangehrm_path/uploads"
        print_success "Secured uploads directory (750)"
        
        # Prevent PHP execution in uploads
        cat > "$orangehrm_path/uploads/.htaccess" << 'EOF'
# Prevent PHP execution in uploads
php_flag engine off
<FilesMatch "\.php$">
    Require all denied
</FilesMatch>
EOF
        print_success "Disabled PHP execution in uploads directory"
        changes_made=true
    fi
    
    # === SAFE: Create .htaccess to protect sensitive directories ===
    local protect_dirs=("lib/confs" "symfony/config" "symfony/log" "symfony/cache")
    for dir in "${protect_dirs[@]}"; do
        if [[ -d "$orangehrm_path/$dir" ]]; then
            cat > "$orangehrm_path/$dir/.htaccess" << 'EOF'
# Deny all access to this directory
Require all denied
EOF
            print_success "Protected $dir from web access"
            changes_made=true
        fi
    done
    
    # === SAFE: Secure log directory ===
    if [[ -d "$orangehrm_path/symfony/log" ]]; then
        chmod 750 "$orangehrm_path/symfony/log"
        find "$orangehrm_path/symfony/log" -type f -exec chmod 640 {} \;
        print_success "Secured symfony/log directory"
    fi
    
    # === SAFE: Search for phpinfo files ===
    echo -e "\n${BOLD}Scanning for phpinfo() files...${NC}"
    local phpinfo_files=$(find "$orangehrm_path" -name "*phpinfo*" -o -name "*info.php*" 2>/dev/null)
    if [[ -n "$phpinfo_files" ]]; then
        print_warning "Found potential phpinfo files:"
        echo "$phpinfo_files" | while read file; do
            echo -e "  ${YELLOW}!${NC} $file"
        done
        if confirm_action "Remove phpinfo files?"; then
            echo "$phpinfo_files" | while read file; do
                rm -f "$file" && print_success "Removed $file"
            done
            changes_made=true
        fi
    else
        print_success "No phpinfo files found"
    fi
    
    # === SAFE: Search for backup files ===
    echo -e "\n${BOLD}Scanning for backup files in webroot...${NC}"
    local backup_files=$(find "$orangehrm_path" \( -name "*.bak" -o -name "*.old" -o -name "*.orig" -o -name "*~" -o -name "*.swp" -o -name "*.sql" \) 2>/dev/null | head -20)
    if [[ -n "$backup_files" ]]; then
        print_warning "Found backup/temp files (info disclosure risk):"
        echo "$backup_files" | while read file; do
            echo -e "  ${YELLOW}!${NC} $file"
        done
        if confirm_action "Remove backup files?"; then
            echo "$backup_files" | while read file; do
                rm -f "$file"
            done
            print_success "Removed backup files"
            changes_made=true
        fi
    else
        print_success "No backup files found"
    fi
    
    # === SAFE: Check for .git/.svn ===
    echo -e "\n${BOLD}Scanning for version control directories...${NC}"
    local vcs_dirs=$(find "$orangehrm_path" \( -name ".git" -o -name ".svn" -o -name ".hg" \) -type d 2>/dev/null)
    if [[ -n "$vcs_dirs" ]]; then
        print_warning "Found version control directories (security risk):"
        echo "$vcs_dirs" | while read dir; do
            echo -e "  ${YELLOW}!${NC} $dir"
        done
        if confirm_action "Remove version control directories?"; then
            echo "$vcs_dirs" | while read dir; do
                rm -rf "$dir"
            done
            print_success "Removed version control directories"
            changes_made=true
        fi
    else
        print_success "No version control directories found"
    fi
    
    # === SAFE: Check for .env files ===
    local env_files=$(find "$orangehrm_path" -name ".env*" 2>/dev/null)
    if [[ -n "$env_files" ]]; then
        print_warning "Found .env files:"
        echo "$env_files" | while read file; do
            echo -e "  ${YELLOW}!${NC} $file"
            chmod 600 "$file"
        done
        print_success "Secured .env file permissions (600)"
        changes_made=true
    fi
    
    echo -e "\n${BOLD}═══ MANUAL STEPS REQUIRED ═══${NC}"
    
    print_warning "The following must be done manually via OrangeHRM web interface:"
    echo -e "${CYAN}1.${NC} Change default admin password (Admin/admin or Admin/Admin123)"
    echo -e "${CYAN}2.${NC} Review and configure password policy in Admin > Configuration"
    echo -e "${CYAN}3.${NC} Enable account lockout after failed login attempts"
    echo -e "${CYAN}4.${NC} Review user accounts and permissions"
    echo -e "${CYAN}5.${NC} Disable debug mode if enabled in configuration"
    echo ""
    
    # === Check if Conf.php has debug enabled ===
    if [[ -f "$orangehrm_path/lib/confs/Conf.php" ]]; then
        if grep -q "DEBUG.*true\|debug.*true" "$orangehrm_path/lib/confs/Conf.php" 2>/dev/null; then
            print_warning "DEBUG may be enabled in Conf.php - review and disable"
        fi
    fi
    
    # Summary
    echo -e "\n${BOLD}═══════════════════════════════════════════════════════════${NC}"
    if [[ "$changes_made" == true ]]; then
        print_success "OrangeHRM hardening complete"
    else
        print_info "No changes made"
    fi
    print_warning "Remember to check default admin credentials!"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    
    press_enter
}

#############################################
# Task 21: LAMP Info Leak Audit
#############################################

lamp_info_leak_audit() {
    print_header "LAMP STACK INFORMATION DISCLOSURE AUDIT"
    print_info "Scanning for information leaks across Apache, MySQL, PHP"
    echo ""
    
    local issues_found=0
    
    echo -e "${BOLD}═══ APACHE INFORMATION LEAKS ═══${NC}"
    
    # Check /server-status
    echo -e "\n${CYAN}Checking /server-status accessibility...${NC}"
    if curl -s -o /dev/null -w "%{http_code}" http://localhost/server-status 2>/dev/null | grep -q "200\|403"; then
        local status_code=$(curl -s -o /dev/null -w "%{http_code}" http://localhost/server-status 2>/dev/null)
        if [[ "$status_code" == "200" ]]; then
            print_warning "/server-status is ACCESSIBLE (info leak!)"
            ((issues_found++))
        else
            print_success "/server-status is protected (403)"
        fi
    else
        print_success "/server-status not accessible"
    fi
    
    # Check /server-info
    echo -e "${CYAN}Checking /server-info accessibility...${NC}"
    if curl -s -o /dev/null -w "%{http_code}" http://localhost/server-info 2>/dev/null | grep -q "200"; then
        print_warning "/server-info is ACCESSIBLE (info leak!)"
        ((issues_found++))
    else
        print_success "/server-info not accessible"
    fi
    
    # Check Server header
    echo -e "${CYAN}Checking Server header...${NC}"
    local server_header=$(curl -sI http://localhost 2>/dev/null | grep -i "^Server:" | head -1)
    if [[ -n "$server_header" ]]; then
        if echo "$server_header" | grep -qi "Apache/[0-9]"; then
            print_warning "Server header reveals version: $server_header"
            ((issues_found++))
        else
            print_success "Server header minimized: $server_header"
        fi
    fi
    
    # Check X-Powered-By header
    echo -e "${CYAN}Checking X-Powered-By header...${NC}"
    local powered_header=$(curl -sI http://localhost 2>/dev/null | grep -i "^X-Powered-By:" | head -1)
    if [[ -n "$powered_header" ]]; then
        print_warning "X-Powered-By header present: $powered_header"
        ((issues_found++))
    else
        print_success "X-Powered-By header not present"
    fi
    
    echo -e "\n${BOLD}═══ PHP INFORMATION LEAKS ═══${NC}"
    
    # Search for phpinfo files
    echo -e "${CYAN}Searching for phpinfo files...${NC}"
    local phpinfo_count=$(find /var/www -name "*phpinfo*" -o -name "*info.php*" 2>/dev/null | wc -l)
    if [[ $phpinfo_count -gt 0 ]]; then
        print_warning "Found $phpinfo_count potential phpinfo file(s)"
        find /var/www -name "*phpinfo*" -o -name "*info.php*" 2>/dev/null | while read f; do
            echo -e "  ${YELLOW}!${NC} $f"
        done
        ((issues_found++))
    else
        print_success "No phpinfo files found"
    fi
    
    # Check PHP version in headers
    echo -e "${CYAN}Checking PHP version disclosure...${NC}"
    for php_ini in /etc/php/*/apache2/php.ini; do
        if [[ -f "$php_ini" ]]; then
            if grep -q "^expose_php = On" "$php_ini"; then
                print_warning "PHP version exposed in $php_ini"
                ((issues_found++))
            fi
        fi
    done
    
    echo -e "\n${BOLD}═══ FILE DISCLOSURE RISKS ═══${NC}"
    
    # Search for backup files
    echo -e "${CYAN}Searching for backup files in webroot...${NC}"
    local backup_count=$(find /var/www \( -name "*.bak" -o -name "*.old" -o -name "*.orig" -o -name "*~" -o -name "*.swp" -o -name "*.sql" \) 2>/dev/null | wc -l)
    if [[ $backup_count -gt 0 ]]; then
        print_warning "Found $backup_count backup/temp file(s)"
        find /var/www \( -name "*.bak" -o -name "*.old" -o -name "*.orig" -o -name "*~" -o -name "*.swp" -o -name "*.sql" \) 2>/dev/null | head -10 | while read f; do
            echo -e "  ${YELLOW}!${NC} $f"
        done
        ((issues_found++))
    else
        print_success "No backup files found in webroot"
    fi
    
    # Search for .git/.svn directories
    echo -e "${CYAN}Searching for version control directories...${NC}"
    local vcs_count=$(find /var/www \( -name ".git" -o -name ".svn" -o -name ".hg" \) -type d 2>/dev/null | wc -l)
    if [[ $vcs_count -gt 0 ]]; then
        print_warning "Found $vcs_count version control directory(ies)"
        find /var/www \( -name ".git" -o -name ".svn" -o -name ".hg" \) -type d 2>/dev/null | while read f; do
            echo -e "  ${YELLOW}!${NC} $f"
        done
        ((issues_found++))
    else
        print_success "No version control directories in webroot"
    fi
    
    # Search for .env files
    echo -e "${CYAN}Searching for .env files...${NC}"
    local env_count=$(find /var/www -name ".env*" 2>/dev/null | wc -l)
    if [[ $env_count -gt 0 ]]; then
        print_warning "Found $env_count .env file(s)"
        find /var/www -name ".env*" 2>/dev/null | while read f; do
            echo -e "  ${YELLOW}!${NC} $f"
        done
        ((issues_found++))
    else
        print_success "No .env files found"
    fi
    
    # Search for config files
    echo -e "${CYAN}Searching for exposed config files...${NC}"
    local config_files=$(find /var/www \( -name "config.php" -o -name "database.php" -o -name "settings.php" -o -name "wp-config.php" \) 2>/dev/null)
    if [[ -n "$config_files" ]]; then
        print_info "Found configuration files (verify not web-accessible):"
        echo "$config_files" | while read f; do
            echo -e "  ${BLUE}>${NC} $f"
        done
    fi
    
    echo -e "\n${BOLD}═══ MYSQL INFORMATION LEAKS ═══${NC}"
    
    # Check if MySQL is accessible without password
    echo -e "${CYAN}Checking MySQL anonymous access...${NC}"
    if mysql -u "" -e "SELECT 1" &>/dev/null 2>&1; then
        print_warning "MySQL allows anonymous access!"
        ((issues_found++))
    else
        print_success "MySQL requires authentication"
    fi
    
    echo -e "\n${BOLD}═══ AUDIT SUMMARY ═══${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    if [[ $issues_found -eq 0 ]]; then
        echo -e "${GREEN}✓${NC} No information disclosure issues found"
    else
        echo -e "${YELLOW}!${NC} Found $issues_found potential information disclosure issue(s)"
        echo ""
        print_info "Run these modules to fix:"
        echo -e "  - Option 16: Apache Hardening"
        echo -e "  - Option 18: PHP Hardening"
        echo -e "  - Option 20: OrangeHRM Hardening"
    fi
    
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    
    press_enter
}

#############################################
# Main Menu
#############################################

show_menu() {
    clear
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}       CYBERPATRIOT SECURITY HARDENING TOOL${NC}"
    echo -e "${BOLD}═══════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${GREEN}=== CORE SECURITY ===${NC}"
    echo -e "${GREEN} 1)${NC} User Auditing"
    echo -e "${GREEN} 2)${NC} Disable Root Login"
    echo -e "${GREEN} 3)${NC} Configure Firewall (UFW)"
    echo -e "${GREEN} 5)${NC} Audit Services"
    echo -e "${GREEN} 6)${NC} Verify Repositories (Package & Source Code)"
    echo -e "${GREEN} 7)${NC} Audit File Permissions"
    echo -e "${GREEN} 8)${NC} Update System"
    echo -e "${GREEN} 9)${NC} Remove Prohibited Software"
    echo ""
    echo -e "${CYAN}=== SERVICE HARDENING ===${NC}"
    echo -e "${GREEN}10)${NC} Harden SSH Configuration"
    echo -e "${GREEN}11)${NC} Harden FTP Server (vsftpd)"
    echo -e "${GREEN}12)${NC} Enable Security Features"
    echo -e "${GREEN}14)${NC} OS Settings (Screen Lock, Bluetooth, Updates, Kernel, Boot)"
    echo -e "${GREEN}15)${NC} Application Security (Apache, Nginx, MySQL, PostgreSQL)"
    echo ""
    echo -e "${YELLOW}=== LAMP STACK HARDENING ===${NC}"
    echo -e "${GREEN}16)${NC} Harden Apache (LAMP)"
    echo -e "${GREEN}17)${NC} Harden MySQL/MariaDB (LAMP)"
    echo -e "${GREEN}18)${NC} Harden PHP (LAMP)"
    echo -e "${GREEN}19)${NC} Kernel Debug & SysRq Disable"
    echo -e "${GREEN}20)${NC} Harden OrangeHRM"
    echo -e "${GREEN}21)${NC} LAMP Info Leak Audit"
    echo ""
    echo -e "${RED} 0)${NC} Exit"
    echo ""
    echo -e -n "${CYAN}Select an option: ${NC}"
}

#############################################
# Main Program Loop
#############################################

main() {
    check_root
    show_splash
    
    while true; do
        show_menu
        read -r choice
        
        case $choice in
            1) user_auditing ;;
            2) disable_root_login ;;
            3) configure_firewall ;;
            5) audit_services ;;
            6) verify_repositories ;;
            7) audit_file_permissions ;;
            8) update_system ;;
            9) remove_prohibited_software ;;
            10) harden_ssh ;;
            11) harden_ftp ;;
            12) enable_security_features ;;
            14) configure_os_settings ;;
            15) harden_application_security ;;
            16) harden_apache ;;
            17) harden_mysql ;;
            18) harden_php ;;
            19) harden_kernel_debug ;;
            20) harden_orangehrm ;;
            21) lamp_info_leak_audit ;;
            0)
                print_header "EXITING"
                print_info "Security audit log saved to: $LOG_FILE"
                echo -e "${GREEN}Thank you for using CyberPatriot Security Tool!${NC}"
                exit 0
                ;;
            *)
                print_error "Invalid option. Please try again."
                sleep 2
                ;;
        esac
    done
}

# Run the main program
main
