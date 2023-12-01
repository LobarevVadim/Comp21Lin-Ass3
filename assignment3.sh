#!/bin/bash

# Lobarev Vadim
# 200530998
#Assignment3

# Configuring Target1-mgmt 

#Create script server1-config.sh

echo "Creating server1 configuration script..."
cat > ~/server1-config.sh << 'EOF'
#!/bin/bash

# Installing UFW and allow connections to port 514/udp (MGMT network)

echo "Checking and installing UFW if necessary..."
dpkg-query -s ufw &> /dev/null || apt-get -qq install ufw

ufw --force enable
echo "UFW enabled."

ufw allow from 172.16.1.0/24 to any port 514 proto udp &> /dev/null

if ufw status | grep -q "514/udp.*ALLOW.*172.16.1.0"; then
    echo "UFW Rule already exists"
else
    echo "Adding UFW Rule"
    ufw allow from 172.16.1.0/24 to any port 514 proto udp
fi

# Adding UFW rule for SSH port 22

ufw allow from 172.16.1.0/24 to any port 22 proto tcp &> /dev/null
ufw allow from 192.168.16.0/24 to any port 22 proto tcp &> /dev/null

echo "UFW Rule added: allow connections to 22/tcp from MGMT network and LAN"

# Configuring rsyslog for UDP connections

echo "Configuring rsyslog..."

if grep -q "imudp" /etc/rsyslog.conf; then
    echo "rsyslog is already listening for UDP connections"
else
    echo "Configuring rsyslog to listen for UDP connections..."
    
    sed -i '/imudp/s/#//g' /etc/rsyslog.conf && systemctl restart rsyslog

    if [ $? -eq 0 ]; then
        echo "Rsyslog configuration successful!"
    else
        echo "Failed to configure rsyslog."
        exit 1
    fi
fi

exit

# Change system name from target1 to loghost (both hostname and /etc/hosts file)

echo "Checking hostname..."

if [ "$(hostname)" = "loghost" ]; then
    echo "System name is already configured as 'loghost', skipping step"
else
    echo "Changing system name to 'loghost'..."
    
    hostnamectl set-hostname loghost && echo "System name was successfully changed to loghost." || { echo "Failed to change system name to loghost."; exit 1; }

    # Additional check in /etc/hostname
    grep -q "loghost" /etc/hostname && echo "Hostname file was updated successfully." || { echo "Failed to update /etc/hostname."; exit 1; }
fi


# Check if "loghost" exists inside /etc/hosts file and change server1 to loghost

echo "Checking for 'loghost' entry inside /etc/hosts file..."

grep -w "loghost" /etc/hosts > /dev/null 2>&1

if [ $? -eq 0 ]; then
    echo "Hostname already configured as 'loghost' within /etc/hosts file"
else
    echo "Changing hostname to 'loghost' within /etc/hosts file..."
    
    sed -i '0,/server1/ s/server1/loghost/' /etc/hosts && echo "Hostname was changed to 'loghost' within /etc/hosts!" || { echo "Failed to change hostname to 'loghost' in /etc/hosts."; exit 1; }

    grep -q "loghost" /etc/hosts && echo "Hosts file was updated successfully." || { echo "Failed to update /etc/hosts."; exit 1; }
fi




# Change IP Address from host 10 to 3

current_ip=$(hostname -I | awk '{ print $1 }')
lan_netip=$(hostname -I | awk '{ print $1 }' | sed "s/\.[^.]*$//")
yaml_file=$(find /etc/netplan -type f -name '*.yaml')

echo "Checking IP address: host 3 on LAN..."

if [ "$current_ip" = "$lan_netip.3" ]; then
    echo "IP Address correct: Server1 is already host 3 on the LAN."
else
    sed -i "/$lan_netip.10/s/$lan_netip.10/$lan_netip.3/" $yaml_file && echo "IP address configured to host 3 on LAN successfully." || { echo "Failed to change IP address to host 3 on LAN."; exit 1; }
    grep -q "$lan_netip.3" $yaml_file && echo "Configuration file updated successfully." || { echo "Failed to update configuration file."; exit 1; }
fi


# Check correct IP address of loghost

echo "Checking IP address of loghost in /etc/hosts..."

# Extract LAN network IP
netip=$(hostname -I | awk '{ print $1 }' | sed "s/\.[^.]*$//")

if [ "$(grep "loghost" /etc/hosts | awk '{ print $1 }')" = "$netip.3" ]; then
    echo "IP address of loghost is configured correctly within /etc/hosts!"
else
    echo "Configuring correct IP address for loghost in /etc/hosts..."
    
    # Update /etc/hosts with correct IP
    sed -i "/$netip.10 loghost/s/$netip.10/$netip.3/" /etc/hosts
    
    if [ "$(grep "loghost" /etc/hosts | awk '{ print $1 }')" = "$netip.3" ]; then
        echo "Correct IP address configured for loghost in /etc/hosts!"
    else
        echo "Failed to configure correct IP address for loghost in /etc/hosts."
        exit 1
    fi
fi

# Add a machine named webhost to the /etc/hosts file as host 4 on the LAN

echo "Checking if webhost exists within /etc/hosts..."

# Extract LAN network IP
netip=$(hostname -I | awk '{ print $1 }' | sed 's/.3$//')
hosts_file="/etc/hosts"

if grep -q "webhost" "$hosts_file"; then
    echo "webhost already exists within $hosts_file. Checking if IP address is configured correctly..."
    
    if grep -q "$netip.4" "$hosts_file"; then
        echo "IP address for webhost is already configured correctly."
    else
        sed -i "s/\(.*webhost\).*/$netip.4 webhost/" "$hosts_file"
        
        if grep -q "$netip.4 webhost" "$hosts_file"; then
            echo "webhost exists in $hosts_file."
        else
            echo "Failed to add correct webhost IP address to $hosts_file."
            exit 1
        fi
    fi
else
    echo "$netip.4 webhost" >> "$hosts_file"
    
    if grep -q "$netip.4 webhost" "$hosts_file"; then
        echo "webhost added to $hosts_file."
    else
        echo "Failed to add webhost to $hosts_file."
        exit 1
    fi
fi

EOF

#Copying server1-config.sh to server1

scp ~/server1-config.sh remoteadmin@server1-mgmt:/home/remoteadmin

if [ $? -eq 0 ]; then
    echo "Script copied successfully to server1!"
else
    echo "Failed to copy script to server1."
    exit 1
fi

# Configuring Target2-mgmt 

#Creating script server2-config.sh

echo "Creating server2 configuration script..."
cat > ~/server2-config.sh << 'EOF'
#!/bin/bash
# Changing system name from target 2 to webhost

if [ "$(hostname)" = "webhost" ]; then
    echo "System name is already configured as 'webhost', skipping step"
else
    echo "Changing system name to 'webhost'..."
    hostnamectl set-hostname webhost 
    grep "webhost" /etc/hostname > /dev/null
    if [ $? -eq 0 ]; then
        echo "System name was successfully changed to webhost."
    else
        echo "Failed to change system name to webhost."
        exit 1
    fi
fi

# Check if "webhost" exists inside /etc/hosts file and change server2 to webhost

echo "Checking for 'webhost' entry inside /etc/hosts file..."

if grep -w "webhost" /etc/hosts > /dev/null; then
    echo "Hostname already configured as 'webhost' within /etc/hosts file"
else
    echo "Changing hostname to 'webhost' within /etc/hosts file..."
    
    sed -i '0,/server2/ s/server2/webhost/' /etc/hosts && echo "Hostname was changed to 'webhost' within /etc/hosts!" || { echo "Failed to change hostname to 'webhost' in /etc/hosts."; exit 1; }

    grep -q "webhost" /etc/hosts && echo "Hosts file was updated successfully." || { echo "Failed to update /etc/hosts."; exit 1; }
fi

# Check and change IP address to host 4 on the LAN

current_ip=$(hostname -I | awk '{ print $1 }')
lan_net_ip=$(hostname -I | awk '{ print $1 }' | sed "s/\.[^.]*$//")
netplan_conf=$(find /etc/netplan -type f -name '*.yaml')

echo "Checking IP: if current is host 4 on LAN..."

if [ "$current_ip" = "$lan_net_ip.4" ]; then
    echo "IP correct: Server2 is already host 4 on the LAN."
else
    sed -i "/$lan_net_ip.11/s/$lan_net_ip.11/$lan_net_ip.4/" "$netplan_conf" && echo "IP set to host 4 on LAN successfully." || { echo "Failed to change IP to host 4 on LAN."; exit 1; }

    grep -q "$lan_net_ip.4" "$netplan_conf" && echo "Config file updated successfully." || { echo "Failed to update config file."; exit 1; }
fi

# Checking and setting correct IP address for webhost

echo "Checking IP address of webhost in /etc/hosts..."
if grep -wq "$lan_netip.4" /etc/hosts; then
    echo "IP address of webhost is correct in /etc/hosts!"
else
    echo "Configuring correct IP for webhost in /etc/hosts..."
    sed -i "s/$lan_netip.11 webhost/$lan_netip.4 webhost/" /etc/hosts
    
    if grep -wq "$lan_netip.4" /etc/hosts; then
        echo "Correct IP configured for webhost in /etc/hosts!"
    else
        echo "Failed to configure correct IP for webhost in /etc/hosts."
        exit 1
    fi
fi

# Add a machine named loghost to the /etc/hosts file as host 3 on the LAN

echo "Checking if loghost exists within /etc/hosts..."
if grep -q "loghost" /etc/hosts; then
    echo "loghost already exists in /etc/hosts. Checking if IP address is configured correctly..."
    grep -q "$lan_netip.3" /etc/hosts || sed -i "s/.*loghost/$lan_netip.3 loghost/" /etc/hosts

    grep -q "$lan_netip.3 loghost" /etc/hosts && echo "loghost exists in /etc/hosts." || { echo "Failed to add correct loghost IP address."; exit 1; }
else
    echo "$lan_netip.3 loghost" >> /etc/hosts

    grep -q "$lan_netip.3 loghost" /etc/hosts && echo "loghost added to /etc/hosts." || { echo "Failed to add loghost to /etc/hosts."; exit 1; }
fi

# Configuring rsyslog on webhost to send logs to loghost by modifying /etc/rsyslog.conf
# Add a line like this to the end of the rsyslog.conf file: *.* @loghost

if grep -q "\*.\* @loghost" /etc/rsyslog.conf; then
    echo "rsyslog is already configured to send logs to loghost!"
else
    echo "Configuring rsyslog to send logs to loghost..."
    echo "*.* @loghost:514" >> /etc/rsyslog.conf
    if grep -q "\*.\* @loghost:514" /etc/rsyslog.conf; then
        echo "Successfully configured rsyslog to send logs to loghost!"
        systemctl restart rsyslog
    else
        echo "Failed to configure rsyslog to send logs to loghost."
        exit 1
    fi
fi
exit
# Install UFW and allow connections to port 80/tcp from anywhere

if ! dpkg-query -s ufw > /dev/null 2>&1; then
    echo "Installing UFW..."
    apt update > /dev/null 2>&1
    apt install -y ufw > /dev/null 2>&1
else
    echo "UFW already installed."
fi

ufw_status=$(ufw status | awk '/Status:/ {print $2}')
if [ "$ufw_status" = "active" ]; then
    echo "UFW already enabled!"
else
    ufw --force enable
fi

if ufw status | grep -q "80/tcp.*ALLOW.*any"; then
    echo "UFW Rule already exists: allow connections to 80/tcp from anywhere"
else
    echo "Adding UFW Rule: allow connections to port 80/tcp from anywhere!"
    ufw allow 80/tcp
fi

# Adding UFW rule for SSH port 22 access from MGMT network

if ufw status | grep -q "22/tcp.*ALLOW.*172.16.1.0"; then
    echo "UFW Rule already exists"
else
    echo "Adding UFW Rule"
    ufw allow from 172.16.1.0/24 to any port 22 proto tcp
fi

# Installing Apache2

if ! dpkg-query -s apache2 > /dev/null 2>&1; then
    echo "Installing Apache2..."
    apt update
    echo "apt update completed."
    apt install -y apache2
    if [ $? -eq 0 ]; then
        echo "Apache2 was successfully installed!"
    else
        echo "Failed to install Apache2."
        exit 1
    fi
else
    echo "Apache2 already installed."
fi

EOF

#Copying server2-config.sh to server2

scp ~/server2-config.sh remoteadmin@server2-mgmt:/home/remoteadmin

if [ $? -eq 0 ]; then
    echo "Script copied successfully to server2!"
else
    echo "Failed to copy script to server2."
    exit 1
fi

# Runing Configuration Update Scripts on Target: Server1 and Server2

echo "Running server1 configuration script..."
ssh remoteadmin@server1-mgmt "bash /home/remoteadmin/server1-config.sh"

if [ $? -eq 0 ]; then
    echo "Completed Server1 configuration!"
    echo "--------------------------------"
else
    echo "Configuration of Server1 failed."
    exit 1
fi

echo "Running server2 configuration script..."
ssh remoteadmin@server2-mgmt "bash /home/remoteadmin/server2-config.sh"

if [ $? -eq 0 ]; then
    echo "Completed Server2 configuration!"
    echo "--------------------------------"
else
    echo "Configuration of Server2 failed."
    exit 1
fi

# Configuring NMS 

# Updating the NMS /etc/hosts file 
echo 'Configuring NMS'


echo "Updating NMS /etc/hosts file..."

update_host() {
    local name="$1"
    local old_ip="$2"
    local new_ip="$3"
    local new_name="$4"

    grep "$name" /etc/hosts | grep "$new_ip" > /dev/null
    if [ $? -eq 0 ]; then
        echo "$name already exists inside /etc/hosts file"
    else
        sudo sed -i "0,/$name/s/$old_ip/$new_ip/;0,/$name/s/$name/$new_name/" /etc/hosts
    fi
}

# Update hosts with new names and IPs
update_host "loghost" ".10" ".3" "loghost"
update_host "webhost" ".11" ".4" "webhost"

lines_hostfile=$(grep -E "loghost|webhost" /etc/hosts | wc -l)
if [ "$lines_hostfile" -eq "2" ]; then
    echo "/etc/hosts file was successfully updated!"
else
    echo "Failed to update /etc/hosts"
    exit 1
fi

#Verifying you can retrieve the default apache web page

if wget -q -O - http://webhost > /dev/null 2>&1; then
    echo "Successfully retrieved default Apache web page!"
else
    echo "Failed to retrieve the default Apache web page."
    exit 1
fi


#Verifying you can retrieve the logs
#Letting the user know that the configuration update has succeeded

webhost_in_log=$(ssh -o StrictHostKeyChecking=no remoteadmin@loghost "grep webhost /var/log/syslog")

if [ -n "$webhost_in_log" ]; then
    echo "Configuration update succeeded!"
else
    echo "Failed to update configuration. Could not find webhost in logs from loghost."
    exit 1
fi
