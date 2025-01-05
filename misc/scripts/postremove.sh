#!/bin/sh

# Function to remove dhcp-monitor user and group
remove_user() {
  if id "dhcp-monitor" >/dev/null 2>&1; then
    echo "Removing user dhcp-monitor"
    userdel dhcp-monitor
  fi
}

remove_user
