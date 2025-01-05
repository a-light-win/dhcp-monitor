#!/bin/sh

# Function to create dhcp-monitor user
create_user() {
  if id "dhcp-monitor" >/dev/null 2>&1; then
    echo "User dhcp-monitor already exists"
  else
    echo "Creating user dhcp-monitor"
    if [ -x "$(command -v useradd)" ]; then
      useradd --system --no-create-home --shell /usr/sbin/nologin dhcp-monitor
    else
      echo "Error: no useradd command found"
      exit 1
    fi
  fi
}

create_user
