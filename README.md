# ONVIF Security Scanner

IoT pentesting tools for ONVIF-enabled devices

## Overview

This toolkit provides two main security testing tools for ONVIF devices:

- **onvifscan**: ONVIF device security scanner that tests for unauthenticated access vulnerabilities and performs credential brute-forcing
- **wsdiscovery**: WS-Discovery protocol scanner for discovering ONVIF devices on the network

## Usage

### wsdiscovery

```bash
# Multicast discovery
wsdiscovery 239.255.255.250

# Unicast discovery
wsdiscovery 192.168.1.100

# JSON output
wsdiscovery 239.255.255.250 --format json
```

### onvifscan

#### Authentication Testing

```bash
# Basic auth scan
onvifscan auth http://192.168.1.100

# Verbose output
onvifscan auth http://192.168.1.100 -v

# Test ALL endpoints including destructive operations
onvifscan auth http://192.168.1.100 -a

# JSON output
onvifscan auth http://192.168.1.100 --format json
```

#### Credential Brute-forcing

```bash
# Use built-in wordlists
onvifscan brute http://192.168.1.100

# Use custom wordlists
onvifscan brute http://192.168.1.100 --usernames users.txt --passwords passwords.txt
```

