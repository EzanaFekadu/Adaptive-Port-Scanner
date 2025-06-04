# Usage Instructions for Red Team Port Scanner

## Overview

This document explains how to configure and run the Red Team Port Scanner.

## Configuration File

Create or customize the `targets_config.json` file to specify targets, TCP/UDP ports, and optional timeouts for each host. Example:

```json
{
    "targets": [
        {
            "ip": "192.168.1.100",
            "tcp_ports": [22, 80, 443],
            "udp_ports": [53, 123],
            "timeout": 2.0
        }
    ]
}