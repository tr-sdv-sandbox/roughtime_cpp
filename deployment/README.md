# Roughtime Server Deployment Guide

This directory contains deployment configurations for running the Roughtime server in production.

## Systemd Service

### Installation Steps

1. **Create service user and group:**
```bash
sudo useradd -r -s /bin/false -d /var/lib/roughtime roughtime
sudo mkdir -p /var/lib/roughtime
sudo chown roughtime:roughtime /var/lib/roughtime
```

2. **Generate server key:**
```bash
# Generate root keypair (store securely!)
# The key will be generated automatically on first run, or you can pre-generate it
sudo -u roughtime touch /var/lib/roughtime/server-key.bin
sudo chmod 600 /var/lib/roughtime/server-key.bin
```

3. **Install the binary:**
```bash
sudo cp build/roughtime-server /usr/local/bin/
sudo chmod 755 /usr/local/bin/roughtime-server
```

4. **Install systemd service file:**
```bash
sudo cp deployment/roughtime-server.service /etc/systemd/system/
sudo systemd reload-daemon
```

5. **Enable and start the service:**
```bash
sudo systemctl enable roughtime-server
sudo systemctl start roughtime-server
```

### Service Management

**Check status:**
```bash
sudo systemctl status roughtime-server
```

**View logs:**
```bash
sudo journalctl -u roughtime-server -f
```

**Restart service:**
```bash
sudo systemctl restart roughtime-server
```

**Stop service:**
```bash
sudo systemctl stop roughtime-server
```

### Configuration

The service file uses these default settings:
- **Address**: 0.0.0.0 (all interfaces)
- **Port**: 2002 (standard Roughtime port)
- **Radius**: 1 second
- **Certificate Validity**: 72 hours

To customize these settings, edit `/etc/systemd/system/roughtime-server.service` and modify the `ExecStart` line.

### Security Hardening

The service file includes extensive security hardening:
- Runs as unprivileged user `roughtime`
- Private /tmp directory
- Read-only filesystem (except /var/lib/roughtime)
- Protected home directories
- Restricted system calls and address families
- Resource limits to prevent DoS

### Firewall Configuration

Allow incoming UDP traffic on port 2002:

**iptables:**
```bash
sudo iptables -A INPUT -p udp --dport 2002 -j ACCEPT
```

**firewalld:**
```bash
sudo firewall-cmd --permanent --add-port=2002/udp
sudo firewall-cmd --reload
```

**ufw:**
```bash
sudo ufw allow 2002/udp
```

### Monitoring

Monitor the server using:
```bash
# Check if service is running
systemctl is-active roughtime-server

# View recent logs
journalctl -u roughtime-server --since "10 minutes ago"

# Monitor resource usage
systemctl status roughtime-server
```

### Troubleshooting

**Service fails to start:**
1. Check logs: `journalctl -u roughtime-server -n 50`
2. Verify permissions on /var/lib/roughtime
3. Ensure port 2002 is not already in use: `sudo ss -ulnp | grep 2002`
4. Check that the binary has execute permissions

**Permission denied errors:**
```bash
sudo chown -R roughtime:roughtime /var/lib/roughtime
sudo chmod 700 /var/lib/roughtime
```

**Rate limiting issues:**
- Rate limiting is enabled by default (100 requests per 10 seconds per IP)
- Adjust in server code or disable by modifying the configuration

## Production Recommendations

1. **Use a dedicated server** or VM for the Roughtime server
2. **Enable automatic updates** for security patches
3. **Monitor server logs** regularly for anomalies
4. **Set up log rotation** to prevent disk space issues
5. **Back up the server key** securely
6. **Use TLS/HTTPS** for management interfaces (if any)
7. **Enable SELinux/AppArmor** for additional security
8. **Configure monitoring** (Prometheus, Nagios, etc.)
9. **Set up alerting** for service failures
10. **Document your deployment** including key locations and configurations
