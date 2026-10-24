FROM alpine:3.20

# Install OpenSSH server safely
RUN apk add --no-cache openssh-server

# 1. Configure SSH to listen on ports 22 and 2222
# 2. Force password authentication on, explicitly allowing it
RUN mkdir -p /var/run/sshd && \
    echo -e "Port 22\nPort 2222\nPasswordAuthentication yes\nPermitRootLogin no" > /etc/ssh/sshd_config

# Create 'testuser' with password 'password123' using a secure alpine shell
RUN adduser -D -s /bin/sh testuser && \
    echo 'testuser:password123' | chpasswd

# Expose both ports to the runtime environment
EXPOSE 22 2222

# Generate host keys on startup and execute sshd in the foreground
CMD ["/bin/sh", "-c", "ssh-keygen -A && exec /usr/sbin/sshd -D"]
