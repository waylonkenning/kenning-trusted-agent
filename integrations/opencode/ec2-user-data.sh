#!/usr/bin/env bash
set -euo pipefail

exec > >(tee -a /var/log/kenning-opencode-bootstrap.log | logger -t kenning-opencode-bootstrap -s 2>/dev/console) 2>&1

dnf install -y git jq unzip tar gzip awscli-2

# Install OpenCode for the unprivileged development user using the official
# installer. The launcher later resolves either supported install location.
runuser -u ec2-user -- env HOME=/home/ec2-user bash -lc 'curl -fsSL https://opencode.ai/install | bash'

for candidate in /home/ec2-user/.opencode/bin/opencode /home/ec2-user/.local/bin/opencode; do
  if [ -x "$candidate" ]; then
    ln -sf "$candidate" /usr/local/bin/opencode
    break
  fi
done

command -v opencode >/dev/null
install -d -o ec2-user -g ec2-user -m 0700 /home/ec2-user/.config
install -d -o ec2-user -g ec2-user -m 0700 /home/ec2-user/.config/kenning
install -d -o ec2-user -g ec2-user -m 0755 /home/ec2-user/workspace
install -d -o root -g root -m 0755 /workspace
install -d -o root -g root -m 0755 /var/lib/kenning-opencode
touch /var/lib/kenning-opencode/bootstrap-complete
