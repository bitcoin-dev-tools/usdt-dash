set shell := ["bash", "-uc"]
os := os()
host := "CX22-demo"
user := "root"
flake_config := "default"

[private]
default:
    just --list

# Initial deployment with nixos-anywhere (WARNING: DESTRUCTIVE!)
[group('deploy')]
[confirm("This will wipe the target system. Are you sure?")]
deploy:
    nix-shell -p nixos-anywhere --run "nixos-anywhere --flake .#{{flake_config}} {{user}}@{{host}} --generate-hardware-config nixos-generate-config ./hardware-configuration.nix"

# Deploy with existing hardware-configuration.nix
[group('deploy')]
[confirm("This will wipe the target system. Are you sure?")]
deploy-no-hardware-gen:
    nix-shell -p nixos-anywhere --run "nixos-anywhere --flake .#{{flake_config}} {{user}}@{{host}}"

# Build the configuration locally (test build)
[group('build')]
build:
    nixos-rebuild build --flake .#{{flake_config}} --show-trace

remote_dir := "/etc/nixos-config"

# Sync config and switch on remote
[group('build')]
switch: sync
    ssh {{user}}@{{host}} 'nixos-rebuild switch --flake {{remote_dir}}#{{flake_config}}'

# Sync config and test on remote (no boot default)
[group('build')]
test: sync
    ssh {{user}}@{{host}} 'nixos-rebuild test --flake {{remote_dir}}#{{flake_config}}'

# Sync config and set as boot default on remote
[group('build')]
boot: sync
    ssh {{user}}@{{host}} 'nixos-rebuild boot --flake {{remote_dir}}#{{flake_config}}'

# Rsync config to remote
[group('build')]
sync:
    rsync -avz --exclude-from=.gitignore --exclude=.git -e ssh . {{user}}@{{host}}:{{remote_dir}}/
    ssh {{user}}@{{host}} 'chown -R root:root {{remote_dir}}'

# Show what would change without build
[group('test')]
dry-run:
    nixos-rebuild dry-run --flake .#{{flake_config}}

# Show what would change on remote without building
[group('test')]
dry-run-remote:
    nixos-rebuild dry-activate --flake .#{{flake_config}} --target-host {{user}}@{{host}}

# Update flake inputs
[group('maintenance')]
update:
    nix flake update

# Check flake for errors
[group('check')]
check:
    nix flake check --no-build

# Generate age key on server and print public key for .sops.yaml
[group('admin')]
generate-sops:
    ssh {{user}}@{{host}} 'mkdir -p /root/.config/sops/age && age-keygen -o /root/.config/sops/age/keys.txt 2>&1 | tee /dev/stderr | grep "public key" | cut -d: -f2 | tr -d " "'

# SSH into the server
[group('admin')]
ssh:
    ssh {{user}}@{{host}}

