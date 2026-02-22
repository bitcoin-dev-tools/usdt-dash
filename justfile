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

# Build and activate the new configuration on remote server
[group('build')]
switch:
    nixos-rebuild switch --flake .#{{flake_config}} --target-host {{user}}@{{host}} --use-remote-sudo

# Build and test the new configuration on remote server (no boot default)
[group('build')]
test:
    nixos-rebuild test --flake .#{{flake_config}} --target-host {{user}}@{{host}} --use-remote-sudo

# Build and activate, but don't add boot entry
[group('build')]
boot:
    nixos-rebuild boot --flake .#{{flake_config}} --target-host {{user}}@{{host}} --use-remote-sudo

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

# SSH into the server
[group('admin')]
ssh:
    ssh {{user}}@{{host}}

