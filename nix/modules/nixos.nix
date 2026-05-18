# NixOS entrypoint for the LDAP nix-hapi provider module.
#
# Currently a thin pass-through to ./common.nix; the per-platform layer
# exists so future deviations (e.g. systemd unit wiring, NixOS-specific
# package defaults) can land here without disturbing the macOS path.
{
  self,
  nixHapiLib,
}:
import ./common.nix {inherit self nixHapiLib;}
