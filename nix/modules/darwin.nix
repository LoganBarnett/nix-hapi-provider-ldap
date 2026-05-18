# nix-darwin entrypoint for the LDAP nix-hapi provider module.
#
# Currently a thin pass-through to ./common.nix; the per-platform layer
# exists so future deviations (e.g. launchd integration, Darwin-specific
# package defaults) can land here without disturbing the NixOS path.
{
  self,
  nixHapiLib,
}:
import ./common.nix {inherit self nixHapiLib;}
