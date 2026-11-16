{ lib, rustPlatform }:

rustPlatform.buildRustPackage {
  pname = "airgrill";
  version = "0.1.0";

  src = lib.cleanSourceWith {
    src = ./.;
    filter =
      path: _type:
      let
        base = baseNameOf path;
      in
      !(base == "target" || base == ".git" || base == "result" || base == "result-static");
  };

  cargoLock.lockFile = ./Cargo.lock;
  doCheck = true;

  meta = {
    description = "Domain-routed proxy client with DPI evasion and LAN router mode";
    license = lib.licenses.mit;
    mainProgram = "airgrill";
  };
}
