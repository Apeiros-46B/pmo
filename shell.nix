{ pkgs ? import <nixpkgs> {} }:

pkgs.mkShell {
	packages = with pkgs; [
		just
		cargo
		rustc
		rust-analyzer
		sqlx-cli
	];
}
