# SPDX-FileCopyrightText: © 2024 Matthew Rothlisberger
# SPDX-License-Identifier: GPL-3.0-only

service: bgain.service
	install -D -t ${HOME}/.config/systemd/user/ bgain.service

install-root: target/release/bgain
	install target/release/bgain /usr/local/bin/

install: target/release/bgain
	install -D -t ${HOME}/.local/bin/ target/release/bgain

target/release/bgain: src/main.rs
	cargo build --release
