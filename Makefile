# SPDX-FileCopyrightText: © 2024 Matthew Rothlisberger
# SPDX-License-Identifier: GPL-3.0-only

install: release
	install target/release/bgain /usr/local/bin/

release: src/main.rs
	cargo build --release
