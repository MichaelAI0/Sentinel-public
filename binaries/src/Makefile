# SENTINEL Test Binary Build System
# 
# Creates a comprehensive suite of test binaries for E2E testing.
# All binaries are SAFE and contain patterns that trigger detection
# without performing any actual malicious actions.
#
# Usage:
#   make all      - Build all test binaries (basic + stripped)
#   make basic    - Build basic (unmodified) binaries
#   make packed   - Build UPX-packed versions (requires upx-ucl)
#   make stripped - Build stripped (no debug symbols) versions
#   make clean    - Remove all built binaries
#   make help     - Show this help
#
# UPX Installation (for packed binaries):
#   Ubuntu/Debian: sudo apt-get install upx-ucl
#   Arch Linux:    sudo pacman -S upx
#   macOS:         brew install upx
#   Docker:        apt-get install -y upx-ucl
#
# UPX 4.2.2+ is recommended for best compatibility.

CC = gcc
CFLAGS = -Wall -Wextra -O2
CFLAGS_32 = $(CFLAGS) -m32
CFLAGS_DEBUG = -Wall -Wextra -g -O0
UPX = upx

# Output directories
OUT_DIR = ..
PACKED_DIR = ../packed
STRIPPED_DIR = ../stripped

# Source files - Original + 2025 Modern Patterns
SOURCES = suspicious_test.c ransomware_sim.c keylogger_sim.c \
          trojan_sim.c cryptominer_sim.c rat_sim.c \
          infostealer_sim.c loader_sim.c apt_sim.c rootkit_sim.c

# Benign test files (for false positive testing)
BENIGN_SOURCES = benign_hello.c benign_calculator.c benign_fileops.c \
                 benign_network.c benign_crypto.c

# All sources combined
ALL_SOURCES = $(SOURCES) $(BENIGN_SOURCES)

# Default target (basic + stripped, packed is optional)
.PHONY: all
all: directories basic stripped
	@echo ""
	@echo "✅ Test binaries built successfully!"
	@echo "   Basic:    $(OUT_DIR)/"
	@echo "   Stripped: $(STRIPPED_DIR)/"
	@echo ""
	@echo "💡 Run 'make packed' for UPX-packed versions (requires upx-ucl)"
	@echo ""

# Full build including packed (for CI with UPX installed)
.PHONY: full
full: directories basic packed stripped
	@echo ""
	@echo "✅ All test binaries built (including packed)!"
	@echo ""

.PHONY: directories
directories:
	@mkdir -p $(OUT_DIR)
	@mkdir -p $(PACKED_DIR)
	@mkdir -p $(STRIPPED_DIR)

# Basic unmodified binaries
.PHONY: basic
basic: $(OUT_DIR)/suspicious_test $(OUT_DIR)/ransomware_sim \
       $(OUT_DIR)/keylogger_sim $(OUT_DIR)/trojan_sim \
       $(OUT_DIR)/cryptominer_sim $(OUT_DIR)/rat_sim \
       $(OUT_DIR)/infostealer_sim $(OUT_DIR)/loader_sim \
       $(OUT_DIR)/apt_sim $(OUT_DIR)/rootkit_sim \
       $(OUT_DIR)/benign_hello $(OUT_DIR)/benign_calculator \
       $(OUT_DIR)/benign_fileops $(OUT_DIR)/benign_network \
       $(OUT_DIR)/benign_crypto

$(OUT_DIR)/suspicious_test: suspicious_test.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built: $@"

$(OUT_DIR)/ransomware_sim: ransomware_sim.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built: $@"

$(OUT_DIR)/keylogger_sim: keylogger_sim.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built: $@"

$(OUT_DIR)/trojan_sim: trojan_sim.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built: $@"

$(OUT_DIR)/cryptominer_sim: cryptominer_sim.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built: $@"

$(OUT_DIR)/rat_sim: rat_sim.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built: $@"

$(OUT_DIR)/infostealer_sim: infostealer_sim.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built: $@"

$(OUT_DIR)/loader_sim: loader_sim.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built: $@"

$(OUT_DIR)/apt_sim: apt_sim.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built: $@"

$(OUT_DIR)/rootkit_sim: rootkit_sim.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built: $@"

# Benign test binaries (for false positive testing)
$(OUT_DIR)/benign_hello: benign_hello.c
	$(CC) $(CFLAGS) -o $@ $< -lm
	@echo "Built: $@"

$(OUT_DIR)/benign_calculator: benign_calculator.c
	$(CC) $(CFLAGS) -o $@ $< -lm
	@echo "Built: $@"

$(OUT_DIR)/benign_fileops: benign_fileops.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built: $@"

$(OUT_DIR)/benign_network: benign_network.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built: $@"

$(OUT_DIR)/benign_crypto: benign_crypto.c
	$(CC) $(CFLAGS) -o $@ $<
	@echo "Built: $@"

# Packed binaries (UPX) - optional, requires upx-ucl 4.2.2+
.PHONY: packed
packed: basic directories
	@if command -v $(UPX) >/dev/null 2>&1; then \
		echo "Using UPX: $$($(UPX) --version | head -1)"; \
		for bin in $(OUT_DIR)/suspicious_test $(OUT_DIR)/ransomware_sim \
		           $(OUT_DIR)/keylogger_sim $(OUT_DIR)/trojan_sim \
		           $(OUT_DIR)/cryptominer_sim $(OUT_DIR)/rat_sim \
		           $(OUT_DIR)/infostealer_sim $(OUT_DIR)/loader_sim \
		           $(OUT_DIR)/apt_sim $(OUT_DIR)/rootkit_sim \
		           $(OUT_DIR)/benign_hello $(OUT_DIR)/benign_calculator \
		           $(OUT_DIR)/benign_fileops $(OUT_DIR)/benign_network \
		           $(OUT_DIR)/benign_crypto; do \
			$(UPX) --best -o $(PACKED_DIR)/$$(basename $$bin)_packed $$bin 2>/dev/null || true; \
			echo "Packed: $(PACKED_DIR)/$$(basename $$bin)_packed"; \
		done; \
	else \
		echo ""; \
		echo "⚠️  UPX not found. Install to create packed binaries:"; \
		echo "   Ubuntu/Debian: sudo apt-get install upx-ucl"; \
		echo "   Arch Linux:    sudo pacman -S upx"; \
		echo "   macOS:         brew install upx"; \
		echo ""; \
		exit 1; \
	fi

# Stripped binaries (no symbols)
.PHONY: stripped
stripped: basic
	@for bin in $(OUT_DIR)/suspicious_test $(OUT_DIR)/ransomware_sim \
	           $(OUT_DIR)/keylogger_sim $(OUT_DIR)/trojan_sim \
	           $(OUT_DIR)/cryptominer_sim $(OUT_DIR)/rat_sim \
	           $(OUT_DIR)/infostealer_sim $(OUT_DIR)/loader_sim \
	           $(OUT_DIR)/apt_sim $(OUT_DIR)/rootkit_sim \
	           $(OUT_DIR)/benign_hello $(OUT_DIR)/benign_calculator \
	           $(OUT_DIR)/benign_fileops $(OUT_DIR)/benign_network \
	           $(OUT_DIR)/benign_crypto; do \
		cp $$bin $(STRIPPED_DIR)/$$(basename $$bin)_stripped; \
		strip $(STRIPPED_DIR)/$$(basename $$bin)_stripped; \
		echo "Stripped: $(STRIPPED_DIR)/$$(basename $$bin)_stripped"; \
	done

# Clean all built files
.PHONY: clean
clean:
	rm -f $(OUT_DIR)/suspicious_test $(OUT_DIR)/ransomware_sim
	rm -f $(OUT_DIR)/keylogger_sim $(OUT_DIR)/trojan_sim
	rm -f $(OUT_DIR)/cryptominer_sim $(OUT_DIR)/rat_sim
	rm -f $(OUT_DIR)/infostealer_sim $(OUT_DIR)/loader_sim
	rm -f $(OUT_DIR)/apt_sim $(OUT_DIR)/rootkit_sim
	rm -f $(OUT_DIR)/benign_hello $(OUT_DIR)/benign_calculator
	rm -f $(OUT_DIR)/benign_fileops $(OUT_DIR)/benign_network
	rm -f $(OUT_DIR)/benign_crypto
	rm -rf $(PACKED_DIR) $(STRIPPED_DIR)
	@echo "Cleaned all test binaries"

# Help target
.PHONY: help
help:
	@echo "SENTINEL Test Binary Build System"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build all test binaries (basic, packed, stripped)"
	@echo "  basic     - Build basic unmodified binaries"
	@echo "  packed    - Build UPX-packed versions"
	@echo "  stripped  - Build symbol-stripped versions"
	@echo "  clean     - Remove all built binaries"
	@echo "  help      - Show this help"
	@echo ""
	@echo "Original Test Binaries:"
	@echo "  suspicious_test  - General suspicious patterns"
	@echo "  ransomware_sim   - Ransomware behavior patterns"
	@echo "  keylogger_sim    - Keylogger patterns"
	@echo "  trojan_sim       - Trojan/backdoor patterns"
	@echo "  cryptominer_sim  - Cryptocurrency miner patterns"
	@echo "  rat_sim          - Remote Access Trojan patterns"
	@echo ""
	@echo "2025 Modern Threat Binaries:"
	@echo "  infostealer_sim  - Lumma/RedLine/Raccoon stealer patterns"
	@echo "  loader_sim       - Emotet/QakBot/Pikabot loader patterns"
	@echo "  apt_sim          - APT/Nation-state threat patterns"
	@echo "  rootkit_sim      - Rootkit/Bootkit/UEFI threat patterns"
