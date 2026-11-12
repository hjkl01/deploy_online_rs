# deploy_online — 前后端打进单一二进制
#
#   make build     编译 release，产物: dist/deploy_online
#   make run       构建并启动（需已设置 SECRET_KEY / ADMIN_PASSWORD）
#   make clean     清理构建产物

CARGO       ?= cargo
TARGET      ?= release
BIN_NAME    := deploy_online
DIST_DIR    := dist
STATIC_DIR  := static

# release 产物路径
ifeq ($(TARGET),release)
  CARGO_FLAGS := --release
  CARGO_OUT   := target/release/$(BIN_NAME)
else
  CARGO_FLAGS :=
  CARGO_OUT   := target/debug/$(BIN_NAME)
endif

.PHONY: help build build-debug check frontend ensure-static clean run install

help:
	@echo "常用目标:"
	@echo "  make build        将 static/ 前端嵌入后端，编译 release 单二进制 → $(DIST_DIR)/$(BIN_NAME)"
	@echo "  make build-debug  debug 构建"
	@echo "  make check        cargo check（不链接）"
	@echo "  make run          构建后启动（127.0.0.1:8000）"
	@echo "  make install      安装到 \$$HOME/.local/bin"
	@echo "  make clean        删除 target/ 与 dist/"
	@echo ""
	@echo "说明: 前端来自 $(STATIC_DIR)/，由 rust-embed 在编译期打进二进制。"

# 确保有可嵌入的前端页面
ensure-static:
	@test -f $(STATIC_DIR)/index.html || { \
	  echo "错误: 缺少 $(STATIC_DIR)/index.html"; \
	  exit 1; \
	}
	@echo "前端资源: $$(find $(STATIC_DIR) -type f | wc -l) 个文件（将嵌入二进制）"

# 默认：release 单文件
build: ensure-static
	@echo ">>> cargo build $(CARGO_FLAGS)"
	$(CARGO) build $(CARGO_FLAGS)
	@mkdir -p $(DIST_DIR)
	@cp -f $(CARGO_OUT) $(DIST_DIR)/$(BIN_NAME)
	@chmod +x $(DIST_DIR)/$(BIN_NAME)
	@echo ""
	@echo "完成: $(DIST_DIR)/$(BIN_NAME) ($$(du -h $(DIST_DIR)/$(BIN_NAME) | cut -f1))"
	@echo "运行: SECRET_KEY=... ADMIN_PASSWORD=... ./$(DIST_DIR)/$(BIN_NAME) --bind 127.0.0.1:8000"

build-debug:
	@$(MAKE) build TARGET=debug

check: ensure-static
	$(CARGO) check $(CARGO_FLAGS)

# 若以后有独立前端构建步骤，可在此扩展（当前 static/ 已是成品）
frontend: ensure-static
	@echo "当前使用内置 SPA: $(STATIC_DIR)/index.html（无需 npm build）"

run: build
	@test -n "$$SECRET_KEY" || { echo "请设置 SECRET_KEY"; exit 1; }
	@test -n "$$ADMIN_PASSWORD" || { echo "请设置 ADMIN_PASSWORD"; exit 1; }
	./$(DIST_DIR)/$(BIN_NAME) --bind 127.0.0.1:8000

install: build
	@mkdir -p "$$HOME/.local/bin"
	@cp -f $(DIST_DIR)/$(BIN_NAME) "$$HOME/.local/bin/$(BIN_NAME)"
	@echo "已安装: $$HOME/.local/bin/$(BIN_NAME)"

clean:
	$(CARGO) clean
	rm -rf $(DIST_DIR)
