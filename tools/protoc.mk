HOST_OS := $(shell uname -s)
protoc_version = 3.6.1
ifeq ($(HOST_OS), Darwin)
protoc_suffix = osx
else
ifeq ($(HOST_OS), Linux)
protoc_suffix = linux
else
$(error Unsupported Host OS)
endif
endif
remote_protoc_zip = https://github.com/protocolbuffers/protobuf/releases/download/v$(protoc_version)/protoc-$(protoc_version)-$(protoc_suffix)-x86_64.zip
echo $(remote_protoc_zip)
local_protoc_zip = $(TOOL_TEMP_DIR)/$(notdir $(remote_protoc_zip))
$(local_protoc_zip): $(TOOL_TEMP_DIR)
	@curl -sL $(remote_protoc_zip) -o $(local_protoc_zip)
PROTOC := $(TOOL_BIN_DIR)/protoc
$(PROTOC): $(local_protoc_zip) $(TOOL_BIN_DIR)
	@unzip -oXq $(local_protoc_zip) -d $(dir $(TOOL_BIN_DIR))
PROTOC_INCLUDE_DIR := $(TOOL_DIR)/include
