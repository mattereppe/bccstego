# Short name for build target
PYTHON_TARGET := ipstats

SED ?= sed
CHMOD ?= chmod

# Executable
PYTHON_OBJ := ${PYTHON_TARGET:=.py}

# Templates to build the target
BPF_TEMPLATE := bpfprog.c
USR_TEMPLATE := userprog.py

# Directory structure
SRC_DIR := src
BPF_TEMPLATE := $(SRC_DIR)/$(BPF_TEMPLATE)
USR_TEMPLATE := $(SRC_DIR)/$(USR_TEMPLATE)

all: $(PYTHON_TARGET)

.PHONY: clean 


clean:
	rm -f $(PYTHON_OBJ)
	rm -f *~

$(PYTHON_TARGET): $(BPF_TEMPLATE) $(USR_TEMPLATE)
	$(SED) -e '/BPFPROG_SRC_CODE/ {' -e 'r $(BPF_TEMPLATE)' -e 'd' -e '}' $(USR_TEMPLATE) > $(PYTHON_OBJ)
	$(CHMOD) a+x $(PYTHON_OBJ)
