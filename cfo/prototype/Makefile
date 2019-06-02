P4C = p4c-bm2-ss
P4C_ARGS = --p4runtime-files $(basename $@).p4.p4info.txt --p4runtime-format text

BUILD_DIR = build
PCAP_DIR = pcaps
LOG_DIR = logs

source := $(wildcard *.p4)
outfile := $(source:.p4=.json)
compiled_json := $(BUILD_DIR)/$(outfile)

RUN_SCRIPT = lib/run_exercise.py
TOPO = topology.json
BMV2_SWITCH_EXE = simple_switch_grpc
RUN_ARGS += -b $(BMV2_SWITCH_EXE)

all: run

run: build
	sudo python $(RUN_SCRIPT) -t $(TOPO) $(RUN_ARGS)

stop:
	sudo mn -c

build: dirs $(compiled_json)

$(BUILD_DIR)/%.json: %.p4
	$(P4C) --p4v 16 $(P4C_ARGS) -o $@ $<

dirs:
	mkdir -p $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)

clean: stop
	rm -f *.pcap
	rm -rf $(BUILD_DIR) $(PCAP_DIR) $(LOG_DIR)
