import os
import yara
from binaryninja import (BackgroundTaskThread, BinaryReader, Endianness,
                         MessageBoxIcon, PluginCommand, Settings,
                         get_open_filename_input, log_error, log_info,
                         log_warn, show_message_box)
from . import settings

RULES_DIR = os.path.dirname(os.path.realpath(__file__)) + os.sep + "rules"


def get_instruction_containing(function, address):
    bb = function.get_basic_block_at(address)
    text = bb.get_disassembly_text()

    # Handle the last instruction in the block
    if text[-1].address <= address:
        return text[-1].address

    for i in range(1, len(text)):
        if text[i - 1].address <= address and address < text[i].address:
            return text[i - 1].address


class YaraScan(BackgroundTaskThread):
    def __init__(self, bv, filepath=None, directories=None):
        self.progress_banner = "Running YARA scan"
        BackgroundTaskThread.__init__(self, self.progress_banner, True)

        self.bv = bv
        self.reader = BinaryReader(self.bv)
        self.rules = []
        self.results = []

        # Ensure that the tag types exist before using it
        if "YARA Matches" not in bv.tag_types:
            bv.create_tag_type("YARA Matches", "🔎")

        if filepath:
            self.load_signature(filepath)

        if directories:
            self.load_signatures(directories)

    def run(self):
        log_info("Scanning binary view for matching YARA signatures")

        # TODO: Scan the raw binary data from the Raw view instead of by segment.
        # This would require mapping the addresses from the Raw view to the PE/ELF views.
        # raw = self.bv.get_view_of_type("Raw")
        # reader = BinaryReader(raw)
        # data = reader.read(raw.end)

        try:
            for idx, rule in enumerate(self.rules):
                if len(self.bv.segments) == 0:
                    # Scan binary without segments
                    self.scan(self.bv.start, self.bv.end, rule)
                else:
                    # Scan by segment
                    for segment in self.bv.segments:
                        if self.cancelled:
                            return

                        self.scan(segment.start, segment.data_length, rule)

                self.progress = f"{self.progress_banner} matching on rules ({round((idx / len(self.rules)) * 100)}%)"

        except yara.TimeoutError:
            log_warn("YARA scan exceeded timeout limit. Consider changing the timeout in settings.")
        except yara.Error as err:
            log_error("Error matching on YARA rules: {}".format(str(err)))
            show_message_box("Error", "Check logs for details", icon=MessageBoxIcon.ErrorIcon)

        if 0 < len(self.results):
            if Settings().get_bool("yara.displayReport"):
                self.display_report()
        else:
            log_info("YARA scan finished with no matches.")

    def scan(self, start, length, rule):
        self.reader.seek(start)
        data = self.reader.read(length)

        matches = rule.match(
            data=data,
            timeout=Settings().get_integer("yara.timeout")
        )

        for match in matches:
            name = match.rule

            # Include the description field if its present in the metadata
            try:
                description = f"{name}: {match.meta['description']}"
            except KeyError:
                description = f"{name}"

            tag = self.bv.create_tag(self.bv.tag_types["YARA Matches"], description, True)

            for address, var, value in match.strings:
                address += start

                # Display data values correctly in the report
                if value.isascii():
                    value = value.decode("ascii")
                elif self.bv.endianness == Endianness.BigEndian:
                    value = hex(int.from_bytes(value, "big"))
                else:
                    value = hex(int.from_bytes(value, "little"))

                self.results.append({
                    "address": address,
                    "name": name,
                    "string": var,
                    "value": value
                })

                # Add either an address or data tag to the location
                funcs = self.bv.get_functions_containing(address)
                if 0 < len(funcs):
                    # Ensure the tag is not placed in the middle of an instruction
                    address = get_instruction_containing(funcs[0], address)
                    funcs[0].add_user_address_tag(address, tag)
                else:
                    self.bv.add_user_data_tag(address, tag)

    def display_report(self):
        contents = """# YARA Results

| Address | Name | String | Value |
|---------|------|--------|-------|
"""

        for result in self.results:
            contents += "| [0x{:x}](binaryninja://?expr=0x{:x}) | {} | {} | {} |\n".format(
                result["address"],
                result["address"],
                result["name"],
                result["string"],
                result["value"]
            )

        self.bv.show_markdown_report("YARA Results", contents)

    def load_signature(self, filepath):
        if os.path.isfile(filepath):
            try:
                self.rules.append(yara.compile(filepath))
                log_info("Loaded YARA rule: {}".format(filepath))
            except yara.SyntaxError:
                log_error("Syntax error compiling YARA rule: {}".format(filepath))
        else:
            log_error("YARA rule filepath is invalid: {}".format(filepath))

    def load_signatures(self, directories):
        rule_files = []

        for directory in directories:
            if not os.path.isdir(directory) and directory != "":
                log_error("YARA rule directory is invalid: {}".format(directory))
            else:
                for f in os.listdir(directory):
                    if f.lower().endswith((".yar", ".yara")):
                        rule_files.append(directory + os.sep + f)

        for f in rule_files:
            try:
                self.rules.append(yara.compile(f))
                log_info("Loaded YARA rule: {}".format(f))
            except yara.SyntaxError:
                log_error("Syntax error compiling YARA rule: {}".format(f))


def scan(bv):
    rules = [RULES_DIR]
    paths = Settings().get_string("yara.customRulesPath")

    for path in paths.split(";"):
        rules.append(path.strip())

    ys = YaraScan(bv, directories=rules)
    ys.start()


def scan_with_file(bv):
    filepath = get_open_filename_input("Open YARA rule", "YARA rules (*.yar *.yara)")
    if filepath:
        ys = YaraScan(bv, filepath=filepath)
        ys.start()


def crypto_scan(bv):
    crypto_rules = RULES_DIR + os.sep + "crypto_signatures.yar"
    ys = YaraScan(bv, filepath=crypto_rules)
    ys.start()


PluginCommand.register("YARA\\Scan", "Scan file using YARA rules", scan)
PluginCommand.register("YARA\\Scan with File", "Scan file using a specific YARA rule", scan_with_file)
PluginCommand.register("YARA\\Scan for Crypto", "Scan file for known crypto constants using YARA rules", crypto_scan)
