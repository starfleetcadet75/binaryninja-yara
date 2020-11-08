# YARA Scanner Plugin

Author: **starfleetcadet75**

_YARA signature scanner for Binary Ninja._

## Description

This plugin provides support for scanning binaries loaded in Binary Ninja with YARA rules.
Matches are tagged with a _YARA Matches_ tag and are displayed in the tags window.
By default, a report will also be generated that lists the results from the scan.
YARA rules are reloaded each time a new scan is started.
Rules can be manually loaded from a file or loaded from a custom rules directory.

![Demo](https://raw.githubusercontent.com/starfleetcadet75/binaryninja-yara/main/demo.gif)

### Scanning for Crypto Constants

This plugin also provides a [findcrypt](https://github.com/you0708/ida/tree/master/idapython_tools/findcrypt) equivalent for Binary Ninja by including a set of built-in YARA rules for crypto detection.
The original ruleset was taken from the [Yara-Rules](https://github.com/Yara-Rules/rules/blob/master/crypto/crypto_signatures.yar) project and has been modified to include additional signatures from other sources.

### Custom YARA Rules

YARA rules can be loaded from a specific file by selecting _Scan with File_.
This will not load any other rules.
The _Scan_ menu option will load all built-in signatures in addition to searching for any YARA files (*.yar, *.yara) in custom locations that the user has provided in the plugin's settings.

### Settings

This plugin provides the following settings:

- *Custom YARA Rules Path*: Absolute path to a directory containing custom YARA rule files (*.yar, *.yara). Use a semicolon to delimit multiple paths.
- *Scan Timeout*: Timeout for running a YARA scan. A value of 0 disables this feature. The default value is 60 seconds. Time is specified in seconds.
- *Show YARA Report*: The plugin will display a report of the YARA results when the scan has finished.

### Resources

- [YARA Documentation](https://yara.readthedocs.io/en/stable/yarapython.html)
- [Awesome-YARA](https://github.com/InQuest/awesome-yara)
- [Yara-Rules](https://github.com/Yara-Rules/rules)

## Required Dependencies

This plugin requires the pip package `python-yara`.

## License

This plugin is released under a [MIT](LICENSE) license.
