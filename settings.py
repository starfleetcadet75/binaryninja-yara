from binaryninja import Settings

Settings().register_group("yara", "Yara")
Settings().register_setting("yara.customRulesPath", """
    {
        "title" : "Custom YARA Rules Path",
        "type" : "string",
        "default" : "",
        "description" : "Absolute path to a directory containing custom YARA rule files (*.yar, *.yara). Use a semicolon to delimit multiple paths."
    }
    """)
Settings().register_setting("yara.timeout", """
    {
        "title" : "Scan Timeout",
        "type" : "number",
        "default" : 60,
        "description" : "Timeout for running a YARA scan. A value of 0 disables this feature. The default value is 60 seconds. Time is specified in seconds."
    }
    """)
Settings().register_setting("yara.displayReport", """
    {
        "title" : "Show YARA Report",
        "type" : "boolean",
        "default" : true,
        "description" : "Display a report of the YARA results when the scan is finished."
    }
    """)
