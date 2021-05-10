# Some Sandbox Signature for persistence using cuckoo Signature Class
#
#
#
#
#
#
from abstracts import Signature


class InstallsAppInit(Signature):
    name = "installs_appinit"
    description = "Installs itself in AppInit to inject into new processes"
    severity = 3
    categories = ["persistence"]
    authors = ["Cuckoo Technologies"]
    minimum = "2.0"
    ttp = ["T1103", "T1067", "T1129"]

    # filter_apinames = "ShellExecuteExW", "CreateProcessInternalW",

    regkeys_re = [
        ".*\\\\SOFTWARE\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Windows\\\\Appinit_Dlls",
    ]

    def on_complete(self):
        for indicator in self.regkeys_re:
            regkey = self.check_key(
                pattern=indicator, regex=True, actions=["regkey_written"])
            if regkey:
                self.mark_ioc("registry", regkey)

        return self.has_marks()


class ModifiesBootConfig(Signature):
    name = "modifies_boot_config"
    description = "Modifies boot configuration settings"
    severity = 3
    categories = ["persistance", "ransomware"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    ttp = ["T1067"]
    filter_apinames = "ShellExecuteExW", "CreateProcessInternalW",

    def on_call(self, call, process):
        if call["api"] == "CreateProcessInternalW":
            buf = call["arguments"]["command_line"].lower()
        else:
            buf = call["arguments"]["filepath"].lower()
        if "bcdedit" in buf and "set" in buf:
            self.mark_ioc("command", buf)

    def on_complete(self):
        return self.has_marks()


class CreatesUserFolderEXE(Signature):
    name = "creates_user_folder_exe"
    description = "Creates an executable file in a user folder"
    severity = 3
    families = ["persistance"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    ttp = ["T1129"]

    directories_re = [
        "^[a-zA-Z]:\\\\Users\\\\[^\\\\]+\\\\AppData\\\\.*",
        "^[a-zA-Z]:\\\\Documents\\ and\\ Settings\\\\[^\\\\]+\\\\Local\\ Settings\\\\.*",
    ]

    def on_complete(self):
        for dropped in self.get_results("dropped", []):
            if "filepath" in dropped:
                droppedtype = dropped["type"]
                filepath = dropped["filepath"]
                if "MS-DOS executable" in droppedtype:
                    for directory in self.directories_re:
                        if re.match(directory, filepath):
                            self.mark_ioc("file", filepath)

        return self.has_marks()


class CreatesService(Signature):
    name = "creates_service"
    description = "Creates a service"
    severity = 2
    categories = ["service", "persistence"]
    authors = ["Cuckoo Technologies", "Kevin Ross"]
    minimum = "2.0"
    ttp = ["T1031"]

    filter_apinames = [
        "CreateServiceA", "CreateServiceW",
        "StartServiceA", "StartServiceW",
    ]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.services = []
        self.startedservices = []

    def on_call(self, call, process):
        service_name = (call["arguments"].get("service_name") or "").lower()
        if call["api"] == "CreateServiceA" or call["api"] == "CreateServiceW":
            self.services.append(service_name)
            self.mark_call()

        elif call["api"] == "StartServiceA" or call["api"] == "StartServiceW":
            self.startedservices.append(service_name)

    def on_complete(self):
        for service in self.services:
            if service not in self.startedservices:
                self.description = "Created a service where a service was also not started"
                self.severity = 3

        return self.has_marks()


class CreatesShortcut(Signature):
    name = "creates_shortcut"
    description = "Creates a shortcut to an executable file"
    severity = 2
    categories = ["persistance"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    ttp = ["T1023", "T1204"]
    files_re = [
        ".*\\.lnk$",
    ]

    safelist = [
        "C:\\Users\\Administrator\\AppData\\Local\\Temp\\%ProgramData%\\Microsoft\\Windows\\Start Menu\\Programs\\Accessories\\Windows PowerShell\\Windows PowerShell.lnk",
        "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Accessories\\Windows PowerShell\\Windows PowerShell.lnk",
    ]

    def on_complete(self):
        for indicator in self.files_re:
            for match in self.check_file(pattern=indicator, regex=True, all=True):
                if match in self.safelist:
                    continue

                self.mark_ioc("file", match)

        return self.has_marks()


class CredentialDumpingLsass(Signature):
    name = "credential_dumping_lsass"
    description = "Locates and dumps memory from the lsass.exe process indicative of credential dumping"
    severity = 3
    categories = ["persistence", "lateral_movement"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    evented = True
    references = ["cyberwardog.blogspot.co.uk/2017/03/chronicles-of-threat-hunter-hunting-for_22.html",
                  "cyberwardog.blogspot.co.uk/2017/04/chronicles-of-threat-hunter-hunting-for.html"]

    lsasspid = []
    lsasshandle = []
    creddump = False

    filter_apinames = "Process32NextW", "NtOpenProcess", "ReadProcessMemory",

    def on_call(self, call, process):
        if call["api"] == "Process32NextW":
            if call["arguments"]["process_name"] == "lsass.exe":
                self.lsasspid.append(call["arguments"]["process_identifier"])
                self.mark_call()

        if call["api"] == "NtOpenProcess":
            if call["arguments"]["process_identifier"] in self.lsasspid:
                if call["arguments"]["desired_access"] in ["0x00001010", "0x00001038"]:
                    self.lsasshandle.append(
                        call["arguments"]["process_handle"])
                    self.mark_call()

        if call["api"] == "ReadProcessMemory":
            if call["arguments"]["process_handle"] in self.lsasshandle:
                self.creddump = True
                self.mark_call()

    def on_complete(self):
        if self.creddump:
            return self.has_marks()


class CredentialDumpingLsassAccess(Signature):
    name = "credential_dumping_lsass_access"
    description = "Requests access to read memory contents of lsass.exe potentially indicative of credential dumping"
    severity = 3
    categories = ["persistence", "lateral_movement"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    evented = True
    references = ["cyberwardog.blogspot.co.uk/2017/03/chronicles-of-threat-hunter-hunting-for_22.html",
                  "cyberwardog.blogspot.co.uk/2017/04/chronicles-of-threat-hunter-hunting-for.html"]

    lsasspid = []
    creddump = False

    filter_apinames = "NtOpenProcess", "Process32NextW",

    def on_call(self, call, process):
        if call["api"] == "Process32NextW":
            if call["arguments"]["process_name"] == "lsass.exe":
                self.lsasspid.append(call["arguments"]["process_identifier"])
                self.mark_call()

        if call["api"] == "NtOpenProcess":
            if call["arguments"]["process_identifier"] in self.lsasspid:
                if call["arguments"]["desired_access"] in ["0x00001010", "0x00001038"]:
                    self.creddump = True
                    self.mark_call()

    def on_complete(self):
        if self.creddump:
            return self.has_marks()


class DeletesExecutedFiles(Signature):
    name = "deletes_executed_files"
    description = "Deletes executed files from disk"
    severity = 3
    categories = ["persistence", "stealth"]
    authors = ["Optiv", "Kevin Ross"]
    minimum = "2.0"
    ttp = ["T1070"]
    evented = True

    def on_complete(self):
        processes = []
        for process in self.get_results("behavior", {}).get("generic", []):
            for cmdline in process.get("summary", {}).get("command_line", []):
                processes.append(cmdline)

        if processes:
            for deletedfile in self.get_files(actions=["file_deleted"]):
                if deletedfile in processes[0]:
                    self.mark_ioc("file", deletedfile)

        return self.has_marks()


class DisablesSystemRestore(Signature):
    name = "disables_system_restore"
    description = "Attempts to disable System Restore"
    severity = 3
    categories = ["ransomware", "persistance"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    ttp = ["T1112"]

    regkeys_re = [
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\SystemRestore\\\\DisableSR$",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Policies\\\\Microsoft\\\\Windows\\ NT\\\\SystemRestore\\\\DisableSR$",
        ".*\\\\SOFTWARE\\\\(Wow6432Node\\\\)?Policies\\\\Microsoft\\\\Windows\\ NT\\\\SystemRestore\\\\DisableConfig$",
    ]

    def on_complete(self):
        for indicator in self.regkeys_re:
            for regkey in self.check_key(pattern=indicator, regex=True, actions=["regkey_written"], all=True):
                self.mark_ioc("registry", regkey)

        return self.has_marks()


class ExeAppData(Signature):
    name = "exe_appdata"
    description = "Drops an executable to the user AppData folder"
    severity = 2
    categories = ["dropper", "persistence"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    ttp = ["T1129"]

    def on_complete(self):
        for dropped in self.get_results("dropped", []):
            if "filepath" in dropped and dropped["type"].startswith("PE32 executable"):
                filepath = dropped["filepath"]
                if "\\Users\\" in filepath and "\\AppData\\" in filepath:
                    self.mark_ioc("file", filepath)

        return self.has_marks()


class JavaScriptCommandline(Signature):
    name = "javascript_commandline"
    description = "Executes JavaScript in a commandline"
    severity = 3
    categories = ["javascript", "persistence", "downloader"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    ttp = ["T1059"]

    def on_complete(self):
        for cmdline in self.get_command_lines():
            if "javascript:" in cmdline.lower():
                self.mark_ioc("cmdline", cmdline)

        return self.has_marks()


class ADS(Signature):
    name = "persistence_ads"
    description = "Creates an Alternate Data Stream (ADS)"
    severity = 2
    categories = ["persistence", "ads"]
    authors = ["nex", "Optiv"]
    minimum = "2.0"
    ttp = ["T1096"]

    def on_complete(self):
        for filepath in self.get_files():
            if len(filepath) <= 3:
                continue

            if ":" in filepath.split("\\")[-1]:
                if not filepath.lower().startswith("c:\\dosdevices\\") and not filepath[-1] == ":":
                    # we have a different signature to deal with removal of Zone.Identifier
                    if not filepath.startswith("\\??\\http://") and not filepath.endswith(":Zone.Identifier") and not re.match(r'^[A-Z]?:\\(Users|Documents and Settings)\\[^\\]+\\Favorites\\Links\\Suggested Sites\.url:favicon$', filepath, re.IGNORECASE):
                        self.mark_ioc("file", filepath)

        return self.has_marks()


class Autorun(Signature):
    name = "persistence_autorun"
    description = "Installs itself for autorun at Windows startup"
    severity = 3
    categories = ["persistence"]
    authors = ["Michael Boman", "nex", "securitykitten",
               "Cuckoo Technologies", "Optiv", "KillerInstinct", "Kevin Ross"]
    minimum = "2.0"
    ttp = ["T1060", "T1053"]

    regkeys_re = [
        ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\.*",
        ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnce\\\\.*",
        ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServices\\\\.*",
        ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunOnceEx\\\\.*",
        ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\RunServicesOnce\\\\.*",
        ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\Notify\\\\.*",
        ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\Userinit$",
        ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Policies\\\\Explorer\\\\Run\\\\.*",
        ".*\\\\Microsoft\\\\Active\\ Setup\\\\Installed Components\\\\.*",
        ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Windows\\\\AppInit_DLLs$",
        ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Explorer\\\\SharedTaskScheduler\\\\.*",
        ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Image\\ File\\ Execution\\ Options\\\\[^\\\\]*\\\\\Debugger$",
        ".*\\\\Microsoft\\\\Windows\\ NT\\\\CurrentVersion\\\\Winlogon\\\\Shell$",
        ".*\\\\System\\\\(CurrentControlSet|ControlSet001)\\\\Services\\\\[^\\\\]*\\\\ImagePath$",
        ".*\\\\System\\\\(CurrentControlSet|ControlSet001)\\\\Services\\\\[^\\\\]*\\\\Parameters\\\\ServiceDLL$",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\Exefile\\\\Shell\\\\Open\\\\Command\\\\\(Default\)$",
        ".*\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\Windows\\\\load$",
        ".*\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\ShellServiceObjectDelayLoad\\\\.*",
        ".*\\\\System\\\\(CurrentControlSet|ControlSet001)\\\\Control\\\\Session\\ Manager\\\\AppCertDlls\\\\.*",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\clsid\\\\[^\\\\]*\\\\InprocServer32\\\\.*",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\clsid\\\\[^\\\\]*\\\\LocalServer32\\\\.*",
    ]

    files_re = [
        ".*\\\\win\.ini$",
        ".*\\\\system\.ini$",
        ".*\\\\Start Menu\\\\Programs\\\\Startup\\\\.*",
        ".*\\\\WINDOWS\\\\Tasks\\\\.*"
    ]

    command_lines_re = [
        ".*schtasks.*/create.*/sc",
    ]

    safelists = [
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\clsid\\\\{CAFEEFAC-0017-0000-FFFF-ABCDEFFEDCBA}\\\\InprocServer32\\\\.*",
        ".*\\\\Software\\\\(Wow6432Node\\\\)?Classes\\\\clsid\\\\[^\\\\]*\\\\InprocServer32\\\\ThreadingModel$"
    ]

    filter_apinames = [
        "RegSetValueExA",
        "RegSetValueExW",
        "NtSetValueKey",
        "CreateServiceA",
        "CreateServiceW",
    ]

    def on_call(self, call, process):
        if call["api"] == "CreateServiceA" or call["api"] == "CreateServiceW":
            starttype = call["arguments"]["start_type"]
            servicename = call["arguments"]["service_name"]
            servicepath = call["arguments"]["filepath"]
            if starttype < 3:
                self.mark(
                    service_name=servicename,
                    service_path=servicepath,
                )

        elif call["status"]:
            regkey = call["arguments"]["regkey"]
            regvalue = call["arguments"]["value"]
            in_safelist = False
            for safelist in self.safelists:
                if re.match(safelist, regkey, re.IGNORECASE):
                    in_safelist = True
                    break
            if not in_safelist:
                for indicator in self.regkeys_re:
                    if re.match(indicator, regkey, re.IGNORECASE) and regvalue != "c:\\program files\\java\\jre7\\bin\jp2iexp.dll":
                        self.mark(
                            reg_key=regkey,
                            reg_value=regvalue,
                        )

    def on_complete(self):
        for indicator in self.files_re:
            for filepath in self.check_file(pattern=indicator, regex=True, actions=["file_written"], all=True):
                self.mark_ioc("file", filepath)

        for indicator in self.command_lines_re:
            for cmdline in self.get_command_lines():
                if re.match(indicator, cmdline, re.I):
                    self.mark_ioc("cmdline", cmdline)

        return self.has_marks()


class PersistenceBootexecute(Signature):
    name = "persistence_bootexecute"
    description = "Installs a native executable to run on early Windows boot"
    severity = 3
    categories = ["persistence"]
    authors = ["Brad Spengler"]
    minimum = "2.0"
    evented = True
    ttp = ["T1060"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.registry_writes = dict()
        self.found_bootexecute = False

    filter_apinames = set(
        ["RegSetValueExA", "RegSetValueExW", "NtSetValueKey"])

    def on_call(self, call, process):
        if call["status"]:
            fullname = call["arguments"]["regkey"]
            self.registry_writes[fullname] = call["arguments"]["value"]

    def on_complete(self):
        match_key = self.check_key(pattern=".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\Control\\\\Session\\ Manager\\\\(BootExecute|SetupExecute|Execute|S0InitialCommand)",
                                   regex=True, actions=["regkey_written"], all=True)
        if match_key:
            self.found_bootexecute = True
            for match in match_key:
                data = self.registry_writes.get(match, "unknown")
                self.data.append({"key": match})
                self.data.append({"data": data})

        return self.found_bootexecute


class PersistenceBootexecute(Signature):
    name = "persistence_bootexecute"
    description = "Installs a native executable to run on early Windows boot"
    severity = 3
    categories = ["persistence"]
    authors = ["Brad Spengler"]
    minimum = "2.0"
    evented = True
    ttp = ["T1060"]

    def __init__(self, *args, **kwargs):
        Signature.__init__(self, *args, **kwargs)
        self.registry_writes = dict()
        self.found_bootexecute = False

    filter_apinames = set(
        ["RegSetValueExA", "RegSetValueExW", "NtSetValueKey"])

    def on_call(self, call, process):
        if call["status"]:
            fullname = call["arguments"]["regkey"]
            self.registry_writes[fullname] = call["arguments"]["value"]

    def on_complete(self):
        match_key = self.check_key(pattern=".*\\\\SYSTEM\\\\(CurrentControlSet|ControlSet001)\\\\Control\\\\Session\\ Manager\\\\(BootExecute|SetupExecute|Execute|S0InitialCommand)",
                                   regex=True, actions=["regkey_written"], all=True)
        if match_key:
            self.found_bootexecute = True
            for match in match_key:
                data = self.registry_writes.get(match, "unknown")
                self.data.append({"key": match})
                self.data.append({"data": data})

        return self.found_bootexecute


class PersistenceRegistryJavaScript(Signature):
    name = "persistence_registry_javascript"
    description = "Used JavaScript in registry key value likely for persistance"
    severity = 3
    categories = ["persistence"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    evented = True
    ttp = ["T1112"]

    filter_apinames = set(
        ["RegSetValueExA", "RegSetValueExW", "NtSetValueKey"])

    def on_call(self, call, process):
        value = call["arguments"]["value"]
        if not isinstance(value, basestring):
            return
        if value and "javascript:" in value:
            self.mark_call()

    def on_complete(self):
        return self.has_marks()


class PersistenceRegistryEXE(Signature):
    name = "persistence_registry_exe"
    description = "Stores an executable in the registry"
    severity = 5
    categories = ["persistence"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    evented = True
    ttp = ["T1112"]

    filter_apinames = set(
        ["RegSetValueExA", "RegSetValueExW", "NtSetValueKey"])

    def on_call(self, call, process):
        value = call["arguments"]["value"]
        if not isinstance(value, basestring):
            return
        if value.startswith("MZ"):
            self.mark_call()

    def on_complete(self):
        return self.has_marks()


class PersistenceRegistryPowershell(Signature):
    name = "persistence_registry_powershell"
    description = "Stores PowerShell commands in the registry likely for persistence"
    severity = 4
    categories = ["persistence"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    evented = True
    ttp = ["T1112"]

    filter_apinames = set(
        ["RegSetValueExA", "RegSetValueExW", "NtSetValueKey"])

    def on_call(self, call, process):
        value = call["arguments"]["value"]
        if not isinstance(value, basestring):
            return
        if "powershell " in value or "powershell.exe" in value:
            self.mark_call()

    def on_complete(self):
        return self.has_marks()


class SpynetRat(Signature):
    name = "rat_spynet"
    description = "Creates known SpyNet files, registry changes and/or mutexes."
    severity = 4
    categories = ["rat"]
    families = ["spynet"]
    authors = ["threatlead", "nex", "RedSocks"]
    minimum = "2.0"

    references = [
        "https://malwr.com/analysis/ZDQ1NjBhNWIzNTdkNDRhNjhkZTFmZTBkYTU2YjMwNzg/",
        "https://malwr.com/analysis/MjkxYmE2YzczNzcwNGJiZjljNDcwMzA2ZDkyNDU2Y2M/",
        "https://malwr.com/analysis/N2E3NWRiNDMyYjIwNGE0NTk3Y2E5NWMzN2UwZTVjMzI/",
        "https://malwr.com/analysis/N2Q2NWY0Y2MzOTM0NDEzNmE1MTdhOThiNTQxMzhiNzk/",
    ]

    mutexes_re = [
        ".*CYBERGATEUPDATE",
        ".*\(\(SpyNet\)\).*",
        ".*Spy-Net.*",
        ".*Spy.*Net.*Instalar",
        ".*Spy.*Net.*Persist",
        ".*Spy.*Net.*Sair",
        ".*X_PASSWORDLIST_X.*",
        ".*X_BLOCKMOUSE_X.*",
        # ".*PERSIST",  # Causes false positive detection on XtremeRAT samples.
        ".*_SAIR",
        ".*SPY_NET_RATMUTEX",
        ".*xXx.*key.*xXx",
        ".*Administrator15",
        ".*Caracas",
        ".*Caracas_PERSIST",
        ".*Pluguin",
        ".*Pluguin_PERSIST",
        ".*Pluguin_SAIR",
        ".*MUT1EX.*",
    ]

    regkeys_re = [
        ".*\\SpyNet\\.*",
    ]

    files_re = [
        ".*XX--XX--XX.txt",
        ".*\\\\Spy-Net\\\\server.exe",
        ".*\\\\Spy-Net\\\\Spy-Net.dll",
        ".*\\\\Spy-Net\\\\keylog.dat",
        ".*\\\\Spy-Net",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            mutex = self.check_mutex(pattern=indicator, regex=True)
            if mutex:
                self.mark_ioc("mutex", mutex)

        for indicator in self.regkeys_re:
            regkey = self.check_key(pattern=indicator, regex=True)
            if regkey:
                self.mark_ioc("registry", regkey)

        for indicator in self.files_re:
            regkey = self.check_file(pattern=indicator, regex=True)
            if regkey:
                self.mark_ioc("file", regkey)

        return self.has_marks()


class XtremeRAT(Signature):
    name = "rat_xtreme"
    description = "Creates known XtremeRAT files, registry keys or mutexes"
    severity = 3
    categories = ["rat"]
    families = ["xtremerat"]
    authors = ["RedSocks"]
    minimum = "2.0"

    references = [
        "https://malwr.com/analysis/ODVlOWEyNDU3NzBhNDE3OWJkZjE0ZjIxNTdiMzU1YmM/",
        "https://malwr.com/analysis/ZWM4YjI2MzI1MmQ2NDBkMjkwNzI3NzhjNWM5Y2FhY2U/",
        "https://malwr.com/analysis/MWY5YTAwZWI1NDc3NDJmMTgyNDA4ODc0NTk0MWIzNjM/",
    ]

    mutexes_re = [
        ".*XTREMEUPDATE",
        ".*XTREMEPERSIST",
        ".*XTREMECLIENT",
        ".*Xtreme",
        "Xtreme.*RAT.*Private",
        ".*\\(\\(Mutex\\)\\)",
    ]

    regkeys_re = [
        ".*\\\\SOFTWARE\\\\XtremeRAT",
        ".*\\\\SOFTWARE\\\\YdymVYB73",
    ]

    files_re = [
        ".*Xtreme.*RAT.*",
        ".*Xtreme.*Private",
        ".*xtreme.*private.*fixed.*",
        ".*Application.*Microsoft.*Windows.*xtr",
    ]

    def on_complete(self):
        for indicator in self.mutexes_re:
            match = self.check_mutex(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("mutex", match)

        for indicator in self.regkeys_re:
            match = self.check_key(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("regkey", match)

        for indicator in self.files_re:
            match = self.check_file(pattern=indicator, regex=True)
            if match:
                self.mark_ioc("file", match)

        return self.has_marks()


class TerminatesRemoteProcess(Signature):
    name = "terminates_remote_process"
    description = "Terminates another process"
    severity = 3
    categories = ["persistence", "stealth"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    evented = True

    filter_apinames = "NtTerminateProcess",

    def on_call(self, call, process):
        if call["arguments"]["process_handle"] not in ["0xffffffff", "0xffffffffffffffff", "0x00000000", "0x0000000000000000"]:
            self.mark_call()

    def on_complete(self):
        return self.has_marks()


class WMIPersistance(Signature):
    name = "wmi_persistance"
    description = "Executes one or more WMI queries which can be used for persistance"
    severity = 3
    categories = ["persistance"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    ttp = ["T1047"]

    persistance = [
        "win32_startupcommand",
    ]

    def on_complete(self):
        for command in self.persistance:
            for query in self.get_wmi_queries():
                if command in query.lower():
                    self.mark_ioc("wmi", query)

        return self.has_marks()


class WMIService(Signature):
    name = "wmi_service"
    description = "Executes one or more WMI queries which can be used to create or modify services"
    severity = 3
    categories = ["persistance"]
    authors = ["Kevin Ross"]
    minimum = "2.0"
    ttp = ["T1047"]

    persistance = [
        "win32_service",
    ]

    def on_complete(self):
        for command in self.persistance:
            for query in self.get_wmi_queries():
                if command in query.lower():
                    self.mark_ioc("wmi", query)

        return self.has_marks()
