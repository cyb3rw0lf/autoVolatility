# AutoVolatility

AutoVolatility is a script made by [carlospolop](https://github.com/carlospolop) to run several volatility plugins at the same time

## How to use

AutoVolatility will create a new folder in the output directory for each plugin executed.

You can run the "main" volatility plugins doing, default directory is the `MEMFILE` name + `_autovol`
```python
python autoVolatility.py -f MEMFILE
``` 

Can you specify output directory:
```python
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY
``` 

The variable `volatility_cmd` is the default command used to run volatility. You can either modify that variable with your own path:
```python
volatility_cmd = "vol2 --plugins=/opt/volatility2/community"
```
or use the option `-e`. Important is that the command is able to use community plugins.
```python
python autoVolatility.py -f MEMFILE -e "/usr/loca/bin/vol.py --plugins==/path/to/plugins"
```

AutoVolatility will use the plugin "imageinfo" to figure out the profile to use. But if you know the profile, you can set it using the option `-p`

```python
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -p WinXPSP2x86
```

If you want to run almos all the default plugins that comes with volatility you can use the option `-a`

```python
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -a
```

By default autoVolatility uses 8 threads, but you can change it with the option `-t`

```python
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -t 16 # 16 threads
```

If want autoVolatility to run other plugins, you can do so using the option `-c`

```python
python autoVolatility.py -f MEMFILE -d OUT_DIRECTORY -c amcache,auditpol,cachedump,clipboard,cmdline,cmdscan # Only these plugins will be executed
```

The plugins executed by default are the following:
(the key of the dictionary if going to be the name of the sub-folder, for dumps there's an additional sub-folder for each plugin)

```python
pluginsDict = {
    "network": ["connections",
                "connscan",
                "sessions",
                "sockets",
                "sockscan",
                "netscan"],

    "processes": ["pslist",
                  "psscan",
                  "pstree",
                  "psxview",
                  "getsids"],

    "registry": ["hivelist",
                 'printkey -K "Software\Microsoft\Windows\CurrentVersion\Run"'],

    "services": ["getservicesids",
                 "servicediff",
                 "svcscan -v"],

    "cmd": ["cmdline",
            "cmdscan",
            "consoles"],

    "browsers": ["chromecookies",
                 "chromedownloadchains",
                 "chromedownloads",
                 "chromehistory",
                 "chromesearchterms",
                 "chromevisits",
                 "firefoxcookies",
                 "firefoxdownloads",
                 "firefoxhistory",
                 "iehistory"],

    "malware": ["malfind",
                "malfinddeep",
                "malfofind",
                "malprocfind",
                "malthfind"],

    "dumps": ["cachedump",
              "dumpcerts",
              "dumpregistry",
              "dumpfiles",
              "dumpregistry",
              "hashdump",
              "screenshot",
              "networkpackets"],

    "others": ["clipboard",
               "amcache",
               "auditpol",
               "deskscan",
               "devicetree",
               "dlllist",
               "envars",
               "handles",
               "hibinfo",
               "ldrmodules",
               "lsadump",
               "mbrparser",
               "memmap",
               "mftparser",
               "modules",
               "notepad",
               "privs",
               "qemuinfo",
               "ssdt",
               "strings",
               "symlinkscan",
               "thrdscan",
               "verinfo",
               "windows",
               "wintree"]
}

extra = ["psscan --output=dot --output-file=psscan.dot"]
```

The plugins executed using the option `-a` are:

```python
dump_plugins = ["dumpcerts", "dumpregistry", "dumpfiles", "dumpregistry"]


plugins_all = ["amcache", "apihooks", "atoms", "atomscan", "auditpol", "bigpools", "bioskbd", "cachedump", "callbacks", "clipboard", "cmdline", "cmdscan", "connections", "connscan", "consoles", "crashinfo",
                "deskscan", "devicetree", "dlldump", "dlllist", "driverirp", "drivermodule", "driverscan", "editbox", "envars", "eventhooks", "evtlogs", "filescan", 
                "gahti", "gditimers", "gdt", "getservicesids", "getsids", "handles", "hashdump", "hibinfo", "hivelist", "hivescan", "hpakextract", "hpakinfo", "idt", "iehistory", "imagecopy", "imageinfo",
                "joblinks", "kdbgscan", "kpcrscan", "ldrmodules", "lsadump", "malfind", "mbrparser", "memdump", "memmap", "messagehooks", "mftparser", "moddump", "modscan", "modules", "multiscan", "mutantscan",
                "notepad", "objtypescan", "patcher", "printkey", "privs", "procdump", "pslist", "psscan", "pstree", "psxview", "qemuinfo", "raw2dmp", "screenshot", "servicediff", "sessions", "shellbags", "shimcache",
                "shutdowntime", "sockets", "sockscan", "ssdt", "strings", "svcscan", "symlinkscan", "thrdscan", "threads", "timeliner", "timers", "truecryptmaster", "truecryptpassphrase", "truecryptsummary",
                "unloadedmodules", "userassist", "userhandles", "vaddump", "vadinfo", "vadtree", "vadwalk", "vboxinfo", "verinfo", "vmwareinfo", "windows", "wintree", "wndscan"]


```
