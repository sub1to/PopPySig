# PopPySig

PopPySig is a python script for IDA that can make byte signatures and scan for byte signatures.

### Installation

PopPySig will require [idapython](https://github.com/idapython/src)

Put the python files in
```
__PATH_TO_IDA_DIR__\python
```

##### Manual Execution
Execute the script by pressing `ALT + F7` and selecting `sig.py`

##### Automatic execution
To start IDA with the script loaded, execute IDA with argument
```bat
-S"python/sig.py"
```

### Usage

##### Create a sig at the cursor position (ScreenEA)
```
sig()
```

##### Scan for a signature
```
scan("11 ? ? ? ? 22")
```

##### Scan for all occurrences of a signature
```
fullscan("11 ? ? ? ? 22")
```

### Authors
- sub1to

License
----

GNU GPL