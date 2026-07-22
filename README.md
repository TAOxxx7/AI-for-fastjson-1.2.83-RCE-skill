# fastjson-1.2.83-RCEskill

AI agent skill for detecting and exploiting Fastjson @JSONType RCE (QVD-2026-43021).

## What it does

Once imported, an AI agent can autonomously:

1. Fingerprint Fastjson and confirm the target version
2. Check SafeMode status
3. Distinguish FatJar vs WAR deployment
4. Generate payloads for JDK 8 (single request) or JDK 11/17/21 (fd enumeration)
5. Deploy and collect results via OOB callback

## Usage

Copy this repo URL and paste it to your AI agent, or place `SKILL.md` in the skill directory manually:

> https://github.com/TAOxxx7/fastjson-1.2.83-RCEskill

Then prompt:

> Check if http://TARGET:8080/api/parse is vulnerable to Fastjson @JSONType RCE

## Requirements

- JDK 8+
- Python 3
- `org.ow2.asm` (Maven Central)

## License

For authorized security research and penetration testing only.
