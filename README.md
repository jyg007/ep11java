# EP11 Java/JNA smoke test

Minimal Java 17 Maven project for direct calls to `libep11.so` using JNA.

It performs:

1. `m_init()`
2. `m_add_module()` for adapter/domain `3.19` by default
3. `m_GetMechanismList()`
4. `m_GenerateRandom()` for 32 bytes
5. `m_GenerateKey()` for an AES-256 EP11 key blob

## Prerequisites

- Java 17 or newer
- Maven 3.8 or newer
- IBM EP11 host library installed
- `libep11.so` visible to the dynamic linker
- Access to adapter 3, domain 19

## Check the environment

```bash
java -version
mvn -version
ldconfig -p | grep libep11
find /usr/lib /usr/lib64 /lib /lib64 -name 'libep11.so*' 2>/dev/null
```

If `libep11.so` is not on the default linker path:

```bash
export LD_LIBRARY_PATH=/path/to/ep11/lib:${LD_LIBRARY_PATH:-}
```

Optionally inspect dependencies:

```bash
ldd /path/to/libep11.so
```

## Build

```bash
cd ep11-java-test
mvn clean package
```

## Run against adapter 3, domain 19

```bash
mvn exec:java -Dexec.args='3.19'
```

Alternative with explicit Java library search path:

```bash
mvn exec:java \
  -Dexec.args='3.19' \
  -Dexec.jvmArgs='-Djna.library.path=/path/to/ep11/lib'
```

## EP11 login blob

If the domain requires a login blob, define it as a hexadecimal string:

```bash
export EP11LOGIN='0123456789abcdef...'
mvn exec:java -Dexec.args='3.19'
```

Avoid placing a real login blob in shell history or source control.

## Native ABI verification

The Java mapping assumes 64-bit Linux, where C `unsigned long`, pointers, and `size_t` are 8 bytes. Before production use, compare `XCP_Module` in this project with the exact `ep11.h` installed on the test machine. A structure-layout mismatch can crash the JVM.

Use JNA diagnostics if the library is not found:

```bash
MAVEN_OPTS='-Djna.debug_load=true' mvn exec:java -Dexec.args='3.19'
```

Useful native diagnostics:

```bash
strace -f -e openat mvn exec:java -Dexec.args='3.19' 2>&1 | grep -E 'libep11|jna'
```

## Run the full converted example

```bash
mvn clean compile exec:java \
  -Dexec.mainClass=com.example.ep11.FullExample \
  -Dexec.args='3.19'
```

Optional seed/import environment variables are `EP11LOGIN` and `MASTERSEED` (hex strings).
`Reencipher` is enabled using the supplied `ep11adm.h` ABI through `xcpa_state`, `xcpa_cmdblock`, `m_admin`, and `xcpa_internal_rv`.
