#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Build the ogir-client prototype (M5-033, ADR-0029): ONE winelib
# artifact (ogir-client.dll.so) that Wine resolves as ogir-client.dll
# when it sits beside the game executable, plus the 64- and 32-bit
# ABI test harnesses that IMPORT the DLL at link time (the loader's
# import pass is what resolves <name>.dll.so in the application
# directory - runtime LoadLibrary does not, per the executed
# evidence in ADR-0029).
# Outputs land in build/ (gitignored). Dev-host toolchain: mingw
# (both arches) + winegcc from wine-devel.
set -euo pipefail
cd "$(dirname "$0")"

for tool in winegcc x86_64-w64-mingw32-gcc i686-w64-mingw32-gcc x86_64-w64-mingw32-dlltool; do
    command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 1; }
done
[[ -f ../../sdk/include/ogir.h ]] || { echo "missing sdk header" >&2; exit 1; }

mkdir -p build

# 1. The winelib module: spec-bound ms_abi C ABI + the native
#    AF_UNIX transport in one artifact.
winegcc -m64 -shared -o build/ogir-client \
    ogir_client_dll.c ogir_client.spec \
    -I../../sdk/include

# 2. A matching import library so the harnesses can IMPORT the DLL
#    (link-time), which is the load path that resolves the winelib
#    artifact.
printf 'LIBRARY ogir-client.dll\nEXPORTS\n  ogir_client_close\n  ogir_client_open\n  ogir_session_begin\n  ogir_session_close\n  ogir_session_get_permit\n  ogir_session_sign_binding\n' \
    > build/ogir-client.def
x86_64-w64-mingw32-dlltool -d build/ogir-client.def -l build/libogir-client.dll.a -D ogir-client.dll
i686-w64-mingw32-dlltool -d build/ogir-client.def -l build/libogir-client32.dll.a -D ogir-client.dll \
    --as i686-w64-mingw32-as 2>/dev/null || i686-w64-mingw32-dlltool -d build/ogir-client.def -l build/libogir-client32.dll.a -D ogir-client.dll

# 3. The ABI harnesses against the public header, importing the DLL.
x86_64-w64-mingw32-gcc -o build/ogir-abi-test.exe \
    abi_test.c -I../../sdk/include -Lbuild -logir-client.dll
i686-w64-mingw32-gcc -o build/ogir-abi-test32.exe \
    abi_test.c -I../../sdk/include -Lbuild -logir-client32.dll

# 4. The 32-bit PE variant for the WoW64 leg (its unix calls fail
#    closed in the prototype - the recorded layout-mismatch
#    defense; see ADR-0029).
i686-w64-mingw32-dlltool -d build/ntdll_unix.def -l build/libntdll_unix32.a -D ntdll.dll
i686-w64-mingw32-gcc -shared -o build/ogir-client32.dll \
    pe/ogir_client.c -I../../sdk/include -I. -I/usr/include/wine/windows \
    -Lbuild -lntdll_unix32

echo "built:"
ls -la build/
