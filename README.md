
# DumpDex
dump dex from memory NEED ROOT

# Build
GOOS=android GOARCH=arm64 GOARM=7 go build .

# Run
```bash
adb push dump-dex /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/dump-dex"
./dump-dex pid
```
