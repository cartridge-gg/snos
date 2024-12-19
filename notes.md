1. Setup python env.
2. Compile SNOS:
```
cairo-compile cairo-lang/src/starkware/starknet/core/os/os.cairo --output build/os_latest.json --cairo_path cairo-lang/src
```
3. Send the compiled program to SNOS.
```
cp build/os_latest.json ~/cgg/saya/bin/saya/programs/snos.json
```
