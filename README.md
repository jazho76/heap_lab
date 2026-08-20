# Heap Lab

Self-contained labs for ptmalloc misuse, one per glibc version.

- `glibc_2.35/` — Ubuntu 22.04 (glibc 2.35)
- `glibc_2.43/` — Ubuntu 26.04 (glibc 2.43)

Each lab is independent. Build and run from within its directory:

    cd glibc_2.35
    ./build.sh      # build the image (heaplab-2.35)
    ./run.sh        # build if needed, then attach the container

## Sources and binaries

`src/` is mounted read-write into the container, so editing a `.c` inside the
container (or on the host) persists. Binaries are compiled from `src/*.c` into
`/lab/bin/` (host-gitignored, rebuilt, never committed).

The container rebuilds on attach, so `bin/` always tracks the current `src/`.
Recompile manually anytime with `make -C /lab build`.

Add a challenge by dropping a `.c` into a lab's `src/`; no other edits needed.
