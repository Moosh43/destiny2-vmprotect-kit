# Notice

This is **reverse-engineering tooling** for interoperability and preservation research. It contains
**no game code** - only scripts and derived address metadata (instruction boundaries and control-flow
edges) for one specific build.

- The MIT license covers the tooling in this repository. It does **not** grant any rights in the game.
- You need your own lawful copy of the game to make a dump. The tools operate only on a dump **you**
  produce from **your** copy.
- The output image is for **static analysis** - it is not a runnable or redistributable game binary,
  and this project does not help produce one.
- A process dump contains your own runtime state (account/session identifiers, machine info). Treat
  a dump as private; don't share it. Share this tooling, not your dump or images built from it.
- Provided as-is, no warranty.
