<div align = "center">

# `LibCPU`
![GitHub](https://img.shields.io/github/license/Cach30verfl0w/libcpu) ![GitHub issues](https://img.shields.io/github/issues/Cach30verfl0w/libcpu) ![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/Cach30verfl0w/libcpu) ![GitHub commit activity (branch)](https://img.shields.io/github/commit-activity/y/Cach30verfl0w/libcpu) ![GitHub last commit (branch)](https://img.shields.io/github/last-commit/Cach30verfl0w/libcpu/main)
![GitHub pull requests](https://img.shields.io/github/issues-pr/Cach30verfl0w/libcpu)

LibCPU is a library to interact with platform-independent and platform-dependant features of the CPU. Subproject of [`OverflowOS`](https://github.com/Cach30verfl0w/OverflowOS)

</div>

## Architectures
Currently, I try to support the architectures listed below. Currently, I'm only working on the x86_64 Support, but x86, ARM and AArch64 are following. In the following table you can see the status of every supported architecture
| Architecture  | Status | CPUID | Control Registers | GDT | IDT            |
|---------------|----------------|----------------|------------------|----------------|----------------------------|
| x86_64        | 🚧 In progress | ✅ Finished     | ✅ Finished      | ✅ Finished     | ✅ Finished              |
| x86           | 🚧 In progress | ✅ Finished     | ✅ Finished      | ✅ Untested     | Planned       |
| ARM           | 📌 Planned     | Planned        | Planned          | Not available  | Not available |
| ARM64/AArch64 | 🚧 In progress | Planned        | Planned          | Not available  | Not available |

## Credits
I have to give some credits for a few assembly instructions or information about architectures and code design ideas. Here is a list.
- [set_cs](https://github.com/rust-osdev/x86_64/blob/master/src/instructions/segmentation.rs#L74) ([Source in LibCPU](https://github.com/Cach30verfl0w/libcpu/blob/main/src/x86/mod.rs#L290)) function from [x86_64](https://github.com/rust-osdev/x86_64)

## Related projects
I found some projects that are related to this. A few of them are written in a different language, but you can check out them too. Here is a list with them.
- [libcpu (kOS Project)](https://github.com/kos-project/libcpu) - Freestanding cross-architecture API for managing CPUs (by [KitsuneAlex](https://github.com/KitsuneAlex))
- [x86_64](https://github.com/rust-osdev/x86_64) - Library to program x86_64 hardware (by [rust-osdev](https://github.com/rust-osdev))
