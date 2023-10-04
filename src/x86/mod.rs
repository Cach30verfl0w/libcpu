use core::arch::asm;
use core::fmt::{Display, Formatter};
use bit_field::BitField;
use bitflags::bitflags;
use crate::{cpu_register, cpu_features, MemoryAddress};
use crate::x86::cpuid::CPUIDRequest;
use crate::Register;

mod macros;
mod cpuid;
pub mod gdt;
pub mod idt;

/// This structure represents the privilege level for the descriptor. x86 and x86_64 CPUs are
/// providing a few rings, but only 2 are used in Production-ready operating systems.
///
/// Here is a short explanation of all privilege levels:
/// - [PrivilegeLevel::KernelSpace] - This is the ring for the Kernel mode. Least protection and
/// maximal access to hardware resources. A bootloader or kernel uses that mode.
/// - [PrivilegeLevel::Ring1] - This is a ring for device drivers. It offers more protection, but
/// not the level of protection as Ring 3. (This ring is not used by almost all operating systems)
/// - [PrivilegeLevel::Ring2] - This is a ring for device drivers. It offers more protection, but
/// not the level of protection as Ring 3. It's the same like Ring 2. (This ring is not used by
/// almost all operating systems)
/// - [PrivilegeLevel::UserSpace] - This is the Userspace/Userland ring. This ring ist used by the
/// most operating systems for running applications. This ring grant the least privileges but the
/// highest protection by the hardware. The communication with the hardware resources is handled
/// over the kernel with System Calls.
///
/// # See also
/// - [CPU Security Rings](https://wiki.osdev.org/Security#Rings) by [OSDev.org](https://wiki.osdev.org/)
/// - [Global Descriptor Table](https://wiki.osdev.org/Global_Descriptor_Table#Segment_Descriptor)
/// by [OSDev.org](https://wiki.osdev.org/)
/// - [Protection Ring](https://en.wikipedia.org/wiki/Protection_ring) by
/// [Wikipedia](https://wikipedia.org)
#[repr(u8)]
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub enum PrivilegeLevel {
    /// This is the ring for the Kernel mode. Least protection and maximal access to hardware
    /// resources. A bootloader or kernel uses that mode.
    ///
    /// # See also
    /// - [Ring 0](https://wiki.osdev.org/Security#Ring_0) by [OSDev.org](https://wiki.osdev.org/)
    KernelSpace = 0b0000_0000,

    /// This is a ring for device drivers. It offers more protection, but not the level of
    /// protection as Ring 3. (This ring is not used by almost all operating systems)
    ///
    /// # See also
    /// - [Rings 1 and 2](https://wiki.osdev.org/Security#Rings_1_and_2) by [OSDev.org](https://wiki.osdev.org/)
    Ring1 = 0b0010_0000,

    /// This is a ring for device drivers. It offers more protection, but not the level of
    /// protection as Ring 3. It's the same like Ring 2. (This ring is not used by almost all
    /// operating systems)
    ///
    /// # See also
    /// - [Rings 1 and 2](https://wiki.osdev.org/Security#Rings_1_and_2) by [OSDev.org](https://wiki.osdev.org/)
    Ring2 = 0b0100_0000,

    /// This is the Userspace/Userland ring. This ring ist used by the most operating systems for
    /// running applications. This ring grant the least privileges but the highest protection by
    /// the hardware. The communication with the hardware resources is handled over the kernel
    /// with System Calls.
    ///
    /// # See also
    /// - [Ring 3](https://wiki.osdev.org/Security#Ring_3) by [OSDev.org](https://wiki.osdev.org/)
    UserSpace = 0b0110_0000,
}

// This code just implements the Display trait into the privilege level over the Debug trait.
impl Display for PrivilegeLevel {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{:?}", self)
    }
}

/// This implementation is used to convert a bits into the privilege level enum. This function is
/// used in [SegmentSelector::privilege_level]
impl From<u16> for PrivilegeLevel {
    #[must_use]
    fn from(value: u16) -> Self {
        match value {
            0x0 => Self::KernelSpace,
            0x1 => Self::Ring1,
            0x2 => Self::Ring2,
            0x4 => Self::UserSpace,
            _ => panic!("Invalid privilege level {}", value),
        }
    }
}

/// This enum identifies which descriptor table is used in the [SegmentSelector]. You can choose
/// between the [GDT](https://wiki.osdev.org/Global_Descriptor_Table) and the
/// [LDT](https://wiki.osdev.org/Local_Descriptor_Table)
///
/// - [DescriptorTable::GDT] - This value identifies the Global Descriptor Table (GDT)
/// - [DescriptorTable::LDT] - This value identifies the Local Descriptor Table (LDT)
///
/// # See also
/// - [Global Descriptor Table](https://wiki.osdev.org/Global_Descriptor_Table) by
/// [OSDev.org](https://wiki.osdev.org/)
/// - [Local Descriptor Table](https://wiki.osdev.org/Local_Descriptor_Table) by
/// [OSDev.org](https://wiki.osdev.org/)
/// - [Segment Selector](https://wiki.osdev.org/Segment_Selector) by
/// [OSDev.org](https://wiki.osdev.org/)
#[repr(u8)]
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Default)]
pub enum DescriptorTable {
    /// This value identifies the Global Descriptor Table (GDT)
    ///
    /// # See also
    /// - [Global Descriptor Table](https://wiki.osdev.org/Global_Descriptor_Table) by
    /// [OSDev.org](https://wiki.osdev.org/)
    #[default]
    GDT = 0b0000,

    /// This value identifies the Local Descriptor Table (LDT)
    ///
    /// # See also
    /// - [Local Descriptor Table](https://wiki.osdev.org/Local_Descriptor_Table) by
    /// [OSDev.org](https://wiki.osdev.org/)
    LDT = 0b1000,
}

/// This code just implements the Display trait into the descriptor table over the Debug trait.
impl Display for DescriptorTable {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{:?}", self)
    }
}

/// This implementation is used to convert a bit into to the table enum. This function is used in
/// [SegmentSelector::table]
impl From<bool> for DescriptorTable {
    #[must_use]
    fn from(value: bool) -> Self {
        match value {
            false => Self::GDT,
            true => Self::LDT,
        }
    }
}

/// This implementation is used to convert the table enum into a bit. This function is used in
/// [SegmentSelector::set_table]
impl From<DescriptorTable> for bool {
    #[must_use]
    fn from(value: DescriptorTable) -> Self {
        match value {
            DescriptorTable::GDT => false,
            DescriptorTable::LDT => true,
        }
    }
}

/// This structure represents the x86_64 and IA-32 specific Segment Selector data structure with a
/// size of 16 bit. It's used in Protected and Long mode. The value of the descriptor identified a
/// segment in the [LDT](https://wiki.osdev.org/Local_Descriptor_Table) or
/// [GDT](https://wiki.osdev.org/Global_Descriptor_Table).
///
/// # See also
/// - [Segment Selector](https://wiki.osdev.org/Segment_Selector) by
/// [OSDev.org](https://wiki.osdev.org/)
#[repr(transparent)]
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Hash, Default)]
pub struct SegmentSelector(pub u16);

impl SegmentSelector {
    /// This function creates the segment selector by the single values of the entry index, type of
    /// the table and the privilege level of the selector.
    ///
    /// - `index` - The index of the entry in the table (Last 3 bits are moved away)
    /// - `table` - The type of the descriptor table in that the entry is located
    /// - `privilege` - The requested privilege level. This value determines if the selector is
    /// valid during permission checks
    ///
    /// - [Segment Selector](https://wiki.osdev.org/Segment_Selector) by
    /// [OSDev.org](https://wiki.osdev.org/)
    #[inline]
    #[must_use]
    pub fn new(index: u16, table: DescriptorTable, privilege: PrivilegeLevel) -> Self {
        Self((index << 3) | (table as u16) | (privilege as u16 >> 5))
    }

    /// This function replaces the privilege level with the function-specific privilege level.
    ///
    /// # See also
    /// - [CPU Security Rings](https://wiki.osdev.org/Security#Rings) by
    /// [OSDev.org](https://wiki.osdev.org/)
    /// - [Global Descriptor Table](https://wiki.osdev.org/Global_Descriptor_Table#Segment_Descriptor)
    /// by [OSDev.org](https://wiki.osdev.org/)
    /// - [Protection Ring](https://en.wikipedia.org/wiki/Protection_ring) by
    /// [Wikipedia](https://wikipedia.org)
    /// - [PrivilegeLevel] (Source Code)
    #[inline]
    pub fn set_privilege_level(&mut self, level: PrivilegeLevel) {
        self.0.set_bits(0..2, level as u16);
    }

    /// This function returns the privilege level, set by the creator of this selector.
    ///
    /// # See also
    /// - [CPU Security Rings](https://wiki.osdev.org/Security#Rings) by
    /// [OSDev.org](https://wiki.osdev.org/)
    /// - [Global Descriptor Table](https://wiki.osdev.org/Global_Descriptor_Table#Segment_Descriptor)
    /// by [OSDev.org](https://wiki.osdev.org/)
    /// - [Protection Ring](https://en.wikipedia.org/wiki/Protection_ring) by
    /// [Wikipedia](https://wikipedia.org)
    /// - [PrivilegeLevel] (Source Code)
    #[inline]
    #[must_use]
    pub fn privilege_level(&self) -> PrivilegeLevel {
        PrivilegeLevel::from(self.0.get_bits(0..2))
    }

    /// This function replaces the descriptor table with the function-specific descriptor table.
    ///
    /// # See also
    /// - [Segment Selector](https://wiki.osdev.org/Segment_Selector) by
    /// [OSDev.org](https://wiki.osdev.org/)
    /// - [DescriptorTable] (Source Code)
    #[inline]
    pub fn set_table(&mut self, descriptor_table: DescriptorTable) {
        self.0.set_bit(2, descriptor_table.into());
    }

    /// This function returns the descriptor set, set by the creator of this selector.
    ///
    /// # See also
    /// - [Segment Selector](https://wiki.osdev.org/Segment_Selector) by
    /// [OSDev.org](https://wiki.osdev.org/)
    /// - [DescriptorTable] (Source Code)
    #[inline]
    #[must_use]
    pub fn table(&self) -> DescriptorTable {
        DescriptorTable::from(self.0.get_bit(2))
    }

    /// This function replaces the descriptor index with the function-specific descriptor index.
    #[inline]
    pub fn set_index(&mut self, index: u16) {
        self.0.set_bits(0..16, index);
    }

    /// This function returns the descriptor index, set by the creator of this selector.
    #[inline]
    #[must_use]
    pub fn index(&self) -> u16 {
        self.0 >> 3
    }
}

/// This structure represents the pointer structure to a descriptor table like the GDT or IDT. These
/// pointers are used in the `lidt` and `lgdt` instruction.
///
/// - `base` - This field represents the linear base address (not the physical address) to the table
/// (size is depending on the target processor architecture)
/// - `size` - This field represents the size of the table in bytes. (subtracted by 1)
///
/// # See also
/// - [Global Descriptor Table](https://wiki.osdev.org/Global_Descriptor_Table#GDTR) by
/// [OSDev.org](https://wiki.osdev.org)
/// - [Interrupt Descriptor Table](https://wiki.osdev.org/Interrupt_Descriptor_Table#IDTR) by
/// [OSDev.org](https://wiki.osdev.org)
/// - [gdt::GlobalDescriptorTable::as_ptr()] (Source Code)
#[repr(C, packed)]
#[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
pub struct DescriptorTablePointer {
    /// This field represents the size of the table in bytes. (subtracted by 1)
    ///
    /// # See also
    /// - [Global Descriptor Table](https://wiki.osdev.org/Global_Descriptor_Table#GDTR) by
    /// [OSDev.org](https://wiki.osdev.org)
    /// - [Interrupt Descriptor Table](https://wiki.osdev.org/Interrupt_Descriptor_Table#IDTR) by
    /// [OSDev.org](https://wiki.osdev.org)
    pub size: u16,

    ///  This field represents the linear base address (not the physical address) to the table
    /// (size is depending on the target processor architecture)
    ///
    /// # See also
    /// - [Global Descriptor Table](https://wiki.osdev.org/Global_Descriptor_Table#GDTR) by
    /// [OSDev.org](https://wiki.osdev.org)
    /// - [Interrupt Descriptor Table](https://wiki.osdev.org/Interrupt_Descriptor_Table#IDTR) by
    /// [OSDev.org](https://wiki.osdev.org)
    pub base: MemoryAddress,
}

// https://github.com/rust-osdev/x86_64/blob/master/src/instructions/segmentation.rs#L74
pub fn set_cs(selector: SegmentSelector) {
    unsafe {
        asm!(
        "push {sel}",
        "lea {tmp}, [1f + rip]",
        "push {tmp}",
        "retfq",
        "1:",
        sel = in(reg) u64::from(selector.0),
        tmp = lateout(reg) _,
        options(preserves_flags),
        );
    }
}

cpu_register!(ds, "ds");
cpu_register!(es, "es");
cpu_register!(ss, "ss");
cpu_register!(fs, "fs");
cpu_register!(gs, "gs");

bitflags! {
    #[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct CR0Flags: Register {
        const PROTECTED_MODE_ENABLE = 1 << 0;
        const MONITOR_CO_PROCESSOR  = 1 << 1;
        const X86_FPU_EMULATION     = 1 << 2;
        const TASK_SWITCHED         = 1 << 3;
        const EXTENSION_TYPE        = 1 << 4;
        const NUMERIC_ERROR         = 1 << 5;
        const WRITE_PROTECTED       = 1 << 16;
        const ALIGNMENT_CHECK       = 1 << 18;
        const NOT_WRITE_THROUGH     = 1 << 29;
        const CACHE_DISABLE         = 1 << 30;
        const PAGING                = 1 << 31;
    }
}

cpu_register!(cr0, "cr0", CR0Flags);

bitflags! {
    #[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct CR3Flags: Register {
        const PAGE_LEVEL_WRITE_THROUGH = 1 << 3;
        const PAGE_LEVEL_CACHE_DISABLE = 1 << 4;
    }
}

cpu_register!(cr3, "cr3", CR3Flags);

bitflags! {
    #[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub struct CR4Flags: Register {
        const VME                        = 1 << 0;
        const PVI                        = 1 << 1;
        const TIMESTAMP_DISABLE          = 1 << 2;
        const DEBUGGING_EXTENSIONS       = 1 << 3;
        const PAGE_SIZE_EXTENSION        = 1 << 4;
        const PHYSCIAL_ADDRESS_EXTENSION = 1 << 5;
        const MACHINE_CHECK_EXCEPTION    = 1 << 6;
        const PAGE_GLOBAL_ENABLED        = 1 << 7;
        const PCE                        = 1 << 8;
        const OSSupportForFXSR           = 1 << 9;
        const OSSupportXMMExcept         = 1 << 10;
        const UMIP                       = 1 << 11;
        const VIRTUAL_MACHINE_EXT_ENABLE = 1 << 13;
        const SAFER_MODE_EXT_ENABLE      = 1 << 14;
        const FSGSBASE                   = 1 << 16;
        const PCID_ENABLE                = 1 << 17;
        const OSXSAVE_ENABLE             = 1 << 18;
        const SMEP                       = 1 << 20;
        const SMAP                       = 1 << 21;
        const ProtectionKeyEnable        = 1 << 22;
        const ControlFlowEnforcement     = 1 << 23;
        const PKS                        = 1 << 34;
    }
}

cpu_register!(cr4, "cr4", CR4Flags);

cpu_features! {
    #[allow(non_camel_case_types)]
    #[derive(Clone, Copy, Ord, PartialOrd, Eq, PartialEq, Debug, Hash)]
    pub enum CPUFeature {
        SSE3              (ecx, "SSE3", CPUIDRequest::Features) = 1 << 0,
        PCLMUL            (ecx, "Carry-Less Multiplication", CPUIDRequest::Features) = 1 << 1,
        DTES64            (ecx, "64-Bit Debug Store", CPUIDRequest::Features) = 1 << 2,
        MONITOR           (ecx, "MONITOR and MWAIT instructions", CPUIDRequest::Features) = 1 << 3,
        DS_CPL            (ecx, "CPL-qualified Debug Store", CPUIDRequest::Features) = 1 << 4,
        VMX               (ecx, "Virtual Machine Extensions", CPUIDRequest::Features) = 1 << 5,
        SMX               (ecx, "Safer Mode Extensions", CPUIDRequest::Features) = 1 << 6,
        EST               (ecx, "Enhanced SpeedStep", CPUIDRequest::Features) = 1 << 7,
        TM2               (ecx, "Thermal Monitor 2", CPUIDRequest::Features) = 1 << 8,
        SSSE3             (ecx, "Supplemental SSE3", CPUIDRequest::Features) = 1 << 9,
        CID               (ecx, "L1 Context ID", CPUIDRequest::Features) = 1 << 10,
        SDBG              (ecx, "Silicon Debug Interface", CPUIDRequest::Features) = 1 << 11,
        FMA               (ecx, "Fused Multiply-Add (FMA3)", CPUIDRequest::Features) = 1 << 12,
        CX16              (ecx, "CMPXCHG1B instruction", CPUIDRequest::Features) = 1 << 13,
        XTPR              (ecx, "Can disable sending task priority messages", CPUIDRequest::Features) = 1 << 14,
        PDCM              (ecx, "Prefmon & Debug Capability", CPUIDRequest::Features) = 1 << 15,
        PCID              (ecx, "Process Context Identifiers", CPUIDRequest::Features) = 1 << 17,
        DCA               (ecx, "Direct Cache Access for DMA writes", CPUIDRequest::Features) = 1 << 18,
        SSE4_1            (ecx, "SSE4.1 instructions", CPUIDRequest::Features) = 1 << 19,
        SSE4_2            (ecx, "SSE4.2 instructions", CPUIDRequest::Features) = 1 << 20,
        X2APIC            (ecx, "x2APIC (enhanced APIC)", CPUIDRequest::Features) = 1 << 21,
        MOVBE             (ecx, "MOVBE instruction", CPUIDRequest::Features) = 1 << 22,
        POPCNT            (ecx, "POPCNT instruction", CPUIDRequest::Features) = 1 << 23,
        TSCDeadline       (ecx, "APIC implements one-shot operation using a TSC deadline value", CPUIDRequest::Features) = 1 << 24,
        AES               (ecx, "Hardware-accelerated AES Instruction Set", CPUIDRequest::Features) = 1 << 25,
        XSAVE             (ecx, "Extensible processor state restore instructions", CPUIDRequest::Features) = 1 << 26,
        OSXSAVE           (ecx, "XSAVE enabled by OS", CPUIDRequest::Features) = 1 << 27,
        AVX               (ecx, "Advanced Vector Extensions (256-bit SIMD)", CPUIDRequest::Features) = 1 << 28,
        F16C              (ecx, "Floating-point conversion instructions to/from FP16 format", CPUIDRequest::Features) = 1 << 29,
        RDRAND            (ecx, "RDRAND (HRNG) feature", CPUIDRequest::Features) = 1 << 30,
        HYPERVISOR        (ecx, "Hypervisor is present", CPUIDRequest::Features) = 1 << 31,
        FPU               (edx, "Onboard x87 FPU", CPUIDRequest::Features) = 1 << 0,
        VME               (edx, "Virtual 8086 Mode Extensions", CPUIDRequest::Features) = 1 << 1,
        DE                (edx, "Debugging Extensions", CPUIDRequest::Features) = 1 << 2,
        PSE               (edx, "Page Size Extension (4MB pages)", CPUIDRequest::Features) = 1 << 3,
        TSC               (edx, "Time Stamp Counter and RDTSC instruction", CPUIDRequest::Features) = 1 << 4,
        MSR               (edx, "Model-Specific Registers and RDMSR/WRMSR instructions", CPUIDRequest::Features) = 1 << 5,
        PAE               (edx, "Physical Address Extension", CPUIDRequest::Features) = 1 << 6,
        MCE               (edx, "Machine Check Exception", CPUIDRequest::Features) = 1 << 7,
        CX8               (edx, "CMPXCHG8B instruction", CPUIDRequest::Features) = 1 << 8,
        APIC              (edx, "Onboard APIC", CPUIDRequest::Features) = 1 << 9,
        SEP               (edx, "SYSENTER and SYSEXIT fast System Call instuctions", CPUIDRequest::Features) = 1 << 11,
        MTRR              (edx, "Memory Type Range Registers", CPUIDRequest::Features) = 1 << 12,
        PGE               (edx, "Page Global Enable bit", CPUIDRequest::Features) = 1 << 13,
        MCA               (edx, "Machine Check Architecture", CPUIDRequest::Features) = 1 << 14,
        CMOV              (edx, "Conditional move instructions", CPUIDRequest::Features) = 1 << 15,
        PAT               (edx, "Page Attribute Table", CPUIDRequest::Features) = 1 << 16,
        PSE36             (edx, "36-bit Page Size Extension", CPUIDRequest::Features) = 1 << 17,
        PSN               (edx, "Processor Serial Number enabled", CPUIDRequest::Features) = 1 << 18,
        CLFLUSH           (edx, "CLFLUSH cache line flush instruction", CPUIDRequest::Features) = 1 << 19,
        NX_Itanium        (edx, "Non-Executable Bit (Itanium only)", CPUIDRequest::Features) = 1 << 20,
        DS                (edx, "Debug Store (Save trace of jumps)", CPUIDRequest::Features) = 1 << 21,
        ACPI              (edx, "Onboard Thermal Control MSRs for ACPI", CPUIDRequest::Features) = 1 << 22,
        MMX               (edx, "MMX instructions (64-bit SIMD)", CPUIDRequest::Features) = 1 << 23,
        FXSR              (edx, "FXSAVE and FXRSTOR instructions", CPUIDRequest::Features) = 1 << 24,
        SSE               (edx, "Streaming SIMD Extensions (128-bit SIMD)", CPUIDRequest::Features) = 1 << 25,
        SSE2              (edx, "SSE2 instructions", CPUIDRequest::Features) = 1 << 26,
        SS                (edx, "CPU Cache implements self-snoop", CPUIDRequest::Features) = 1 << 27,
        HTT               (edx, "Mac APIC IDs reserved field is valid", CPUIDRequest::Features) = 1 << 28,
        TM                (edx, "Thermal Monitor automatically limits temperature", CPUIDRequest::Features) = 1 << 29,
        IA64              (edx, "IA64 Processor emulating x86", CPUIDRequest::Features) = 1 << 30,
        PBE               (edx, "Pending Break Enable wakeup capacity", CPUIDRequest::Features) = 1 << 31,
        FSGSBase          (ebx, "Access to base of %fs and %gs", CPUIDRequest::ExtendedFeatures1) = 1 << 0,
        SGX               (ebx, "Software Guard Extensions", CPUIDRequest::ExtendedFeatures1) = 1 << 2,
        BMI1              (ebx, "Bit Manipulation Instruction Set 1", CPUIDRequest::ExtendedFeatures1) = 1 << 3,
        HLE               (ebx, "TSX Hardware Lock Elision", CPUIDRequest::ExtendedFeatures1) = 1 << 4,
        AVX2              (ebx, "Advanced Vector Extensions 2 (AVX2)", CPUIDRequest::ExtendedFeatures1) = 1 << 5,
        FDP_EXCPTN_ONLY   (ebx, "x86 FPU Data Pointer register updated on exceptions only", CPUIDRequest::ExtendedFeatures1) = 1 << 6,
        SMEP              (ebx, "Supervisor Mode Execution Prevention", CPUIDRequest::ExtendedFeatures1) = 1 << 7,
        BMI2              (ebx, "Bit Manipulation Instruction Set 2", CPUIDRequest::ExtendedFeatures1) = 1 << 8,
        ERMS              (ebx, "Enhanced REP MOVSB/STOSB", CPUIDRequest::ExtendedFeatures1) = 1 << 9,
        INVPCID           (ebx, "INVPCID instruction", CPUIDRequest::ExtendedFeatures1) = 1 << 10,
        RTM               (ebx, "TSX Restricted Transactional Memory", CPUIDRequest::ExtendedFeatures1) = 1 << 11,
        PQM               (ebx, "Intel RDT Monitoring or AMD Platform QOS Monitoring", CPUIDRequest::ExtendedFeatures1) = 1 << 12,
        MPX               (ebx, "Intel Memory Protection Extensions", CPUIDRequest::ExtendedFeatures1) = 1 << 14,
        AVX512F           (ebx, "AVX-512 Foundation", CPUIDRequest::ExtendedFeatures1) = 1 << 16,
        AVX512DQ          (ebx, "AVX-512 Doubleword and Quadword instructions", CPUIDRequest::ExtendedFeatures1) = 1 << 17,
        RDSEED            (ebx, "RDSEED instruction", CPUIDRequest::ExtendedFeatures1) = 1 << 18,
        ADX               (ebx, "Intel Multi-Precision Add-Carry Instruction Extensions", CPUIDRequest::ExtendedFeatures1) = 1 << 19,
        SMAP              (ebx, "Supervisor Mode Access Prevention", CPUIDRequest::ExtendedFeatures1) = 1 << 20,
        AVX512_IFMA       (ebx, "AVS-512 Integer Fusd Multiply-Add Instructions", CPUIDRequest::ExtendedFeatures1) = 1 << 21,
        PCOMMIT           (ebx, "PCOMMIT intruction (deprecated)", CPUIDRequest::ExtendedFeatures1) = 1 << 22,
        CFLUSHOPT         (ebx, "CFLUSHOPT instruction", CPUIDRequest::ExtendedFeatures1) = 1 << 23,
        CLWB              (ebx, "CLWB (Cache Line Writeback) instruction", CPUIDRequest::ExtendedFeatures1) = 1 << 24,
        PT                (ebx, "Intel Processor Trace", CPUIDRequest::ExtendedFeatures1) = 1 << 25,
        AVX512PF          (ebx, "AVX-512 Prefetch Instructions", CPUIDRequest::ExtendedFeatures1) = 1 << 26,
        AVX512ER          (ebx, "AVX-512 Exponential and Reciprocal instructions", CPUIDRequest::ExtendedFeatures1) = 1 << 27,
        AVX512CD          (ebx, "AVX-512 Conflict Detection Instructions", CPUIDRequest::ExtendedFeatures1) = 1 << 28,
        SHA               (ebx, "SHA-1 and SHA-256 Extensions", CPUIDRequest::ExtendedFeatures1) = 1 << 29,
        AVX512BW          (ebx, "AVX-512 Byte and Word instructions", CPUIDRequest::ExtendedFeatures1) = 1 << 30,
        AVX512VI          (ebx, "AVX-512 Vector Length Extensions", CPUIDRequest::ExtendedFeatures1) = 1 << 31,
        PreFetchWT1       (ecx, "PREFETCHWT1 instruction", CPUIDRequest::ExtendedFeatures1) = 1 << 0,
        AVX512VBMI        (ecx, "AVX-512 Vector Bit Manipulation Instructions", CPUIDRequest::ExtendedFeatures1) = 1 << 1,
        UMIP              (ecx, "User-Mode Instruction Prevention", CPUIDRequest::ExtendedFeatures1) = 1 << 2,
        PKU               (ecx, "Memory Protection Keys for User-Mode Pages", CPUIDRequest::ExtendedFeatures1) = 1 << 3,
        OSPKE             (ecx, "PKU enabled by OS", CPUIDRequest::ExtendedFeatures1) = 1 << 4,
        WAITKG            (ecx, "Timed pause and user-level monitor/wait instructions", CPUIDRequest::ExtendedFeatures1) = 1 << 5,
        AVX512VBMI2       (ecx, "AVS-512 Vector Bit Manipulation Instructions 2", CPUIDRequest::ExtendedFeatures1) = 1 << 6,
        ShadowStack       (ecx, "Intel Control-Flow Enforcement Technology/Shadow Stack", CPUIDRequest::ExtendedFeatures1) = 1 << 7,
        GFNI              (ecx, "Galois Field Instructions", CPUIDRequest::ExtendedFeatures1) = 1 << 8,
        VAES              (ecx, "Vector AES Instruction Set", CPUIDRequest::ExtendedFeatures1) = 1 << 9,
        VPCLMULQDQ        (ecx, "CLMUL Instruction Set", CPUIDRequest::ExtendedFeatures1) = 1 << 10,
        AVX512VNNI        (ecx, "AVX-512 Vector Neural Network Instructions", CPUIDRequest::ExtendedFeatures1) = 1 << 11,
        AVX512BITALG      (ecx, "AVX-512 BITALG Instructions", CPUIDRequest::ExtendedFeatures1) = 1 << 12,
        TME               (ecx, "Total Memory Encryption", CPUIDRequest::ExtendedFeatures1) = 1 << 13,
        AVX512VPOPCNTDQ   (ecx, "AVX-512 Vector Population ount Dobule and Quad Word", CPUIDRequest::ExtendedFeatures1) = 1 << 14,
        LA57              (ecx, "5-Level Paging (57 Address Bits)", CPUIDRequest::ExtendedFeatures1) = 1 << 16,
        RDPID             (ecx, "RDPID (Read Processor ID) Instruction", CPUIDRequest::ExtendedFeatures1) = 1 << 22,
        KL                (ecx, "AES Key Locker", CPUIDRequest::ExtendedFeatures1) = 1 << 23,
        BusLockDetect     (ecx, "Bus Lock Debug Exceptions", CPUIDRequest::ExtendedFeatures1) = 1 << 24,
        CIDEMOTE          (ecx, "CLDEMOTE (Cache Line Demote) Instruction", CPUIDRequest::ExtendedFeatures1) = 1 << 25,
        MOVDIRI           (ecx, "MOVDIRI Instruction", CPUIDRequest::ExtendedFeatures1) = 1 << 27,
        MOBDIR64B         (ecx, "MOBDIR64B (64-Byte Direct Store) Instruction", CPUIDRequest::ExtendedFeatures1) = 1 << 28,
        ENQCMD            (ecx, "Enqueue Stores and EMQCMD/EMCCMDS instructions", CPUIDRequest::ExtendedFeatures1) = 1 << 29,
        SGXLC             (ecx, "SGX Launch Confgiuration supported", CPUIDRequest::ExtendedFeatures1) = 1 << 30,
        PKS               (ecx, "Protection Keys for Supervisor_mode Pages", CPUIDRequest::ExtendedFeatures1) = 1 << 31,
        SGXKeys           (edx, "Attestation Services for Intel Software Guard Extensions", CPUIDRequest::ExtendedFeatures1) = 1 << 1,
        AVX512_4VNNIW     (edx, "AVX-512 4-Register Neural Network Instructions", CPUIDRequest::ExtendedFeatures1) = 1 << 2,
        AVX512_4FMAPS     (edx, "AVX-512 4-Register Multiply Accumolation Single Precision", CPUIDRequest::ExtendedFeatures1) = 1 << 3,
        FSRM              (edx, "Fast Short REP MOVSB", CPUIDRequest::ExtendedFeatures1) = 1 << 4,
        UINTR             (edx, "User Inter-Processor Interrupts", CPUIDRequest::ExtendedFeatures1) = 1 << 5,
        AVX512VP2INTERSECT(edx, "AVX-512 Vector Insertion Instruction on 32/64-Bit Integers", CPUIDRequest::ExtendedFeatures1) = 1 << 8,
        SRDBS_CTRL        (edx, "Special Register Buffer Data Sampling Mitigations", CPUIDRequest::ExtendedFeatures1) = 1 << 9,
        MCClear           (edx, "VERW Instruction clears CPU buffers", CPUIDRequest::ExtendedFeatures1) = 1 << 10,
        RTMAlwaysAbort    (edx, "All TSX transactions are aborted", CPUIDRequest::ExtendedFeatures1) = 1 << 11,
        TSXForceAbort     (edx, "TSX Force Abort", CPUIDRequest::ExtendedFeatures1) = 1 << 13,
        SERIALIZE         (edx, "SERIALIZE instruction", CPUIDRequest::ExtendedFeatures1) = 1 << 14,
        HYBRID            (edx, "Mixture of CPU types in Processor Topology", CPUIDRequest::ExtendedFeatures1) = 1 << 15,
        TSXLDTRK          (edx, "TSX load address tracking suspend/resume instructions", CPUIDRequest::ExtendedFeatures1) = 1 << 16,
        PCONFIG           (edx, "Platform Configuration (Memory Encryption Technologies Instruction)", CPUIDRequest::ExtendedFeatures1) = 1 << 18,
        IBR               (edx, "Architectural Last Branch Records", CPUIDRequest::ExtendedFeatures1) = 1 << 19,
        CET_IBT           (edx, "Control Flow Enforcement (CET) Indirect Branch Tracking", CPUIDRequest::ExtendedFeatures1) = 1 << 20,
        AMXBF16           (edx, "AMX Tile Computation on bfloat16 Numbers", CPUIDRequest::ExtendedFeatures1) = 1 << 22,
        AVS512FP16        (edx, "AVX-512 Half-Precision Floating-Point Arithmetic Instructions", CPUIDRequest::ExtendedFeatures1) = 1 << 23,
        AMXTile           (edx, "AMX Tile Load/Store Instructions", CPUIDRequest::ExtendedFeatures1) = 1 << 24,
        AMXInt8           (edx, "AMD Tile Computation on 8-bit Integers", CPUIDRequest::ExtendedFeatures1) = 1 << 25,
        SpecControl       (edx, "Indirect Branch Restricted Speculation and Indirect Branch Prediction Barrier", CPUIDRequest::ExtendedFeatures1) = 1 << 26,
        STIBP             (edx, "Single Thread Indirect Branch Predictor", CPUIDRequest::ExtendedFeatures1) = 1 << 27,
        L1DFlush          (edx, "IA32 Flush Command MSR", CPUIDRequest::ExtendedFeatures1) = 1 << 28,
        SSBD              (edx, "Speculative Store Bypass Disable", CPUIDRequest::ExtendedFeatures1) = 1 << 31,
        SHA512Extensions  (eax, "SHA-512 Extensions", CPUIDRequest::ExtendedFeatures2) = 1 << 0,
        SM3               (eax, "SM3 Hash Extensions", CPUIDRequest::ExtendedFeatures2) = 1 << 1,
        SM4               (eax, "SM4 Cipher Extensions", CPUIDRequest::ExtendedFeatures2) = 1 << 2,
        RAO_INT           (eax, "Remote Atomic Operations on Integers", CPUIDRequest::ExtendedFeatures2) = 1 << 3,
        AVX_VNNI          (eax, "AVX Vector Neural Network Instrutions", CPUIDRequest::ExtendedFeatures2) = 1 << 4,
        AVX512BF16        (eax, "AVX-512 Instructions for bfloat16 numbers", CPUIDRequest::ExtendedFeatures2) = 1 << 5,
        LASS              (eax, "Linear Address Space Separation", CPUIDRequest::ExtendedFeatures2) = 1 << 6,
        CMPCCXADD         (eax, "CMPccXADD instruction", CPUIDRequest::ExtendedFeatures2) = 1 << 7,
        ARCHPerfMonExt    (eax, "Architectural Performance Monitoring Extended Leaf", CPUIDRequest::ExtendedFeatures2) = 1 << 8,
        FastZeroRepMOVSB  (eax, "Fast zero-length REP MOVSB", CPUIDRequest::ExtendedFeatures2) = 1 << 10,
        FastShortRepSTOSB (eax, "Fast short REP STOSB", CPUIDRequest::ExtendedFeatures2) = 1 << 11,
        FastShortRepCMPSB (eax, "Fast short REP CMBSP and REP SCASB", CPUIDRequest::ExtendedFeatures2) = 1 << 12,
        FRED              (eax, "Flexible Return and Event Delivery", CPUIDRequest::ExtendedFeatures2) = 1 << 17,
        LKGS              (eax, "LKGS Instruction", CPUIDRequest::ExtendedFeatures2) = 1 << 18,
        WRMSRNS           (eax, "WRMSNS Instruction", CPUIDRequest::ExtendedFeatures2) = 1 << 19,
        AMXFP16           (eax, "AMX Instructions for FP16 Numbers", CPUIDRequest::ExtendedFeatures2) = 1 << 21,
        HReset            (eax, "HRESET instruction MSR and Processor History Reset Leaf", CPUIDRequest::ExtendedFeatures2) = 1 << 22,
        LAM               (eax, "Linear Address Masking", CPUIDRequest::ExtendedFeatures2) = 1 << 26,
        MSRList           (eax, "RDMSRLIKST and WRMSRLIST instructions", CPUIDRequest::ExtendedFeatures2) = 1 << 27,
        PPIN              (ebx, "Intel Protected Processor Inventory Number: IA32_PPIN_CTL MSR", CPUIDRequest::ExtendedFeatures2) = 1 << 0,
        PKNDKB            (ebx, "Total Storage Encryption (PBNDKB instruction)", CPUIDRequest::ExtendedFeatures2) = 1 << 1,
        AVX_VNNI_INT8     (edx, "AVX VNNI Int8 Instructions", CPUIDRequest::ExtendedFeatures2) = 1 << 4,
        AVX_NE_CONVERT    (edx, "AVX No-Exception FS Conversion Instructions", CPUIDRequest::ExtendedFeatures2) = 1 << 5,
        AMXComplex        (edx, "AMX Support for complex Tiles", CPUIDRequest::ExtendedFeatures2) = 1 << 8,
        AVX_VNNI_INT16    (edx, "AVX VNNI Int16 Instructions", CPUIDRequest::ExtendedFeatures2) = 1 << 10,
        PREFETCHI         (edx, "Instruction-Cache prefetch Instructions", CPUIDRequest::ExtendedFeatures2) = 1 << 14,
        UserMSR           (edx, "User-Mode MSR Access Instructions", CPUIDRequest::ExtendedFeatures2) = 1 << 15,
        UIRetUIFFromRFlags(edx, "UIRET Instruction set User Interrupt Flags to 1", CPUIDRequest::ExtendedFeatures2) = 1 << 17,
        CET_SSS           (edx, "Control-Flow Enforcement Supervisor Shadow Stack can't be prematurely busy", CPUIDRequest::ExtendedFeatures2) = 1 << 18,
        AVX10             (edx, "AVX10 Converged Vector ISA", CPUIDRequest::ExtendedFeatures2) = 1 << 19,
        APX_F             (edx, "Advanced Performance Extensions Foundation", CPUIDRequest::ExtendedFeatures2) = 1 << 21,
        PFSD              (edx, "Fast Store Forwarding Predictor Disable supported", CPUIDRequest::ExtendedFeatures3) = 1 << 0,
        IPREDDIS          (edx, "IPPRED_DIS controls supported", CPUIDRequest::ExtendedFeatures3) = 1 << 1,
        RRSBACtrl         (edx, "RRSBA behavior disable supported", CPUIDRequest::ExtendedFeatures3) = 1 << 2,
        DPPDU             (edx, "Data Dependent Prefetcher Disable supported", CPUIDRequest::ExtendedFeatures3) = 1 << 3,
        BHICtrl           (edx, "BHI_DIS_S behavior enable supported", CPUIDRequest::ExtendedFeatures3) = 1 << 4,
        MCDT_NO           (edx, "Processor does not exhibit MXCSR configuration dependent timing", CPUIDRequest::ExtendedFeatures3) = 1 << 5,
        Syscall           (edx, "Syscall and Sysret Instructions", CPUIDRequest::ExtendedFeatures4) = 1 << 11,
        NX                (edx, "Non-Executable Bit", CPUIDRequest::ExtendedFeatures4) = 1 << 20,
        FXSROpt           (edx, "FXSAVE/FXRSTOR optimization", CPUIDRequest::ExtendedFeatures4) = 1 << 25,
        GigabytePages     (edx, "1 Gigabyte Pages", CPUIDRequest::ExtendedFeatures4) = 1 << 26,
        RDTSCP            (edx, "RDTSCP instruction", CPUIDRequest::ExtendedFeatures4) = 1 << 27,
        LongMode          (edx, "Long Mode", CPUIDRequest::ExtendedFeatures4) = 1 << 29,
        Ext3dNow          (edx, "Extended 3DNow!", CPUIDRequest::ExtendedFeatures4) = 1 << 30,
        F3DNow            (edx, "3DNow!", CPUIDRequest::ExtendedFeatures4) = 1 << 31,
        LAHF_LM           (ecx, "LAHF/SAHF in Long Mode", CPUIDRequest::ExtendedFeatures4) = 1 << 0,
        CmpLegacy         (ecx, "Hyperthreading is not valid", CPUIDRequest::ExtendedFeatures4) = 1 << 1,
        SecureVM          (ecx, "Secure Virtual Machine", CPUIDRequest::ExtendedFeatures4) = 1 << 2,
        ExtendedAPIC      (ecx, "Extended APIC Space", CPUIDRequest::ExtendedFeatures4) = 1 << 3,
        CR8Legacy         (ecx, "CR8 in 32-bit mode", CPUIDRequest::ExtendedFeatures4) = 1 << 4,
        ABM               (ecx, "Advanced Bit Manipulation", CPUIDRequest::ExtendedFeatures4) = 1 << 5,
        SSE4a             (ecx, "SSE4a", CPUIDRequest::ExtendedFeatures4) = 1 << 6,
        MisalignedSSE     (ecx, "Misaligned SSE Mode", CPUIDRequest::ExtendedFeatures4) = 1 << 7,
        Prefetch3DNow     (ecx, "PREFETCH and PREFETCHW instructions", CPUIDRequest::ExtendedFeatures4) = 1 << 8,
        OSVW              (ecx, "OS Visible Workaround", CPUIDRequest::ExtendedFeatures4) = 1 << 9,
        IBS               (ecx, "Instruction-based Sampling", CPUIDRequest::ExtendedFeatures4) = 1 << 10,
        XOP               (ecx, "XOP Instruction Set", CPUIDRequest::ExtendedFeatures4) = 1 << 11,
        SKINIT            (ecx, "SKINIT/STGI Instructions", CPUIDRequest::ExtendedFeatures4) = 1 << 12,
        WatchdogTimer     (ecx, "Watchdog Timer", CPUIDRequest::ExtendedFeatures4) = 1 << 13,
        LWP               (ecx, "Lightweight Profiling", CPUIDRequest::ExtendedFeatures4) = 1 << 15,
        FMA4              (ecx, "4-Operand Fused Multiply-Add Instructions", CPUIDRequest::ExtendedFeatures4) = 1 << 16,
        TCE               (ecx, "Translation Cache Extension", CPUIDRequest::ExtendedFeatures4) = 1 << 17,
        NodeIdMSR         (ecx, "NodID MSR", CPUIDRequest::ExtendedFeatures4) = 1 << 19,
        TBM               (ecx, "Trailing Bit Manipulation", CPUIDRequest::ExtendedFeatures4) = 1 << 20,
        TopoExt           (ecx, "Topology Extensions", CPUIDRequest::ExtendedFeatures4) = 1 << 22,
        PrefCtrCoe        (ecx, "Core Performance Counter Extensions", CPUIDRequest::ExtendedFeatures4) = 1 << 23,
        PrefCtrNb         (ecx, "Northbridge Performance Counter Extensions", CPUIDRequest::ExtendedFeatures4) = 1 << 24,
        StreamPerfMon     (ecx, "Streaming Performance Monitor Architecture", CPUIDRequest::ExtendedFeatures4) = 1 << 25,
        DBX               (ecx, "Data Breakpoint Extensions", CPUIDRequest::ExtendedFeatures4) = 1 << 26,
        PerfTSC           (ecx, "Performance Timestamp Cointer (PTSC)", CPUIDRequest::ExtendedFeatures4) = 1 << 27,
        PCXL2I            (ecx, "L2I Perf Counter Extensions", CPUIDRequest::ExtendedFeatures4) = 1 << 28,
        MonitorX          (ecx, "MONITORX and MWAITX instructions", CPUIDRequest::ExtendedFeatures4) = 1 << 29,
        AddrMaskExt       (ecx, "Address Mask Extensions to 32 bits for Instruction Breakpoints", CPUIDRequest::ExtendedFeatures4) = 1 << 30
    }
}

#[inline]
pub fn wait_for_interrupts() {
    unsafe {
        asm!("hlt");
    }
}