module ELF2

# Write your package code here.

const EI_MAG0 = 0 #File identification byte 0 index
const ELFMAG0 = 0x7f #Magic number byte 0
const EI_MAG1 = 1 # File identification byte 1 index
const ELFMAG1 = UInt8('E') # Magic number byte 1
const EI_MAG2 = 2 # File identification byte 2 index
const ELFMAG2 = UInt8('L') # Magic number byte 2
const EI_MAG3 = 3 # File identification byte 3 index
const ELFMAG3 = UInt8('F') # Magic number byte 3

# e_indent[EIBCLASS]
const ELFCLASSNONE = 0 #Invalid class
const ELFCLASS32 = 1 #32-bit objects
const ELFCLASS64 = 2 #64-bit objects

# e_ident[EIDATA]
const ELFDATANONE = 0
const ELFDATA2LSB = 1
const ELFDATA2MSB = 2

# e_version constants
const EV_NONE = 0       #Invalid Version
const EV_CURRENT = 1    #Current Version

# e_type constants
const ET_NONE = 0   #No file type
const ET_REL = 1   #Relocatable file
const ET_EXEC = 2   #Executable file
const ET_DYN = 3   #Shared object file
const ET_CORE = 4   #Core file

const ET_LOOS = 0xfe00  #Operating system-specific
const ET_HIOS = 0xfeff  #Operating system-specific
const ET_LOPROC = 0xff00  #Processor-specific
const ET_HIPROC = 0xffff  #Processor-specific

mutable struct Ehdr
    e_ident1::UInt8
    e_ident2::UInt8
    e_ident3::UInt8
    e_ident4::UInt8
    e_class::UInt8
    e_data::UInt8
    e_fversion::UInt8
    e_osabi::UInt8
    e_abiversion::UInt8
    e_pad::UInt8
    e_type::UInt16
    e_machine::UInt16
    e_version::UInt32
    e_entry::UInt64
    e_phoff::UInt64
    e_shoff::UInt64
    e_flags::UInt32
    e_ehsize::UInt16
    e_phentsize::UInt16
    e_phnum::UInt16
    e_shentsize::UInt16
    e_shnum::UInt16
    e_shstrndx::UInt16
    Ehdr() = new()
end

mutable struct Phdr
    p_type::UInt32
    p_flags::UInt32
    p_offset::UInt64
    p_vaddr::UInt64
    p_paddr::UInt64
    p_filesz::UInt64
    p_memsz::UInt64
    p_align::UInt64
    Phdr() = new()
end

mutable struct ELF
    ehdr::Ehdr
    ELF() = new()
end

function read_phdr(io::IOStream)
    phdr = Phdr()
    phdr.p_type = read(io, UInt32)
    phdr.p_flags = read(io, UInt32)
    phdr.p_vaddr = read(io, UInt64)
    phdr.p_paddr = read(io, UInt64)
    phdr.p_filesz = read(io, UInt64)
    phdr.p_memsz = read(io, UInt64)
    phdr.p_align = read(io, UInt64)
end

function read_ehdr(io::IOStream)
    ehdr = Ehdr()
    ehdr.e_ident1 = read(io, UInt8)
    ehdr.e_ident2 = read(io, UInt8)
    ehdr.e_ident3 = read(io, UInt8)
    ehdr.e_ident4 = read(io, UInt8)
    ehdr.e_class = read(io, UInt8)
    ehdr.e_data = read(io, UInt8)
    ehdr.e_fversion = read(io, UInt8)
    ehdr.e_osabi = read(io, UInt8)
    ehdr.e_abiversion = read(io, UInt8)
    ehdr.e_pad = read(io, UInt8)

    ehdr.e_type = read(io, UInt16)
    ehdr.e_machine = read(io, UInt16)
    ehdr.e_version = read(io, UInt32)
    ehdr.e_entry = read(io, UInt64)
    ehdr.e_phoff = read(io, UInt64)
    ehdr.e_shoff = read(io, UInt64)
    ehdr.e_flags = read(io, UInt32)
    ehdr.e_ehsize = read(io, UInt16)
    ehdr.e_phentsize = read(io, UInt16)
    ehdr.e_phnum = read(io, UInt16)
    ehdr.e_shentsize = read(io, UInt16)
    ehdr.e_shnum = read(io, UInt16)
    ehdr.e_shstrndx = read(io, UInt16)

    @assert ehdr.e_ident1 == ELF2.ELFMAG0
    @assert ehdr.e_ident2 == ELF2.ELFMAG1
    @assert ehdr.e_ident3 == ELF2.ELFMAG2
    @assert ehdr.e_ident4 == ELF2.ELFMAG3
    return ehdr 
end

function read_elf(io::IOStream)
    elf = ELF()
    elf.ehdr = read_ehdr(io)
    return elf
end

end
