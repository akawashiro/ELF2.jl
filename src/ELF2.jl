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

const PT_NULL           = 0
const PT_LOAD           = 1
const PT_DYNAMIC        = 2
const PT_INTERP         = 3
const PT_NOTE           = 4
const PT_SHLIB          = 5
const PT_PHDR           = 6
const PT_TLS            = 7
const PT_LOOS           = 0x60000000
const PT_GNU_EH_FRAME   = 0x6474e550
const PT_GNU_STACK      = 0x6474e551
const PT_GNU_RELRO      = 0x6474e552
const PT_PAX_FLAGS      = 0x65041580
const PT_HIOS           = 0x6fffffff
const PT_LOPROC         = 0x70000000
const PT_HIPROC         = 0x7fffffff

const DT_NULL         = 0
const DT_NEEDED       = 1
const DT_PLTRELSZ     = 2
const DT_PLTGOT       = 3
const DT_HASH         = 4
const DT_STRTAB       = 5
const DT_SYMTAB       = 6
const DT_RELA         = 7
const DT_RELASZ       = 8
const DT_RELAENT      = 9
const DT_STRSZ        = 10
const DT_SYMENT       = 11
const DT_INIT         = 12
const DT_FINI         = 13
const DT_SONAME       = 14
const DT_RPATH        = 15
const DT_SYMBOLIC     = 16
const DT_REL          = 17
const DT_RELSZ        = 18
const DT_RELENT       = 19
const DT_PLTREL       = 20
const DT_DEBUG        = 21
const DT_TEXTREL      = 22
const DT_JMPREL       = 23
const DT_BIND_NOW     = 24
const DT_INIT_ARRAY	  = 25
const DT_FINI_ARRAY	  = 26
const DT_INIT_ARRAYSZ =	27
const DT_FINI_ARRAYSZ =	28
const DT_RUNPATH	  = 29
const DT_FLAGS	      = 30
const DT_ENCODING     = 32
const OLD_DT_LOOS     = 0x60000000
const DT_LOOS         = 0x6000000d
const DT_HIOS         = 0x6ffff000
const DT_VALRNGLO     = 0x6ffffd00
const DT_VALRNGHI     = 0x6ffffdff
const DT_ADDRRNGLO    = 0x6ffffe00
const DT_ADDRRNGHI    = 0x6ffffeff
const DT_VERSYM       = 0x6ffffff0
const DT_RELACOUNT    = 0x6ffffff9
const DT_RELCOUNT     = 0x6ffffffa
const DT_FLAGS_1      = 0x6ffffffb
const DT_VERDEF       = 0x6ffffffc
const DT_VERDEFNUM    = 0x6ffffffd
const DT_VERNEED      = 0x6ffffffe
const DT_VERNEEDNUM   = 0x6fffffff
const OLD_DT_HIOS     = 0x6fffffff
const DT_LOPROC       = 0x70000000
const DT_HIPROC       = 0x7fffffff

macro show_const_case(d, c)
    return quote
        if $(esc(d)) == $(esc(c))
            return string($(esc(c)))
        end
    end
end

function show_ELFDATA(d::UInt8)
    @show_const_case(d, ELFDATANONE)
    # Above line should be
    # 
    # if d == ELFDATANONE
    #     return "ELFDATANONE"
    # end
    if d == ELFDATA2LSB
        return "ELFDATA2LSB"
    end
    if d == ELFDATA2MSB
        return "ELFDATA2MSB"
    end
    error("$(d) is not legitimate")
end

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

const EI_NIDENT = 16

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
    Ehdr() = new(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
end

mutable struct Dyn
    d_tag::UInt64
    d_val_or_ptr::UInt64
    Dyn() = new(0, 0)
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
    Phdr() = new(0, 0, 0, 0, 0, 0, 0, 0)
end

mutable struct Shdr
    sh_name::UInt32
    sh_type::UInt32
    sh_flags::UInt64
    sh_addr::UInt64
    sh_offset::UInt64
    sh_size::UInt64
    sh_link::UInt32
    sh_info::UInt32
    sh_addralign::UInt64
    sh_entsize::UInt64
    Shdr() = new(0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
end

mutable struct ELF
    ehdr::Ehdr
    phdrs::Vector{Phdr}
    shdrs::Vector{Shdr}
    dyns::Vector{Dyn}
    ELF() = new(Ehdr(), [], [], [])
end

macro read_field(io, field)
    return :( $(esc(field)) = read($(esc(io)), typeof($(esc(field)))) )
end

# TODO: Use this macro
macro read_field_from_io(field)
    return :( $(esc(field)) = read(io, typeof($(esc(field)))) )
end

function read_dyn(io::IOStream)
    dyn = Dyn()

    @read_field(io, dyn.d_tag)
    @read_field(io, dyn.d_val_or_ptr)
    return dyn
end

function read_ehdr(io::IOStream)
    ehdr = Ehdr()

    @read_field(io, ehdr.e_ident1)
    @read_field(io, ehdr.e_ident2)
    @read_field(io, ehdr.e_ident3)
    @read_field(io, ehdr.e_ident4)
    @read_field(io, ehdr.e_class)
    @read_field(io, ehdr.e_data)
    @read_field(io, ehdr.e_fversion)
    @read_field(io, ehdr.e_osabi)
    @read_field(io, ehdr.e_abiversion)

    for i = 1:EI_NIDENT-position(io)
        read(io, UInt8)
    end

    @read_field(io, ehdr.e_type)
    @read_field(io, ehdr.e_machine)
    @read_field(io, ehdr.e_version)
    @read_field(io, ehdr.e_entry)
    @read_field(io, ehdr.e_phoff)
    @read_field(io, ehdr.e_shoff)
    @read_field(io, ehdr.e_flags)
    @read_field(io, ehdr.e_ehsize)
    @read_field(io, ehdr.e_phentsize)
    @read_field(io, ehdr.e_phnum)
    @read_field(io, ehdr.e_shentsize)
    @read_field(io, ehdr.e_shnum)
    @read_field(io, ehdr.e_shstrndx)

    @assert ehdr.e_ident1 == ELF2.ELFMAG0
    @assert ehdr.e_ident2 == ELF2.ELFMAG1
    @assert ehdr.e_ident3 == ELF2.ELFMAG2
    @assert ehdr.e_ident4 == ELF2.ELFMAG3
    return ehdr 
end

function read_phdr(io::IOStream)
    phdr = Phdr()
    @read_field(io, phdr.p_type)
    @read_field(io, phdr.p_flags)
    @read_field(io, phdr.p_offset)
    @read_field(io, phdr.p_vaddr)
    @read_field(io, phdr.p_paddr)
    @read_field(io, phdr.p_filesz)
    @read_field(io, phdr.p_memsz)
    @read_field(io, phdr.p_align)
    return phdr
end

function read_shdr(io::IOStream)
    shdr = Shdr()
    @read_field(io, shdr.sh_name)
    @read_field(io, shdr.sh_type)
    @read_field(io, shdr.sh_flags)
    @read_field(io, shdr.sh_addr)
    @read_field(io, shdr.sh_offset)
    @read_field(io, shdr.sh_size)
    @read_field(io, shdr.sh_link)
    @read_field(io, shdr.sh_info)
    @read_field(io, shdr.sh_addralign)
    @read_field(io, shdr.sh_entsize)
    return shdr
end

function read_elf(io::IOStream)
    elf = ELF()

    elf.ehdr = read_ehdr(io)

    if elf.ehdr.e_phoff != 0
        seek(io, elf.ehdr.e_phoff)
        for i = 1:elf.ehdr.e_phnum
            push!(elf.phdrs, read_phdr(io))
        end
    end

    if elf.ehdr.e_shoff != 0
        seek(io, elf.ehdr.e_shoff)
        for i = 1:elf.ehdr.e_shnum
            push!(elf.shdrs, read_shdr(io))
        end
    end

    @assert count(p->p.p_type==PT_DYNAMIC, elf.phdrs) < 2
    for p in elf.phdrs
        if p.p_type == PT_DYNAMIC
            seek(io, p.p_offset)
            while true
                d = read_dyn(io)
                push!(elf.dyns, d)
                if d.d_tag == DT_NULL
                    break
                end
            end
        end
    end

    return elf
end

end
