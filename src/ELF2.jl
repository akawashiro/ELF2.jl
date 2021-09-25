module ELF2

using PrettyPrint

include("constants.jl")

const EI_NIDENT = 16

function hex(n)
    return string("0x", string(n, 16))
end

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

function Base.show(io::IO, e::Ehdr)
    ret = """Ehdr(e_class=$(ELFCLASS[e.e_class]), e_data=$(ELFDATA[e.e_data]), e_fversion=$(ELFVERSION[e.e_fversion]), e_osabi=$(ELFOSABI[e.e_osabi]), e_abiversion=$(hex(e.e_abiversion)), e_type=$(ET_TYPES[e.e_type]), e_machine=$(EM_MACHINES[e.e_machine]), e_version=$(hex(e.e_version)), e_entry=$(hex(e.e_entry)), e_phoff=$(hex(e.e_phoff)), e_shoff=$(hex(e.e_shoff)), e_flags=$(hex(e.e_flags)), e_ehsize=$(hex(e.e_ehsize)), e_phentsize=$(hex(e.e_phentsize)), e_phnum=$(hex(e.e_phnum)), e_shentsize=$(hex(e.e_shentsize)), e_shnum=$(e.e_shnum), e_shstrndx=$(string(e.e_shstrndx)))"""
    print(ret)
end

mutable struct Dyn
    d_tag::UInt64
    d_val_or_ptr::UInt64
    Dyn() = new(0, 0)
end

function Base.show(io::IO, dyn::Dyn)
    print("Dyn($(DYNAMIC_TYPE[dyn.d_tag]), d_val_or_ptr=0x$(string(dyn.d_val_or_ptr, 16)))")
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

function show_PF(f::UInt32)
    ret::Vector{String} = []
    if (f & PF_R) == PF_R
        push!(ret, "PF_R")
    end
    if (f & PF_W) == PF_W
        push!(ret, "PF_W")
    end
    if (f & PF_X) == PF_X
        push!(ret, "PF_X")
    end

    @assert size(ret)[1] != 0
    return join(ret, "+")
end

function Base.show(io::IO, p::Phdr)
    ret = "Phdr(p_type=$(P_TYPE[p.p_type]), p_flags=$(show_PF(p.p_flags)), p_offset=$(hex(p.p_offset)), p_vaddr=$(hex(p.p_vaddr)), p_paddr=$(hex(p.p_paddr)), p_filesz=$(hex(p.p_filesz)), p_memsz=$(p.p_memsz), p_align=$(hex(p.p_align)))"
    print(ret)
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

function show_SHF_FLAGS(f::UInt64)
    ret::Vector{String} = []
    for (value, name) in SHF_FLAGS
        if (f & value) == value
            push!(ret, name)
        end
    end

    return join(ret, "+")
end

function Base.show(io::IO, s::Shdr)
    ret = "Shdr(sh_name=$(hex(s.sh_name)), sh_type=$(SHT_TYPES[s.sh_type]), sh_flags=$(show_SHF_FLAGS(s.sh_flags)), sh_addr=$(hex(s.sh_addr)), sh_offset=$(hex(s.sh_offset)), sh_size=$(hex(s.sh_size)), sh_link=$(s.sh_link), sh_info=$(hex(s.sh_info)), sh_addralign=$(hex(s.sh_addralign)), sh_entsize=$(hex(s.sh_entsize)))"
    print(ret)
end

mutable struct ELF
    ehdr::Ehdr
    phdrs::Vector{Phdr}
    shdrs::Vector{Shdr}
    dyns::Vector{Dyn}
    ELF() = new(Ehdr(), [], [], [])
end

macro read_field(io, field)
    return :($(esc(field)) = read($(esc(io)), typeof($(esc(field)))))
end

# TODO: Use this macro
macro read_field_from_io(field)
    return :($(esc(field)) = read(io, typeof($(esc(field)))))
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

    @assert count(p -> p.p_type == PT_DYNAMIC, elf.phdrs) < 2
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
