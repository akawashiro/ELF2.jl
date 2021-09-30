module ELF2

include("constants.jl")

const EI_NIDENT = 16

function hex(n)
    return string("0x", string(n, base=16))
end

macro read_field(io, field)
    return :($(esc(field)) = read($(esc(io)), typeof($(esc(field)))))
end

# TODO: Use this macro
macro read_field_from_io(field)
    return :($(esc(field)) = read(io, typeof($(esc(field)))))
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

function ehdr_to_str(e::Ehdr)
    ret = """Ehdr(e_class=$(ELFCLASS[e.e_class]), e_data=$(ELFDATA[e.e_data]), e_fversion=$(ELFVERSION[e.e_fversion]), e_osabi=$(ELFOSABI[e.e_osabi]), e_abiversion=$(hex(e.e_abiversion)), e_type=$(ET_TYPES[e.e_type]), e_machine=$(EM_MACHINES[e.e_machine]), e_version=$(hex(e.e_version)), e_entry=$(hex(e.e_entry)), e_phoff=$(hex(e.e_phoff)), e_shoff=$(hex(e.e_shoff)), e_flags=$(hex(e.e_flags)), e_ehsize=$(hex(e.e_ehsize)), e_phentsize=$(hex(e.e_phentsize)), e_phnum=$(hex(e.e_phnum)), e_shentsize=$(hex(e.e_shentsize)), e_shnum=$(e.e_shnum), e_shstrndx=$(string(e.e_shstrndx)))"""
    return ret
end

mutable struct Dyn
    d_tag::UInt64
    d_val_or_ptr::UInt64
    Dyn() = new(0, 0)
end

function dyn_to_str(dyn::Dyn)
    return "Dyn($(DYNAMIC_TYPE[dyn.d_tag]), d_val_or_ptr=0x$(string(dyn.d_val_or_ptr, 16)))"
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
    for (value, name) in PF
        if (f & value) == value
            push!(ret, name)
        end
    end

    @assert size(ret)[1] != 0
    return join(ret, "+")
end

function phdr_to_str(p::Phdr)
    ret = "Phdr(p_type=$(P_TYPE[p.p_type]), p_flags=$(show_PF(p.p_flags)), p_offset=$(hex(p.p_offset)), p_vaddr=$(hex(p.p_vaddr)), p_paddr=$(hex(p.p_paddr)), p_filesz=$(hex(p.p_filesz)), p_memsz=$(p.p_memsz), p_align=$(hex(p.p_align)))"
    return ret
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

function shdr_to_str(s::Shdr, shstrtab::Vector{UInt8})
    ret = "Shdr(sh_name=$(get_str_from_uint8s(shstrtab, s.sh_name + 1)), sh_type=$(SHT_TYPES[s.sh_type]), sh_flags=$(show_SHF_FLAGS(s.sh_flags)), sh_addr=$(hex(s.sh_addr)), sh_offset=$(hex(s.sh_offset)), sh_size=$(hex(s.sh_size)), sh_link=$(s.sh_link), sh_info=$(hex(s.sh_info)), sh_addralign=$(hex(s.sh_addralign)), sh_entsize=$(hex(s.sh_entsize)))"
    return ret
end

mutable struct Sym
    st_name::UInt32
    st_info::UInt8
    st_other::UInt8
    st_shndx::UInt16
    st_value::UInt64
    st_size::UInt64
    Sym() = new(0, 0, 0, 0, 0, 0)
end

function read_sym(io::IOStream)
    sym = Sym()
    @read_field(io, sym.st_name) 
    @read_field(io, sym.st_info)
    @read_field(io, sym.st_other)
    @read_field(io, sym.st_shndx)
    @read_field(io, sym.st_value)
    @read_field(io, sym.st_size)
    return sym 
end

function sym_to_str(s::Sym, strtab::Vector{UInt8})
    ret = "Sym(st_name=$(get_str_from_uint8s(strtab, s.st_name+1)), st_info=$(hex(s.st_info)), st_other=$(s.st_other), sh_shndx=$(s.st_shndx), st_value=$(hex(s.st_value)), st_size=$(hex(s.st_size)))"
    return ret
end

mutable struct Rela
    r_offset::UInt64
    r_info::UInt64
    r_addend::Int64
    Rela() = new(0, 0, 0)
end

function read_rela(io::IOStream)
    r = Rela()
    @read_field(io, r.r_offset) 
    @read_field(io, r.r_info)
    @read_field(io, r.r_addend)
    return r 
end

function rela_to_str(r::Rela)
    ret = "Rela(r_offset=$(hex(r.r_offset)), r_info=$(hex(r.r_info)), r_addend=$(r.r_addend))"
    return ret
end

mutable struct Rel
    r_offset::UInt64
    r_info::UInt64
    Rel() = new(0, 0)
end

function read_rel(io::IOStream)
    r = Rel()
    @read_field(io, r.r_offset) 
    @read_field(io, r.r_info)
    return r 
end

function rel_to_str(r::Rel)
    ret = "Rel(r_offset=$(hex(r.r_offset)), r_info=$(hex(r.r_info)))"
    return ret
end

mutable struct ELF
    ehdr::Ehdr
    phdrs::Vector{Phdr}
    shdrs::Vector{Shdr}
    dyns::Vector{Dyn}
    syms::Vector{Sym}
    dynsyms::Vector{Sym}
    rels::Vector{Rel}
    relas::Vector{Rela}
    dynstrtab::Vector{UInt8}
    strtab::Vector{UInt8}
    shstrtab::Vector{UInt8}
    ELF() = new(Ehdr(), [], [], [], [], [], [], [], [], [], [])
end

function get_str_from_uint8s(v::Vector{UInt8}, index)
    @assert index <= size(v)[1] "index = $(index), size(v)[1] = $(size(v)[1])"
    s = Vector{UInt8}([])
    for i = index:size(v)[1]
        if v[i] == 0x0
            break
        end
        push!(s, v[i])
    end

    return String(UInt8.(s))
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

function read_strs(io::IOStream, offset::UInt64, size::UInt64)
    seek(io, offset)

    str = Vector{UInt8}([])
    for i in 1:size
        c = 0x0
        @read_field(io, c)
        push!(str, c)
    end

    return str
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

    if elf.ehdr.e_shstrndx < size(elf.shdrs)[1]
        elf.shstrtab = read_strs(io, elf.shdrs[elf.ehdr.e_shstrndx + 1].sh_offset, elf.shdrs[elf.ehdr.e_shstrndx + 1].sh_size)
    end

    for sh in elf.shdrs
        str = get_str_from_uint8s(elf.shstrtab, sh.sh_name + 1)
        if str == ".strtab"
            elf.strtab = read_strs(io, sh.sh_offset, sh.sh_size)
        elseif str == ".dynstr"
            elf.dynstrtab = read_strs(io, sh.sh_offset, sh.sh_size)
        elseif str == ".symtab"
            seek(io, sh.sh_offset)
            for i = 1:Int64(sh.sh_size/sh.sh_entsize)
                s = read_sym(io)
                push!(elf.syms, s)
            end
        elseif str == ".dynsym"
            seek(io, sh.sh_offset)
            for i = 1:Int64(sh.sh_size/sh.sh_entsize)
                s = read_sym(io)
                push!(elf.dynsyms, s)
            end
        end

        if sh.sh_type == SHT_RELA
            seek(io, sh.sh_offset)
            for i = 1:Int64(sh.sh_size/sh.sh_entsize)
                r = read_rela(io)
                push!(elf.relas, r)
            end
        end


        if sh.sh_type == SHT_REL
            seek(io, sh.sh_offset)
            for i = 1:Int64(sh.sh_size/sh.sh_entsize)
                r = read_rel(io)
                push!(elf.relas, r)
            end
        end
    end

    return elf
end

function Base.show(io::IO, elf::ELF)
    println("ELF(")

    println(ehdr_to_str(elf.ehdr))

    println("phdrs=[")
    for p in elf.phdrs
        println(phdr_to_str(p))
    end
    println("]")

    println("shdrs=[")
    for s in elf.shdrs
        println(shdr_to_str(s, elf.shstrtab))
    end
    println("]")

    println("dyns=[")
    for d in elf.dyns
        println(dyn_to_str(d))
    end
    println("]")

    println("syms=[")
    for s in elf.syms
        println(sym_to_str(s, elf.strtab))
    end
    println("]")

    println("dynsyms=[")
    for s in elf.dynsyms
        println(sym_to_str(s, elf.dynstrtab))
    end
    println("]")

    println("relas=[")
    for r in elf.relas
        println(rela_to_str(r))
    end
    println("]")

    println("rels=[")
    for r in elf.rels
        println(rela_to_str(r))
    end
    println("]")

    println(")")
end

end
