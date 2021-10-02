using ELF2
using Test

function check_command(command::String)
    which = `which $(command)`
    println(which)
    try
        run(which)
    catch
        println("Cannot find $(command) skip this test")
        return false
    end
    return true
end

function test_gcc()
    if !check_command("gcc")
        return
    end

    cmd = `gcc main.c -o main.gcc.out`
    run(cmd)
    f = open("main.gcc.out", "r")
    elf = ELF2.read_elf(f)
    show(elf)
end

function test_gcc_aarch64()
    if !check_command("aarch64-linux-gnu-gcc")
        return
    end

    cmd = `aarch64-linux-gnu-gcc main.c -o main.gcc.aarch64.out`
    run(cmd)
    f = open("main.gcc.out", "r")
    elf = ELF2.read_elf(f)
    show(elf)
end

function test_clang()
    if !check_command("clang")
        return
    end

    cmd = `clang main.c -o main.gcc.out`
    run(cmd)
    f = open("main.clang.out", "r")
    elf = ELF2.read_elf(f)
    show(elf)
end

function test_gcc_cxx()
    if !check_command("g++")
        return
    end

    cmd = `g++ main.cc -o main.g++.out`
    run(cmd)
    f = open("main.g++.out", "r")
    elf = ELF2.read_elf(f)
    show(elf)
end

function test_gcc_cxx_aarch64()
    if !check_command("aarch64-linux-gnu-g++")
        return
    end

    cmd = `aarch64-linux-gnu-g++ main.cc -o main.g++.aarch64.out`
    run(cmd)
    f = open("main.g++.aarch64.out", "r")
    elf = ELF2.read_elf(f)
    show(elf)
end

function test_clang_cxx()
    if !check_command("clang++")
        return
    end

    cmd = `clang++ main.c -o main.clang++.out`
    run(cmd)
    f = open("main.clang++.out", "r")
    elf = ELF2.read_elf(f)
    show(elf)
end

function test_magic()
    f = open("libmax.so", "r")

    elf = ELF2.read_elf(f)
    @test elf.ehdr.e_ident1 == ELF2.ELFMAG0
    @test elf.ehdr.e_ident2 == ELF2.ELFMAG1
    @test elf.ehdr.e_ident3 == ELF2.ELFMAG2
    @test elf.ehdr.e_ident4 == ELF2.ELFMAG3
    @test elf.ehdr.e_data == ELF2.ELFDATA2LSB
    @test elf.ehdr.e_fversion == ELF2.EV_CURRENT
    @test elf.ehdr.e_type == ELF2.ET_DYN
    
    show(elf)

    close(f)
end

@testset "ELF2.jl" begin
    test_magic()
    test_gcc()
    test_gcc_aarch64()
    test_clang()
    test_gcc_cxx()
    test_gcc_cxx_aarch64()
    test_clang_cxx()
end
