using ELF2
using Test

function execute(cmd::Cmd)
  out = Pipe()
  err = Pipe()

  process = run(pipeline(ignorestatus(cmd), stdout=out, stderr=err))
  close(out.in)
  close(err.in)

  (
    stdout = String(read(out)), 
    stderr = String(read(err)),  
    code = process.exitcode
  )
end

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

function test_command_itself(command::String)
    if !check_command(command)
        return
    end

    path, _, _ = execute(`which $(command)`)
    path = chop(path, tail=1)
    f = open(path, "r")
    elf = ELF2.read_elf(f)
    show(elf)
end

function test_cc(command::String)
    if !check_command(command)
        return
    end

    cmd = `$(command) main.c -o main.$(command).out`
    run(cmd)
    f = open("main.$(command).out", "r")
    elf = ELF2.read_elf(f)
    show(elf)
end

function test_cxx(command::String)
    if !check_command(command)
        return
    end

    cmd = `$(command) main.c -o main.$(command).out`
    run(cmd)
    f = open("main.$(command).out", "r")
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

function test_demangle()
    @test ELF2.demangle("_Z41__static_initialization_and_destruction_0ii") == "__static_initialization_and_destruction_0"
    @test ELF2.demangle("_ZNSolsEPFRSoS_E") == "std::basic_ostream<char, std::char_traits<char> >::operator<<(std::basic_ostream<char, std::char_traits<char> >& (*)(std::basic_ostream<char, std::char_traits<char> >&))"
    @test ELF2.demangle("_ZNSt8ios_base4InitC1Ev") == "std::ios_base::Init::Init()"
    @test ELF2.demangle("_ZNSt8ios_base4InitD1Ev") == "std::ios_base::Init::~Init()"
    @test ELF2.demangle("_ZSt4cout") == "_ZSt4cout"
    @test ELF2.demangle("_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_") == "_ZSt4endlIcSt11char_traitsIcEERSt13basic_ostreamIT_T0_ES6_"
    @test ELF2.demangle("_ZStL8__ioinit") == "_ZStL8__ioinit"
    @test ELF2.demangle("_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc") == "_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc"
end

@testset "ELF2.jl" begin
    test_magic()
    test_cc("gcc")
    test_cc("aarch64-linux-gnu-gcc")
    test_cc("clang")
    test_cxx("g++")
    test_cxx("aarch64-linux-gnu-g++")
    test_cxx("clang++")
    test_command_itself("gcc")
    test_command_itself("g++")
    test_command_itself("clang")
    test_command_itself("clang++")
    # test_demangle()
end
