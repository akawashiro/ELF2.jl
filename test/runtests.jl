using ELF2
using Test

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

    print(elf)

    close(f)
end

@testset "ELF2.jl" begin
    # Write your tests here.

    test_magic()

end
