#include <cxxabi.h>

#include <string>
#include <typeinfo>

int main() {
    int status;
    char *mangled = "_ZStlsISt11char_traitsIcEERSt13basic_ostreamIcT_ES5_PKc";
    char *demangled = abi::__cxa_demangle(mangled, 0, 0, &status);
    printf("demangled: %s\n", demangled);
    free(demangled);
    return 0;
}
