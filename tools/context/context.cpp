
#include "PAF/ArchInfo.h"
#include "PAF/PAF.h"

#include "libtarmac/argparse.hh"
#include "libtarmac/elf.hh"
#include "libtarmac/reporter.hh"
#include "libtarmac/tarmacutil.hh"

#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>

#include <tgmath.h>

#include <algorithm>
#include <ctype.h>
#include <locale>
#include <set>
#include <string>
#include <vector>

#define NREG 16

using std::cout;
using std::string;
using std::unique_ptr;
using std::vector;

/** A Reporter instance to display diagnostics to the user */
unique_ptr<Reporter> reporter = make_cli_reporter();

/** The MemoryData class contains the memory content at a certain address */
class MemoryData {
    Addr address;
    int size;    // Total size of the symbol
    string name; // Name of the symbol(if it exists)
  public:
    vector<uint64_t> values;

    MemoryData() {}
    MemoryData(Addr address, int size, string name = "", int width = 0)
        : address(address), size(size), name(name), values() {}

    Addr getaddress() const { return address; }
    int getsize() const { return size; }
    string getname() const { return name; }
    string getValue() {
        string s = "";
        for (auto a : values) {
            s = std::to_string(a) + s;
        }
        return s;
    }
    string getValuehex() {
        string s = "";
        for (auto a : values) {
            std::stringstream stream;
            stream << std::hex << a;
            s = stream.str() + s;
        }
        return s;
    }
    void setname(string nom) { name = nom; }
    void setaddress(Addr a) { address = a; }
    void setsize(int s) { size = s; }
    // Debug
    void print() {
        std::ios_base::fmtflags f(cout.flags()); // save flags state
        cout << "0x" << std::hex << address << ":    ";
        cout.flags(f);
        cout << name << "    ";
        for (auto a : values) {
            cout << a;
        }
        cout << "    " << size << "\n";
    }
};
namespace {

class Analyzer : public PAF::MTAnalyzer {
    vector<PAF::ReferenceInstruction> insts;

  public:
    Analyzer(const Analyzer &) = delete;
    /// Anayzer constructor.
    Analyzer(const TracePair &trace, const std::string &image_filename)
        : MTAnalyzer(trace, image_filename), insts() {}

    /** The getMemContent function returns a set of symbols accessed
    by the program within the ExecutionRange ER
    * param:
    *@ ER : the execution range
    *@ s  : a set of Symbol objects
    */
    void getMemContent(const PAF::ExecutionRange &ER,
                       std::set<const Symbol *> &s) {
        struct TCont {
            std::set<const Symbol *> &s;
            Analyzer &A;
            unique_ptr<PAF::ArchInfo> CPU;

            TCont(std::set<const Symbol *> &s, Analyzer &A)
                : s(s), A(A), CPU(std::move(PAF::getCPU(A.index))) {}

            void operator()(PAF::ReferenceInstruction &I) {
                for (const auto ma : I.memaccess) {

                    const Symbol *sym_ptr = A.get_image()->find_symbol(ma.addr);
                    if (sym_ptr == nullptr) {
                        reporter->errx(EXIT_FAILURE,
                                       "No symbol at address %d found",
                                       ma.addr);
                    }
                    s.insert(sym_ptr);
                    if (ma.size >= 2) {
                        const Symbol *sym_ptr =
                            A.get_image()->find_symbol(ma.addr + 1);
                        if (sym_ptr == nullptr) {
                            reporter->errx(EXIT_FAILURE,
                                           "No symbol at address %d found",
                                           ma.addr);
                        }
                        s.insert(sym_ptr);
                    }
                    if (ma.size >= 4) {
                        const Symbol *sym_ptr =
                            A.get_image()->find_symbol(ma.addr + 2);
                        if (sym_ptr == nullptr) {
                            reporter->errx(EXIT_FAILURE,
                                           "No symbol at address %d found",
                                           ma.addr);
                        }
                        s.insert(sym_ptr);

                        sym_ptr = A.get_image()->find_symbol(ma.addr + 3);
                        if (sym_ptr == nullptr) {
                            reporter->errx(EXIT_FAILURE,
                                           "No symbol at address %d found",
                                           ma.addr);
                        }
                        s.insert(sym_ptr);
                    }
                    if (ma.size == 8) {
                        const Symbol *sym_ptr =
                            A.get_image()->find_symbol(ma.addr + 4);
                        if (sym_ptr == nullptr) {
                            reporter->errx(EXIT_FAILURE,
                                           "No symbol at address %d found",
                                           ma.addr);
                        }
                        s.insert(sym_ptr);

                        sym_ptr = A.get_image()->find_symbol(ma.addr + 5);
                        if (sym_ptr == nullptr) {
                            reporter->errx(EXIT_FAILURE,
                                           "No symbol at address %d found",
                                           ma.addr);
                        }
                        s.insert(sym_ptr);

                        sym_ptr = A.get_image()->find_symbol(ma.addr + 6);
                        if (sym_ptr == nullptr) {
                            reporter->errx(EXIT_FAILURE,
                                           "No symbol at address %d found",
                                           ma.addr);
                        }
                        s.insert(sym_ptr);

                        sym_ptr = A.get_image()->find_symbol(ma.addr + 7);
                        if (sym_ptr == nullptr) {
                            reporter->errx(EXIT_FAILURE,
                                           "No symbol at address %d found",
                                           ma.addr);
                        }
                        s.insert(sym_ptr);
                    }
                }
            }
        };
        TCont TC(s, *this);
        PAF::FromTraceBuilder<PAF::ReferenceInstruction,
                              PAF::ReferenceInstructionBuilder, TCont>
            FTB(*this);
        FTB.build(ER, TC);
    }

    void add(const PAF::ReferenceInstruction &I) { insts.push_back(I); }
    void reset() { insts.clear(); }

    /** The getMeminfoatTime function retrieves all the symbols accessed by the
     * program in the ExecutionRange ER by calling the getMemContent function,
     * associates each symbol with a MemoryData instance and then store it in
     * the vector MD. param :
     * @t  : time of analysis
     * @MD : MemoryData vector
     * @ER : The execution range
     */
    void getMeminfoatTime(Time t, vector<MemoryData> &MD,
                          const PAF::ExecutionRange &ER) {
        std::set<const Symbol *> s;
        getMemContent(ER, s); // Fetch all the memory accesses found in the
                              // trace
        if (!has_image()) {
            reporter->errx(EXIT_FAILURE,
                           "No image, symbols can not be looked up");
        }
        std::unique_ptr<ElfFile> elf_file =
            elf_open(get_image()->get_filename());

        for (auto symb : s) { // Save symbols to MD and retrieve their value.
            Symbol sym = *(symb);
            MemoryData data(sym.addr, sym.size * 8, sym.getName());
            int c = 0;
            int size = sym.size * 8;
            do {
                uint64_t value = getmemValue(sym.addr + c * 8, t, size);
                data.values.push_back(value);
                size -= 64;
                c += 1;
            } while (size > 0);
            MD.push_back(data);
        }
    }
    /** The getmemValue function returns the memory contents at a certain
     * address at time t
     * param :
     *  @address : address of memory segment
     *  @t       : time of analysis
     *  @size    : size
     */
    uint64_t getmemValue(int address, Time t, size_t size) {

        SeqOrderPayload SOP;

        if (!node_at_time(t, &SOP)) {
            reporter->errx(1, "Can not find node at time %d in this trace", t);
        }
        vector<unsigned char> val(size);
        vector<unsigned char> def(size);
        auto memroot = SOP.memory_root;

        getmem(memroot, 'm', address, size, &val[0], &def[0]);

        uint64_t value = 0;

        for (size_t i = size; i-- > 0;) {
            value = (value << 8) | val[i];
        }

        return value;
    }
};

/** Test of ofsteam is open and close it */
void close(std::ofstream &ofs) {
    if (ofs.is_open()) {
        ofs.close();
    }
}

/** The printfile function prints the header of the python file and the
 * memory initialization param :
 * @A             : Analyzer object
 * @trace         : name of the trace
 * @function_name : name of the function analyzed
 * @starttime     : time in clock cycles of function start
 * @endtime       : time in clock cycles of function start
 * @startaddress  : address of function start
 * @stopaddress   : address of function end
 * @ofs           : output ofstream
 * @MD            : vector of the program's MemoryData
 * @reg           : vector of initial register values
 */
void printfile(Analyzer &A, string trace, string function_name, int starttime,
               int endtime, unsigned int startaddress, unsigned int stopaddress,
               std::ofstream &ofs, vector<MemoryData> MD,
               vector<uint32_t> reg) {
    if (!ofs) {
        reporter->errx(EXIT_FAILURE, "Error opening output file");
    }
    std::ios_base::fmtflags f(ofs.flags()); // save flags state
    ofs << "#\n";
    ofs << "#  Execution context of function : \'" << function_name << "\'\n";
    ofs << "#\n\n";
    ofs << "Image: \"";
    ofs << A.get_image()->get_filename();
    ofs << "\"\n";
    ofs << "ReferenceTrace: \"";
    ofs << trace;
    ofs << "\"\n";
    ofs << "FunctionInfo:\n";
    ofs << "  - { Name: \"" << function_name << "\", StartTime: " << starttime
        << ", EndTime: " << endtime << ", StartAddress: 0x";
    ofs << std::hex;
    ofs << startaddress << ", EndAddress: 0x" << stopaddress << "}\n";
    ofs << "InitialRegisterValues:\n";
    for (size_t c = 0; c < reg.size() - 2; c += 1) {
        ofs.flags(f);
        ofs << "    - "
            << "r" << c << ": 0x" << std::hex << reg[c] << "\n";
    }
    ofs << "    - "
        << "pc"
        << ": 0x" << reg[14] << "\t\t\t# current instruction"
        << "\n";
    ofs.flags(f);
    ofs << "InitialMemoryContent:\n";
    for (auto a : MD) {
        ofs << "    - "
            << "Symbol: {"
            << "Name: \"" << a.getname() << "\", Address: 0x" << std::hex
            << a.getaddress();
        ofs.flags(f);
        ofs << ", Size: " << a.getsize() << ", Value: 0x" << a.getValuehex()
            << "}\n";
    }
}

} // namespace

int main(int argc, char **argv) {
    string OutputFilename = "output";
    string Function_name = "main";
    Time t = 0;
    Addr startaddress;
    Addr stopaddress;
    int starttime;
    int stoptime;
    string trace_name;
    vector<uint32_t> reg; // Initial register values

    Argparse ap("paf-context", argc, argv);
    ap.optval({"-o", "--output"}, "OutputFilename",
              "name of generated file (default: output)",
              [&](const string &s) { OutputFilename = s; });
    ap.optval({"-f", "--function_name"}, "Function_name",
              "function name (default: main)",
              [&](const string &s) { Function_name = s; });

    TarmacUtilityMT tu(ap);

    ap.parse();
    tu.setup();

    vector<MemoryData> MD;

    for (const auto &trace : tu.traces) { // Multiple traces

        if (tu.is_verbose()) {
            cout << " - Running analysis on trace '" << trace.tarmac_filename
                 << "'\n";
        }
        Analyzer A(trace, tu.image_filename);
        vector<PAF::ExecutionRange> Functions = A.getInstances(Function_name);

        // Some sanity checks.

        if (Functions.size() == 0)
            reporter->errx(EXIT_FAILURE,
                           "Function '%s' was not found in the trace",
                           Function_name.c_str());

        if (tu.is_verbose()) {
            cout << " - Reading Memory contents from '" << trace.tarmac_filename
                 << "' and '" << (A.get_image())->get_filename() << '\''
                 << '\n';
        }

        OutputFilename.append(".yaml");
        std::ofstream ofs(OutputFilename.c_str());
        startaddress = (Functions[0].Start).addr;
        starttime = (Functions[0].Start).time;
        stoptime = (Functions[0].End).time;
        stopaddress = (Functions[0].End).addr;
        trace_name = trace.tarmac_filename;
        t = (Functions[0].Start).time - 1;
        A.getMeminfoatTime(t, MD, Functions[0]);

        for (int c = 0; c < (NREG - 1); c += 1) {
            string reg_name = "r" + std::to_string(c);
            uint32_t value = A.getRegisterValueAtTime(reg_name, t);
            reg.push_back(value);
        }

        reg.push_back(Functions[0].Start.addr);

        if (tu.is_verbose()) {
            cout << " - Generating output from '" << trace.tarmac_filename
                 << "' to '" << OutputFilename << "'\n";
        }

        printfile(A, trace_name, Function_name, starttime, stoptime,
                  startaddress, stopaddress, ofs, MD, reg);
        A.reset();
        close(ofs);
    }
    return EXIT_SUCCESS;
}
