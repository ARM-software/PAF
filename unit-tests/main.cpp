#include "libtarmac/reporter.hh"

#include "gtest/gtest.h"

std::unique_ptr<Reporter> reporter = make_cli_reporter();

using namespace testing;

int main(int argc, char **argv) {
    InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
