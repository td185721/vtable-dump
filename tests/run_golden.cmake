# Runs a tool and compares its stdout and exit code with a golden file.
#
#   cmake -DTOOL=<exe> -DARGS=<arg|arg|...> -DWORKDIR=<dir>
#         -DEXPECTED=<file> -DEXPECTED_RC=<code> -P run_golden.cmake
#
# Arguments are separated by '|' so they survive add_test(). Line endings
# are normalized, so the same golden files work on Windows and Unix.

string(REPLACE "|" ";" args "${ARGS}")
execute_process(
    COMMAND "${TOOL}" ${args}
    WORKING_DIRECTORY "${WORKDIR}"
    OUTPUT_VARIABLE actual
    RESULT_VARIABLE rc)

if(NOT rc STREQUAL EXPECTED_RC)
    message(FATAL_ERROR "exit code was ${rc}, expected ${EXPECTED_RC}")
endif()

file(READ "${EXPECTED}" expected)
string(REPLACE "\r\n" "\n" actual "${actual}")
string(REPLACE "\r\n" "\n" expected "${expected}")
if(NOT actual STREQUAL expected)
    get_filename_component(name "${EXPECTED}" NAME)
    file(WRITE "actual-${name}" "${actual}")
    message(FATAL_ERROR "output differs from ${EXPECTED}\n"
                        "actual output written to ${CMAKE_CURRENT_BINARY_DIR}/actual-${name}")
endif()
