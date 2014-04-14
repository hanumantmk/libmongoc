AC_OUTPUT

if test $(( ${MONGOC_MINOR_VERSION} % 2 )) -eq 1; then
cat << EOF
 *** IMPORTANT *** 

 This is an unstable version of libmongoc.
 It is for test purposes only.

 Please, DO NOT use it in a production environment.
 It will probably crash and you will lose your data.

 Additionally, the API/ABI may change during the course
 of development.

 Thanks,

   The libmongoc team.

 *** END OF WARNING ***

EOF
fi

echo "
libmongoc was configured with the following options:

Build configuration:
  Enable debugging (slow)                          : ${enable_debug}
  Compile with debug symbols (slow)                : ${enable_debug_symbols}
  Enable GCC build optimization                    : ${enable_optimizations}
  Enable automatic binary hardening                : ${enable_hardening}
  Code coverage support                            : ${enable_coverage}
  Cross Compiling                                  : ${enable_crosscompile}
  Fast counters                                    : ${enable_rdtscp}
  SASL                                             : ${enable_sasl}
  SSL                                              : ${enable_ssl}
  Libbson                                          : ${with_libbson}

Documentation:
  Generate man pages                               : ${mongoc_build_doc}
  Install man pages                                : ${mongoc_install_man}

Bindings:
  CXX (experimental)                               : ${ax_cxx_header}
  Python (experimental)                            : ${ax_python_header}
"
