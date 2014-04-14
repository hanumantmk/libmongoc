AC_ARG_ENABLE(
	[cxx],
	[AC_HELP_STRING([--enable-cxx=@<:@no/yes@:>@],
			[Enable support for experimental cxx bindings. default=no])],
	[], [
		enable_cxx=no
		ax_cxx_header=no
	]
)
AS_IF([test "x$enable_cxx" = "xyes"], [
	AX_CXX
])
AM_CONDITIONAL([ENABLE_CXX], [test "x$ax_cxx_header" != "xno"])
