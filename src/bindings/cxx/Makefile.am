if ENABLE_CXX

noinst_PROGRAMS += cxxmongoc_example

cxxmongoc_example_SOURCES = \
	src/bindings/cxx/example.cpp

cxxmongoc_example_LDADD = \
	libmongoc-1.0.la \
	$(BSON_LIBS)

cxxmongoc_example_CPPFLAGS = \
	$(BSON_CFLAGS) \
	-I$(top_srcdir)/src/mongoc \
	-I$(top_srcdir)/src/bindings/cxx \
	-I$(top_builddir)/src/mongoc

endif
