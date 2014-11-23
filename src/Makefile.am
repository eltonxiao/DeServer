AUTOMAKE_OPTIONS = subdir-objects serial-tests

noinst_LTLIBRARIES = libdegencpp.la
nodist_libdegencpp_la_SOURCES = \
	gen-cpp/BulletinBoard.cpp \
	gen-cpp/BulletinBoard.h \
	gen-cpp/decode_engine_constants.cpp \
	gen-cpp/decode_engine_constants.h \
	gen-cpp/DecodeEngine.cpp \
	gen-cpp/DecodeEngine.h \
	gen-cpp/decode_engine_types.cpp \
	gen-cpp/decode_engine_types.h


libdegencpp_la_LIBADD = /usr/local/lib/libthrift.la


bin_PROGRAMS = \
	DeServer \
	DeClient

DeServer_SOURCES = \
	BbLauncher.cpp \
	DeLauncher.cpp \
	BulletinService.cpp \
	CommandLineParser.cpp \
	DeLauncherRemote.cpp \
	DeServer.cpp \
	ProcessUtility.cpp \
	WorkerService.cpp

DeServer_LDADD = /usr/local/lib/libthrift.la \
	libdegencpp.la \
	-lboost_thread


DeClient_SOURCES = \
	DeClient.cpp

DeClient_LDADD = /usr/local/lib/libthrift.la \
	libdegencpp.la


#
# Common thrift code generation rules
#
THRIFT = thrift

gen-cpp/BulletinBoard.cpp gen-cpp/BulletinBoard.h gen-cpp/BulletinBoard_server.skeleton.cpp gen-cpp/decode_engine_constants.cpp gen-cpp/decode_engine_constants.h gen-cpp/DecodeEngine.cpp gen-cpp/DecodeEngine.h gen-cpp/DecodeEngine_server.skeleton.cpp gen-cpp/decode_engine_types.cpp gen-cpp/decode_engine_types.h : decode_engine.thrift
	$(THRIFT) --gen cpp -r $<


AM_CPPFLAGS = $(BOOST_CPPFLAGS) $(LIBEVENT_CPPFLAGS) -I$(top_srcdir)/lib/cpp/src -Igen-cpp
AM_CXXFLAGS = -Wall -Wextra -pedantic
AM_LDFLAGS = $(BOOST_LDFLAGS) $(LIBEVENT_LDFLAGS)

clean-local:
	$(RM) -r gen-cpp

server: all
	./DeServer

client: all
	./DeClient

