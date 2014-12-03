AUTOMAKE_OPTIONS = subdir-objects serial-tests

noinst_LTLIBRARIES = libdegencpp.la libde.la
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

nodist_libde_la_SOURCES = \
	DecodeEngine/DetailResultsCompiler.cpp     \
	DecodeEngine/DnsResolveName.cpp            \
	DecodeEngine/H323Common.cxx                \
	DecodeEngine/PreScanDynamicPorts.cpp       \
	DecodeEngine/PreScanProtocol.cpp           \
	DecodeEngine/PreScanProtocolH245.cpp       \
	DecodeEngine/PreScanProtocolH323.cpp       \
	DecodeEngine/PreScanProtocolMgcp.cpp       \
	DecodeEngine/PreScanProtocolRtp.cpp        \
	DecodeEngine/PreScanProtocolSip.cpp        \
	DecodeEngine/StandaloneDecoder.cpp         \
	DecodeEngine/WinsResolveName.cpp           \
	DecodeEngine/wtapfile.cpp                  \
	DecodeEngine/DecodePreScan.cpp	

libde_la_CPPFLAGS = \
         -I ethereal -I ethereal/epan -I ethereal/wiretap -I ethereal/epan/dissectors \
         -I glib-2.42.1  -I glib-2.42.1/glib  -I glib-2.42.1/gmodule  -I glib-2.42.1/gobject 


#         -I glib  -I glib/glib  -I glib/gmodule  -I glib/gobject 

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
	libde.la \
	-lboost_thread


DeClient_SOURCES = \
	MyDecodeEngineClient.cpp \
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


