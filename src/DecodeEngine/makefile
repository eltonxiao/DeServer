
CXX=g++

INCPATH= -I ..  -I ../DecodeEngine \
	 -I ../../DecodeEngine \
         -I ../../ethereal -I ../../ethereal/epan -I ../../ethereal/wiretap -I ../../ethereal/epan/dissectors  \
         -I ../../glib  -I ../../glib/glib  -I ../../glib/gmodule  -I ../../glib/gobject 

CPPFLAGS=-Wall -g $(INCPATH) -D__CS_LINUX 

SRCS= 	DetailResultsCompiler.cpp     \
	DnsResolveName.cpp            \
	H323Common.cxx                \
	PreScanDynamicPorts.cpp       \
	PreScanProtocol.cpp           \
	PreScanProtocolH245.cpp       \
	PreScanProtocolH323.cpp       \
	PreScanProtocolMgcp.cpp       \
	PreScanProtocolRtp.cpp        \
	PreScanProtocolSip.cpp        \
	StandaloneDecoder.cpp         \
	WinsResolveName.cpp           \
	wtapfile.cpp                  \
	DecodePreScan.cpp	

OBJS=   DetailResultsCompiler.o     \
        DnsResolveName.o            \
        H323Common.o                \
        PreScanDynamicPorts.o       \
        PreScanProtocol.o           \
        PreScanProtocolH245.o       \
        PreScanProtocolH323.o       \
        PreScanProtocolMgcp.o       \
        PreScanProtocolRtp.o        \
        PreScanProtocolSip.o        \
        StandaloneDecoder.o         \
        WinsResolveName.o           \
        wtapfile.o                  \
        DecodePreScan.o             



all: $(OBJS)

.SUFFIXES: .cpp  .cxx
.cpp.o:
	$(CXX) $(CPPFLAGS) -c $(SRCS)
.cxx.o:
	$(CXX) $(CPPFLAGS) -c $(SRCS)

clean:
	-rm -f $(OBJS)

