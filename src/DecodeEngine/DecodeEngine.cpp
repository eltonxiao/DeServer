/* 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
// DecodeEngine.cpp : Defines the entry point for the DLL application.
//

#include "stdafx.h"
#include "DecodeEngine.h"

// undefine the TRY, CATCH, etc macros defined for MFC - they conflict
// with ethereal definitions
#include "UndefineTryCatch.h"
#include "PreScanProtocol.h"
#include "wtapFile.h"
#include "DetailResultsCompiler.h"
#include "StandaloneDecoder.h"

extern "C"
{
    #include "packet.h"
    #include "file.h"
    #include "column.h"
    #include "timestamp.h"
    #include "register.h"
    #include "epan.h"
    #include "epan_dissect.h"    
    #include "summarycols.h"
	#include "addr_resolv.h"

    ts_type timestamp_type = TS_RELATIVE;
    capture_file cfile;

    capture_file cfile_for_standalone;
}

static CWtapFile* s_pCapFile = 0;
static StandaloneDecoder * s_pStandaloneDecoder = 0;

bool IsCapable(DecodeCapabilities)
{
    return true;
}

void InitCFile(capture_file &_cfile)
{
    /* Initialize the capture file struct */
    _cfile.plist        = NULL;
    _cfile.plist_end    = NULL;
    _cfile.wth        = NULL;
    _cfile.filename    = NULL;
    _cfile.user_saved    = FALSE;
    _cfile.is_tempfile    = FALSE;
    _cfile.rfcode        = NULL;
    _cfile.displayfilter        = NULL;
    _cfile.dfcode        = NULL;
    _cfile.snap        = WTAP_MAX_PACKET_SIZE;
    _cfile.count        = 0;

    _cfile.edt = 0;
    _cfile.detail_items        = 0;

    _cfile.current_frame = 0;

    col_setup(&_cfile.cinfo, NUMBER_OF_SUMMARY_COL);

    // build a map describing how the displayed columns (SUMMARY_COL_xxx) are
    // built up from the available ethereal columns (COL_xxx). 
    // note that each displayable column happens to map to exactly one ethereal
    // column. 
    _cfile.cinfo.col_fmt[SUMMARY_COL_NUMBER] = COL_NUMBER;
    _cfile.cinfo.col_fmt[SUMMARY_COL_REL_TIME] = COL_REL_TIME;
    _cfile.cinfo.col_fmt[SUMMARY_COL_ABS_DATE_TIME] = COL_ABS_DATE_TIME;
    _cfile.cinfo.col_fmt[SUMMARY_COL_DELTA_TIME] = COL_DELTA_TIME;
    _cfile.cinfo.col_fmt[SUMMARY_COL_UNRES_DL_SRC] = COL_UNRES_DL_SRC;
    _cfile.cinfo.col_fmt[SUMMARY_COL_UNRES_DL_DST] = COL_UNRES_DL_DST;
    _cfile.cinfo.col_fmt[SUMMARY_COL_RES_DL_SRC] = COL_RES_DL_SRC;
    _cfile.cinfo.col_fmt[SUMMARY_COL_RES_DL_DST] = COL_RES_DL_DST;
    _cfile.cinfo.col_fmt[SUMMARY_COL_UNRES_NET_SRC] = COL_UNRES_NET_SRC;
    _cfile.cinfo.col_fmt[SUMMARY_COL_UNRES_NET_DST] = COL_UNRES_NET_DST;
    _cfile.cinfo.col_fmt[SUMMARY_COL_RES_NET_SRC] = COL_RES_NET_SRC;
    _cfile.cinfo.col_fmt[SUMMARY_COL_RES_NET_DST] = COL_RES_NET_DST;
    _cfile.cinfo.col_fmt[SUMMARY_COL_PACKET_LENGTH] = COL_PACKET_LENGTH;
    _cfile.cinfo.col_fmt[SUMMARY_COL_PROTOCOL] = COL_PROTOCOL;
    _cfile.cinfo.col_fmt[SUMMARY_COL_INFO] = COL_INFO;
    // appdancer-specific columns
    _cfile.cinfo.col_fmt[SUMMARY_COL_STATUS] = COL_STATUS; 
    _cfile.cinfo.col_fmt[SUMMARY_COL_INFO_PHYSICAL_LAYER] = COL_INFO_PHYSICAL_LAYER;
    _cfile.cinfo.col_fmt[SUMMARY_COL_INFO_NETWORK_LAYER] = COL_INFO_NETWORK_LAYER;
    _cfile.cinfo.col_fmt[SUMMARY_COL_INFO_TRANSPORT_LAYER] = COL_INFO_TRANSPORT_LAYER;

    // for each displayed column...
    for (int i = 0; i < _cfile.cinfo.num_cols; i++)
    {
        // allocate an array large enough to hold one boolean for each of the
        // possible ethereal fields that might be used to display the column. 
        // we only map one to one but it's possible to map to more than one 
        // ethereal field for each field we display.
        _cfile.cinfo.fmt_matx[i] = (gboolean *) g_malloc0(sizeof(gboolean) * NUM_COL_FMTS);
        get_column_format_matches(_cfile.cinfo.fmt_matx[i], _cfile.cinfo.col_fmt[i]);

        // allocate space for dissection results.
        _cfile.cinfo.col_data[i] = NULL;
        if ( (_cfile.cinfo.col_fmt[i] == COL_INFO) ||
             (_cfile.cinfo.col_fmt[i] == COL_INFO_PHYSICAL_LAYER) ||
             (_cfile.cinfo.col_fmt[i] == COL_INFO_NETWORK_LAYER) ||
             (_cfile.cinfo.col_fmt[i] == COL_INFO_TRANSPORT_LAYER) )
        {
            _cfile.cinfo.col_buf[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_INFO_LEN);
            _cfile.cinfo.col_expr[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_INFO_LEN);
            _cfile.cinfo.col_expr_val[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_INFO_LEN);
        }
        else
        {
            _cfile.cinfo.col_buf[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
            _cfile.cinfo.col_expr[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
            _cfile.cinfo.col_expr_val[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
        }
    }
    
    for (i = 0; i < _cfile.cinfo.num_cols; i++)
    {
        int j;

        for (j = 0; j < NUM_COL_FMTS; j++) {
           if (!_cfile.cinfo.fmt_matx[i][j])
               continue;

           if (_cfile.cinfo.col_first[j] == -1)
               _cfile.cinfo.col_first[j] = i;
           _cfile.cinfo.col_last[j] = i;
        }
    }
}

void Init()
{
    // create the environment variable so that it packet-radius can find the dictionary
    char szPath[512];
    char szDrive[_MAX_DRIVE];
    char szDir[_MAX_DIR];
    if (GetModuleFileName(NULL, szPath, 512) != 0)
    {
        _splitpath(szPath, szDrive, szDir, 0, 0);
        wsprintf(szPath, "%s%s", szDrive, szDir);
    }
    // set it to our current installed program dir
    SetEnvironmentVariable("APPDATA", szPath);

    //***************** should only be called once, JJL
    /* Register all dissectors; we must do this before checking for the
       "-G" flag, as the "-G" flag dumps a list of fields registered
       by the dissectors, and we must do it before we read the preferences,
       in case any dissectors register preferences. */
    epan_init("",register_all_protocols,register_all_protocol_handoffs,NULL,NULL,NULL);

    InitCFile(cfile);
    InitCFile(cfile_for_standalone);

    // Initialize all data structures used for dissection
    // note: we need to call this now (we didn't before) because it calls
    // epan_conversation_init() (we did call this previously) AND 
    // reassemble_init(). reassemble_init must now be called because a new
    // dissector (packet-fc.c) requires it so that certain g_mem_chunk_alloc
    //  calls will not fail (see packet-fc.c and reassemble.c in ethereal)
    init_dissection();
    init_all_protocols();
}

void Cleanup()
{
    CloseCapFile();
    epan_cleanup();
}

bool SupportsCaptureFileType(DecodeCaptureFileTypes eFileType)
{
    switch (eFileType)
    {
        case DECODE_FORMAT_APPDANCER:
        case DECODE_FORMAT_SNIFFER:
		case DECODE_FORMAT_PCAP:
			return true;
    }

    return false;
}

int OpenCapFile(const char* filename, unsigned int *pMediumType, unsigned int *pSubMediumType, unsigned int *pBandWidth)
{
    CloseCapFile();
	int retValue = false;
    s_pCapFile = new CWtapFile();
	retValue = s_pCapFile->OpenCapFile(filename);
    if (retValue == true)
    {
        *pMediumType = s_pCapFile->GetMediumType();
        *pSubMediumType = s_pCapFile->GetSubMediumType();
        *pBandWidth = s_pCapFile->GetBandwidth();
        return true;
    }
	return retValue;
   // return false;
}

void CloseCapFile()
{
    if (!s_pCapFile)
        return;
    
    s_pCapFile->CloseCapFile();
    delete s_pCapFile;
    s_pCapFile = NULL;
}

unsigned int GetNumberOfSegments()
{
    if (!s_pCapFile)
        return 0;
    
    return s_pCapFile->GetNumberOfSegments();
}

wchar_t * GetSegmentName(unsigned int segmentIndex)
{
    if (!s_pCapFile)
        return 0;

    return s_pCapFile->GetSegmentName(segmentIndex);
}

void SetMarked(unsigned int pktNum)
{
    if (!s_pCapFile)
        return;
    
    s_pCapFile->SetMarked(pktNum);
}
int GetMarked()
{
    if (!s_pCapFile)
        return -1;
    
    return s_pCapFile->GetMarked();
}

void ResolveAddresses(bool resolve)
{
    if (!s_pCapFile)
        return;
    
    s_pCapFile->ResolveAddresses(resolve);
}
//csa - added
void setnumwepKeys(int numkeys)
{
    if (!s_pCapFile)
        return;
    
    s_pCapFile->setnumwepKeys(numkeys);
}
void setwepKeysStr(unsigned char *wepkeystr,unsigned int keyindex, unsigned int length)
{
    if (!s_pCapFile)
        return;
    
    s_pCapFile->setwepKeysStr(wepkeystr,keyindex,length);
}

void setIpDscp(bool IpDscp)
{
    if (!s_pCapFile)
        return;
    
    s_pCapFile->setIpDscp(IpDscp);
}

//csa - added
void forceDocsis(bool bforceDocsis)
{
    if (!s_pCapFile)
        return;
    
    s_pCapFile->forceDocsis(bforceDocsis);
}
void forceProtocol(unsigned int forceEnable)
{
    if (!s_pCapFile)
        return;
    
    s_pCapFile->forceProtocol(forceEnable);
}
void forceProtocolRule(unsigned int force_start, unsigned int force_offset, unsigned int force_protocol)
{
    if (!s_pCapFile)
        return;
    
    s_pCapFile->forceProtocolRule( force_start,  force_offset,  force_protocol);
}
void setwimax(unsigned int wimaxState)
{
    if (!s_pCapFile)
        return;
    
    s_pCapFile->setwimax(wimaxState);
}
void PatternForceProtocol(bool isPatternEnable, long PatternOffset,  int* pattern, unsigned int PatternLength)
{
    if (!s_pCapFile)
        return;
    
    s_pCapFile->PatternForceProtocol( isPatternEnable, PatternOffset,  pattern,PatternLength);
}
//csa - 
void AddAddressName(unsigned int address, char *name)
{
    if (!s_pCapFile)
        return;

    s_pCapFile->AddAddressName(address, name);
}

void AddIpv6AddrName(unsigned char* address, char *name)
{
    if (!s_pCapFile)
        return;
    
    s_pCapFile->AddIpv6AddrName(address, name);
}

void AddDlcAddrName(unsigned char* address, char *name)
{
    if (!s_pCapFile)
        return;
    
    s_pCapFile->AddDlcAddrName(address, name);
}
void AddVendorName( char* vendorpath) 
{
     epan_AddVendorName(( char*)vendorpath);
}
void ApplyFilter(unsigned int * pktIndexArray, int numOfIndeces)
{
    if (!s_pCapFile)
        return;
    
    s_pCapFile->ApplyFilter(pktIndexArray, numOfIndeces);
}

void RemoveFilter()
{
    if (!s_pCapFile)
        return;
    
    s_pCapFile->RemoveFilter();
}

void AddDynamicPort(unsigned int appType, unsigned int ipPortNumber, bool bDefault)
{
    CPreScanProtocol::AddAppPort(appType, ipPortNumber, bDefault);
}

int GetNumOfPackets(bool ignoreFilter)
{
    if (!s_pCapFile)
        return 0;
    
    return s_pCapFile->GetNumOfPackets(ignoreFilter);
}

bool DecodePacketSummary(unsigned int pktNum, bool ignoreFilter)
{
    if (!s_pCapFile)
        return false;
    
    return s_pCapFile->DecodePacket(pktNum+1, true, ignoreFilter);
}

char* GetSummaryOutput(int index)
{
    if (!s_pCapFile)
        return 0;
    
    return s_pCapFile->GetSummaryOutput(index);
}

int GetProtocolId()
{
    if (!s_pCapFile)
        return 0;
    
    return s_pCapFile->GetProtocolId();
}

int GetProtocolIdForPacket(unsigned int pktNum, bool ignoreFilter)
{
    if (!s_pCapFile)
        return 0;
    
    return s_pCapFile->GetProtocolId(pktNum+1, ignoreFilter);
}

int GetNumOfColumns()
{
    return NUMBER_OF_SUMMARY_COL;
}

int DecodePacketDetail(unsigned int pktNum)
{
    if (!s_pCapFile)
        return 0;
    
    if (!s_pCapFile->DecodePacket(pktNum+1, false))
        return 0;
    
    return s_pCapFile->ParseDetailOutput();
}

char* GetDetailOutput(int lineIndex, int* depth, int* offsetStart, int* offsetLen, int* protocolId)
{
    if (!s_pCapFile)
        return 0;
    
    return s_pCapFile->GetDetailOutput(lineIndex, depth, offsetStart, offsetLen, protocolId);
}

int GetUnfilteredPacketNumber(unsigned int pktNum)
{
    if (!s_pCapFile)
        return 0;

    return s_pCapFile->GetRealPktNum(pktNum+1) - 1;
}

int GetPacketPosition(unsigned int pktNum, bool matchClosest)
{
    if (!s_pCapFile)
        return 0;
    
    return s_pCapFile->GetPacketPosition(pktNum+1, matchClosest);
}

unsigned char* GetPacket(
    unsigned int pktNum, 
    int* pPktSize, 
    unsigned int* pAbsSecs, 
    unsigned int* pAbsUsecs, 
    unsigned int* pAbsNsecs, 
    bool ignoreFilter, 
    unsigned int *pChannel, 
    unsigned int *pErrorStatus,
    unsigned int *pPacketStatus,
    unsigned int *pSegment,int* pWholePktSize) 
{
    if (!s_pCapFile)
        return 0;
    
    return s_pCapFile->GetPacket(
        pktNum+1,
        pPktSize,
        pAbsSecs,
        pAbsUsecs,
        pAbsNsecs,
        ignoreFilter,
        pChannel,
        pErrorStatus,
        pPacketStatus,
        pSegment,pWholePktSize);
}

int BulkGetPackets(
    unsigned int startPktNum, 
    unsigned int maxPackets,
    char * rawDataBuffer,
    unsigned int rawDataBufferSize,
    unsigned int parameterArraySize, 
    unsigned int* pktSizeArray,
    unsigned int* absSecsArray,
    unsigned int* absUsecsArray,
    unsigned int* absNsecsArray,
    unsigned int* channelArray,
    unsigned int* errorStatusArray,
    unsigned int* packetStatusArray,
    unsigned int* segmentArray,
    unsigned int* pktWholeSizeArray)
{
    if (!s_pCapFile)
        return 0;
    
    return s_pCapFile->BulkGetPackets(
        startPktNum+1, 
        maxPackets,
        rawDataBuffer,
        rawDataBufferSize,
        parameterArraySize, 
        pktSizeArray,
        absSecsArray,
        absUsecsArray,
        absNsecsArray,
        channelArray,
        errorStatusArray,
        packetStatusArray,
        segmentArray,
		pktWholeSizeArray);
}    

bool WriteCapFileId(const char* filename, DecodeCaptureFileTypes eFileType, bool ignoreFilter)
{
    if (!s_pCapFile)
        return false;
    
    return s_pCapFile->WriteCapFile(filename, eFileType, ignoreFilter);
}

bool WriteCapFileName(const char* filename, const char * fileTypeName, bool ignoreFilter)
{
    if (!s_pCapFile)
        return false;
    
    return s_pCapFile->WriteCapFile(filename, fileTypeName, ignoreFilter);
}

extern bool TiePort(const char * protocolName, int port)
{
    return CWtapFile::TiePort(protocolName, port);
}

int GetRealSearchStartPktNum(int startPktNum, bool allowWrapping)
{
    if (GetNumOfPackets(false) == 0)
        return -1;
    
    int newStartPktNum = GetPacketPosition(startPktNum, true) + 1; //fixed bug3859-Get the packet position in case of filter has been used

    if (newStartPktNum >= GetNumOfPackets(false))
    {
        if (!allowWrapping)
            return -1;
        newStartPktNum = 1;
    }

    return newStartPktNum;
}

int SearchPacketDataHex(char * hexSearchData, int searchDataSize, int startPktNum, bool allowWrapping)
{
    if (!s_pCapFile)
        return 0;
    
    // the startPktNum passed in is already 1-based. we really want to start searching from
    // the next packet number, however, so it must be incremented (and wrapped if necessary)
    int realStartPktNum = GetRealSearchStartPktNum(startPktNum, allowWrapping);
    if (realStartPktNum < 0)
        return 0;
    
    return s_pCapFile->SearchPacketDataHex(
        hexSearchData, searchDataSize, realStartPktNum, allowWrapping);
}

int SearchPacketDataASCII(char * asciiSearchData, int searchDataSize, int startPktNum, bool allowWrapping)
{
    if (!s_pCapFile)
        return 0;

    // the startPktNum passed in is already 1-based. we really want to start searching from
    // the next packet number, however, so it must be incremented (and wrapped if necessary)
    int realStartPktNum = GetRealSearchStartPktNum(startPktNum, allowWrapping);
    if (realStartPktNum < 0)
        return 0;
    
    return s_pCapFile->SearchPacketDataASCII(
        asciiSearchData, searchDataSize, realStartPktNum, allowWrapping);
}

int SearchSummaryColumn(char *searchData, int searchDataSize, int startPktNum, bool allowWrapping)
{
    if (!s_pCapFile)
        return 0;
    
    // the startPktNum passed in is already 1-based. we really want to start searching from
    // the next packet number, however, so it must be incremented (and wrapped if necessary)
    int realStartPktNum = GetRealSearchStartPktNum(startPktNum, allowWrapping);
    if (realStartPktNum < 0)
        return 0;
    
    return s_pCapFile->SearchColumn(
        searchData,
        searchDataSize,
        SUMMARY_COL_INFO,
        realStartPktNum,
        allowWrapping);
}

int SearchDetail(char *searchData, int searchDataSize, int startPktNum, bool allowWrapping)
{
    if (!s_pCapFile)
        return 0;

    // the startPktNum passed in is already 1-based. we really want to start searching from
    // the next packet number, however, so it must be incremented (and wrapped if necessary)
    int realStartPktNum = GetRealSearchStartPktNum(startPktNum, allowWrapping);
    if (realStartPktNum < 0)
        return 0;
    
    return s_pCapFile->SearchDetail(searchData, searchDataSize, realStartPktNum, allowWrapping);
}

int GetSearchResultCode(int sessionId)
{
    if (!s_pCapFile)
        return 0;
    
    return s_pCapFile->GetSearchResultCode(sessionId);
}    

int GetSearchPacketNumber(int sessionId)
{
    if (!s_pCapFile)
        return 0;
    
    return s_pCapFile->GetSearchPacketNumber(sessionId);
}    

int GetSearchStartOffset(int sessionId)
{
    if (!s_pCapFile)
        return 0;
    
    return s_pCapFile->GetSearchStartOffset(sessionId);
}    

int GetSearchEndOffset(int sessionId)
{
    if (!s_pCapFile)
        return 0;
    
    return s_pCapFile->GetSearchEndOffset(sessionId);
}    

int GetSearchLineIndex(int sessionId)
{
    if (!s_pCapFile)
        return 0;
    
    return s_pCapFile->GetSearchLineIndex(sessionId);
}    

void ContinueSearch( int sessionId )
{
    if (!s_pCapFile)
        return;
    
    s_pCapFile->ContinueSearch( sessionId );
}

void DoneSearching( int sessionId )
{
    if (!s_pCapFile)
        return;
    
    s_pCapFile->DoneSearching( sessionId );
}
 

StandaloneDecoder & GetStandaloneDecoder()
{
    if (!s_pStandaloneDecoder)
        s_pStandaloneDecoder = new StandaloneDecoder(cfile_for_standalone);

    return *s_pStandaloneDecoder;
}

bool DecodePacketSummaryStandalone(
    unsigned char *rawPacketData,
    unsigned int rawPacketDataLength,
    unsigned int packetNumber,
    unsigned int *timeInfo,
    char *retSummaryBuffer,
    unsigned int retSummaryBufferLength,
    unsigned int *retSummaryDataLength,
    int *retProtocolId, unsigned int channel, unsigned int segment)
{
    StandaloneDecoder & standaloneDecoder = GetStandaloneDecoder();

    return standaloneDecoder.DecodeSummary(
        rawPacketData, rawPacketDataLength, packetNumber,
        timeInfo,
        retSummaryBuffer, retSummaryBufferLength,
        retSummaryDataLength,
        retProtocolId, channel, segment);
}


bool DecodePacketDetailStandalone(
        unsigned char *rawPacketData, 
        unsigned int rawPacketDataLength,
        unsigned int packetNumber,
        char * retCharDataBuffer, 
        unsigned int charDataBufferSize,
        unsigned int * retNumberOfLines,
        unsigned int * retStringIndexArray,
        unsigned int * retDepthArray,
        unsigned int * retOffsetStartArray,
        unsigned int * retOffsetLenArray,
        int * retProtocolIdArray,
        unsigned int arraySizes)
{
    StandaloneDecoder & standaloneDecoder = GetStandaloneDecoder();

    return standaloneDecoder.DecodePacketDetail(
        rawPacketData,
        rawPacketDataLength,
        packetNumber,
        retCharDataBuffer,
        charDataBufferSize,
        retNumberOfLines,
        retStringIndexArray,
        retDepthArray,
        retOffsetStartArray,
        retOffsetLenArray,
        retProtocolIdArray,
        arraySizes);
}
           


