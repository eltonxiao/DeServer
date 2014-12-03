
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
#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <glib.h>
#include "wtap.h"
#include "wtap-int.h"
#include "packet.h"
#include "file.h"
#include "DecodeEngine.h"
//copy from IEEEdef.h
typedef enum _NETWORK_MEDIUM_E
{
	NetworkMediumEthernet,
	NetworkMediumTokenRing,
	NetworkMediumFddi,
	NetworkMediumWan,
	NetworkMediumAtm,
	NetworkMediumPPP=9,//added by wzheng for ppp protocols
	NetworkMediumWireless=10,
	NetworkMediumWiMax,
	NetworkMediumCHDLC
}	NETWORK_MEDIUM_E;

#ifdef __cplusplus
}
#endif /* __cplusplus */

#include "DecodePreScan.h"
#include "DecodeIp.h"

class CWtapFrameInfo
{
public:
    frame_data* m_fdata;
    int m_protocolId;
};


class DecodeSearchState
{
    public:

        DecodeSearchState()
        {
            searchState = 0;
        }

        DecodeSearchResultCode result;
        int packetNumber;
        int startOffset;
        int endOffset;
        int lineIndex;
        class InternalSearchState * searchState;

        ~DecodeSearchState();
};    

class InternalSearchState
{
    public:

        InternalSearchState() {
            packetNumber = -1;
            startPacketNumber = -1;
            startOffset = -1;
            endOffset = -1;
            columnIndex = -1;
            lineIndex = -1;
            searchData = 0;
            searchDataIndex = 0;
            searchDataBufSize = 0;
            searchResult = SEARCH_ERROR;
            allowWrapping = true;
        }

        typedef enum {HEX_DATA_SEARCH, ASCII_DATA_SEARCH, COLUMN_SEARCH, PROTO_TREE_SEARCH} SearchType;
        void SetSearchType( SearchType type ) {searchType = type;}
        SearchType GetSearchType() {return searchType;}

        void SetSearchResult(DecodeSearchResultCode result) {searchResult=result;}
        DecodeSearchResultCode GetSearchResult() {return searchResult;}

        void SetPacketNumber(int number) {packetNumber=number;}
        int GetPacketNumber() {return packetNumber;}
        void IncPacketNumber() {packetNumber++;}

        void SetStartPacketNumber(int number) {startPacketNumber=number;}
        int GetStartPacketNumber() {return startPacketNumber;}

        void SetAllowWrapping(bool allow) {allowWrapping=allow;}
        bool AllowWrapping() {return allowWrapping;}

        void SetStartOffset(int offset) {startOffset=offset;}
        int GetStartOffset() {return startOffset;}

        void SetEndOffset(int offset) {endOffset=offset;}
        int GetEndOffset() {return endOffset;} 

        void SetColumnIndex(int index) {columnIndex=index;}
        int GetColumnIndex() {return columnIndex;}

        void SetLineIndex(int index) {lineIndex=index;}
        int GetLineIndex() {return lineIndex;}
        void IncLineIndex() {lineIndex++;}

        int PacketsPerSearch() {return 100;}

        void AllocateSearchData(int bufSize) {
            delete [] searchData;
            searchData = new guint8[bufSize];
            searchDataBufSize = bufSize;
            searchDataIndex = 0;
        }
        void AddSearchData(guint8 value) {searchData[searchDataIndex++] = value;}

        void CopySearchData(guint8 * inSearchData, int length) {
            AllocateSearchData(length);
            memcpy( searchData, inSearchData, length );
            searchDataIndex = length;
        }

        guint8 * GetSearchDataPtr() {return searchData;}
        int GetSearchDataSize() {return searchDataIndex;}

        
        void FillInDecodeSearchState(DecodeSearchState *pDecodeSearchState) {
            pDecodeSearchState->result = searchResult;
            pDecodeSearchState->packetNumber = packetNumber - 1; // externalized packet numbers are 0-based
            pDecodeSearchState->startOffset = startOffset;
            pDecodeSearchState->endOffset = endOffset;
            pDecodeSearchState->lineIndex = lineIndex;
            pDecodeSearchState->searchState = this;
        }

        ~InternalSearchState () {
            delete [] searchData; searchData = 0;
        }
         
    private:

        // members used by all searches
        SearchType searchType;
        DecodeSearchResultCode searchResult;
        int packetNumber;
        int startPacketNumber;
        bool allowWrapping;
        guint8 * searchData;
        int searchDataBufSize;        
        int searchDataIndex;

        // members used by some searches
        int columnIndex; // for column searches
        int lineIndex; // for proto-tree searches
        int startOffset;
        int endOffset;
};


class CWtapFile
{
public:
    CWtapFile();
    ~CWtapFile();

    int OpenCapFile(const char* filename, bool bPreScan=FALSE);
    void CloseCapFile();

    unsigned int GetNumberOfSegments();
    wchar_t * GetSegmentName(unsigned int segmentIndex);
    
    static void ResolveAddresses(bool resolve);
    static void setIpDscp(bool IpDscp);
    static void forceDocsis(bool bforceDocsis);
    static void force_protocol_enable(int force_enable);
    static void force_protocol_rule(int force_start, int force_offset, int force_protocol);
    static void AddAddressName(unsigned int address, char *name);
    static void AddIpv6AddrName(unsigned char* address, char *name);
    static void AddDlcAddrName(unsigned char* address, char *name);
    static void AddVendorName( char *path);
    void ApplyFilter(unsigned int * pktIndexArray, int numOfIndeces);
    void RemoveFilter();
    int GetNumOfPackets(bool ignoreFilter) const;
    bool DecodePacket(unsigned int pktNum, bool bSummaryOnly=true, bool ignoreFilter=false);
    char* GetSummaryOutput(int index);
    int GetProtocolId(); // -1=unknown 
    int GetProtocolId(unsigned int pktNum, bool ignoreFilter);
    int ParseDetailOutput();
    char* GetDetailOutput(int lineIndex, int* depth, int* offsetStart, int* offsetLen, int* protocolId, int *dsIndex);
    unsigned int GetRealPktNum(unsigned int pktNum);
    int GetPacketPosition(unsigned int pktNum, bool matchClosest);
    void SetMarked(unsigned int pktNum);
    int GetMarked();
    static void forceProtocol(unsigned int forceEnable);
    static void forceProtocolRule(unsigned int force_start, unsigned int force_offset, unsigned int force_protocol);
    static void setwimax(unsigned int wimaxState);
    static void PatternForceProtocol(bool isPatternEnable, long PatternOffset,  int* pattern, unsigned int PatternLength);
    static void setLwappSwapFrameControl(bool isSwaped);
    static void SetDTMFPayloadValue(int payloadValue);
    static void setQinQEtherType(unsigned short EtherType);
    static void setGtpuTypePort(bool bGtpuOverTcp, unsigned short port);
    static void setPBBEtherType(unsigned short EtherType);	
    //Antonio 2007-10-19, for IPsec
    static void setAttemptToDecodeEspPayload(bool bEnable);
    static void setAttemptToCheckEspAuthentication(bool bEnable);
    static void clearEspParamSet(void);
    static void addEspParamSet(int addressType, const char * sourceAddress, const char * destinationAddress, 
    	                       const char * securityParameterIndex, int encryptionAlgorithm, const char * encryptionKey,
    	                       int authenticationAlgorithm, const char * authenticationKey);

	
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
        unsigned int *pSegment,
        int * pWholePktSize);

    unsigned char* GetPacketDecryption(
        unsigned int pktNum,
        unsigned int dsIndex,
        int* pPktSize, 
        unsigned int* pAbsSecs, 
        unsigned int* pAbsUsecs, 
        unsigned int* pAbsNsecs, 
        bool ignoreFilter, 
        unsigned int *pSegment);

    int GetPacketDataSourceCount(unsigned int pktNum);

    char* GetDataSourceName(int dsIndex);
    
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
        unsigned int* wholePktSizeArray);

    // 0=appdancer format, 1=NG sniffer
    bool WriteCapFile(const char* filename, DecodeCaptureFileTypes eFileType, bool disableFilter);
    bool WriteCapFile(const char* filename, const char * targetFileTypeName, bool disableFilter);

    // search methods
    int SearchPacketDataHex(char * inHexSearchData, int searchSize, int startPktNum, bool allowWrapping);
    int SearchPacketDataASCII(char * asciiSearchData, int searchSize, int startPktNum, bool allowWrapping);
    int SearchColumn(char * searchData, int searchDataSize, int columnIndex, int startPktNum, bool allowWrapping);
    int SearchDetail(char * searchData, int searchDataSize, int startPktNum, bool allowWrapping);
    void ContinueSearch(int searchSessionId);
    void DoneSearching(int searchSessionId);

    // query search results
    int GetSearchResultCode(int sessionId);
    int GetSearchPacketNumber(int sessionId);
    int GetSearchStartOffset(int sessionId);
    int GetSearchEndOffset(int sessionId);
    int GetSearchLineIndex(int sessionId);
    int GetLastPktNum() const;
    int GetFirstPktNum() const;

    static bool TiePort(const char * protocolName, int port);
    static void UnTiePort(unsigned short port);// added by xulei for bug#5986
    static void setnumwepKeys(int numkeys);
    static void setwepKeysStr(guint8 *wepkeystr,unsigned int keyindex, unsigned int len);

    inline gint64 GetCapFileSize() 
    {
        //return m_nFileSize;
        return m_pCapFile->wth->data_offset;
    };

    inline unsigned int GetCrcSize() 
    {
        return m_pCapFile->wth->crc_size;
    };

    int GetTriggerFrameIndex();
    bool IsShomitiFile();
		
    inline unsigned int GetSubMediumType()
    {
        return m_pCapFile->wth->first_segment.subMediumType;
    };

    /*
    inline void SetSubMediumType(unsigned int type)
    {
        m_subMediumType = type;
    };
    */

    inline unsigned int GetMediumType()
    {
        if ((m_pCapFile->wth->file_encap == WTAP_ENCAP_IEEE_802_11_WITH_RADIO) || //wireless
            (m_pCapFile->wth->file_encap == WTAP_ENCAP_IEEE_802_11))
            m_pCapFile->wth->first_segment.mediumType = NetworkMediumWireless;
        else if (m_pCapFile->wth->file_encap == WTAP_ENCAP_PPP)
            m_pCapFile->wth->first_segment.mediumType = NetworkMediumPPP;
        else if (m_pCapFile->wth->file_encap == WTAP_ENCAP_CHDLC)
            m_pCapFile->wth->first_segment.mediumType = NetworkMediumCHDLC;
        else
            m_pCapFile->wth->first_segment.mediumType = NetworkMediumEthernet;
        return m_pCapFile->wth->first_segment.mediumType;
    };

    /*
    inline void SetMediumType(unsigned int type)
    {
        m_mediumType = type;
    };
    */

    inline unsigned int GetBandwidth()
    {
        return m_pCapFile->wth->first_segment.bandwidth;
    };
    
    inline unsigned int GetOption()
    {
        return m_pCapFile->wth->first_segment.option;
    };

    /*
    inline void SetBandwidth(unsigned int bandwidth)
    {
        m_nBandwidth = bandwidth;
    };
    
    inline void SetOption(unsigned int option)
    {
        m_nOption = option;
    };  
    */
    
    static int LookupProtocolId(char *protocolShortName);

    static void InitCFile(capture_file &_cfile);
    static void Init();
    static void Cleanup();
    
private:

    inline void PreScanInit();
    inline void PreScanTerminate();
    inline bool IsPreScanOn();
    inline void PreScanProcess(unsigned char *pFrameStart, int frameLen);
    
    inline bool IsNameResolvingOn();
    inline void SetNameResolving(bool enabled);
    inline void NameResolvingProcess(unsigned char *pFrameStart, int frameLen);

    void CopySegmentInfo(wtap_dumper *wtap_dumper, wtap *wtap);

    CDecodePreScan *m_pDecodePreScan;
    bool           m_bNameResolving;
    bool            m_bIsGigabit;
    //    unsigned int    m_mediumType;
    //    unsigned int    m_subMediumType;
    //    unsigned int    m_nBandwidth;
    //    unsigned int    m_nOption;

    capture_file* m_pCapFile;
    CWtapFrameInfo* m_pFrameInfos1;
    CWtapFrameInfo* m_pFrameInfos2;
    int    m_iSplitPoint;
    unsigned char* m_pPktDataBuf;    //use this to pass packet data back to caller
    int m_pPktDataBufSize;
    unsigned int m_lastPktNumDecoded; //always a real packet number - ie, not filtered
    unsigned int m_maxPktNumDecoded;
    gint64   m_nFileSize;

    unsigned int m_markedPktNum;     //marked packet number
    int m_triggerPktNum;    //trigger frame packet number , 1 based, -1 mean not exit trigger frame

    unsigned int * m_pPacketFilterIndexArray;
    unsigned int m_numberOfFilterIndeces;

    bool DecodePacket(frame_data *fdata, frame_data *first_fdata, frame_data *prev_fdata, bool bSummaryOnly, int &protocolId);
    void ParseProtocolTree(proto_node *node, GSList *&list);
    bool ReadNextPacket();
    frame_data* GetFrameData(unsigned int pktNum, bool ignoreFilter=false);
    bool WriteCapFileInternal(const char* filename, int etherealFiletype, bool ignoreFilter);

    // search support
    enum {NUMBER_OF_SEARCH_SESSION_SLOTS=10};
    DecodeSearchState * searchSessionSlots[NUMBER_OF_SEARCH_SESSION_SLOTS];
    void SearchPacketDataBinary( InternalSearchState * pSearchState );
    void SearchColumnData( InternalSearchState *pSearchState );
    void SearchProtoTreeData( InternalSearchState *pSearchState );
    bool SearchForData(
        guint8 *packetData,
        unsigned int packetDataSize,
        guint8 *searchData,
        unsigned int searchDataSize,
        int & startOffset,
        int & endOffset );
    int CreateNewSearchSession(DecodeSearchState *pDecodeSearchState);
    DecodeSearchState * GetSearchStateFromSessionId(int searchSessionId);
    void CleanupSearchSession(int searchSessionId);

    void SetProtocolId(unsigned int pktNum, int protocolId, bool ignoreFilter);
};

