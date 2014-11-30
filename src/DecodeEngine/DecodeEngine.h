
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
#ifndef __DECODE_ENGINE_H__
#define __DECODE_ENGINE_H__
#define MAX_WEPKEYS 4
    typedef enum {DECODE_CAPABILITY_DISSECT=1, DECODE_CAPABILITY_BULK_GET} DecodeCapabilities;
    typedef enum {DECODE_FORMAT_APPDANCER=0, DECODE_FORMAT_SNIFFER, DECODE_FORMAT_PCAP, DECODE_FORMAT_NSEC_PCAP,DECODE_FORMAT_SCAP,DECODE_FORMAT_CAP} DecodeCaptureFileTypes;

    void Init();
    void Cleanup();
    int OpenCapFile(const char* filename, unsigned int *pMediumType, unsigned int *pSubMediumType, unsigned int *pBandWidth);
    void CloseCapFile();
    unsigned int GetNumberOfSegments();
    wchar_t * GetSegmentName(unsigned int segmentIndex);
    void ResolveAddresses(bool resolve);
    void setIpDscp(bool IpDscp);
    void forceDocsis(bool bforceDocsis);
	// for protocol forcing [4/28/2006 Ken]
	void force_protocol_enable(int force_enable);
	void force_protocol_rule(int force_start, int force_offset, int force_protocol);

    void AddAddressName(unsigned int address, char *name);
    void AddIpv6AddrName(unsigned char* address, char *name);
    void AddDlcAddrName(unsigned char* address, char *name);
    void AddVendorName( char *path);
    void ApplyFilter(unsigned int * pktIndexArray, int numOfIndeces);
    void RemoveFilter();
    int GetNumOfPackets(bool ignoreFilter);
    bool DecodePacketSummary(unsigned int pktNum, bool ignoreFilter);
    char* GetSummaryOutput(int index);
    int GetProtocolId();
    int GetProtocolIdForPacket(unsigned int pktNum, bool ignoreFilter);
    int GetNumOfColumns();
    int DecodePacketDetail(unsigned int pktNum);
    char* GetDetailOutput(int lineIndex, int* depth, int* offsetStart, int* offsetLen, int* protocolId);
    int GetPacketPosition(unsigned int pktNum, bool matchClosest);
    int GetUnfilteredPacketNumber(unsigned int pktNum);
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
        unsigned int *channelArray,
        unsigned int *errorStatusArray,
        unsigned int *packetStatusArray,
        unsigned int *segmentArray,
        unsigned int* WholepktSizeArray
		);
    bool WriteCapFileId(const char* filename, DecodeCaptureFileTypes eFileType, bool ignoreFilter);
    bool WriteCapFileName(const char* filename, const char * fileTypeName, bool ignoreFilter);
    bool TiePort(const char * protocolName, int port);
    void SetMarked(unsigned int pktNum);
    int GetMarked();
    void forceProtocol(unsigned int forceEnable);
    void forceProtocolRule(unsigned int force_start, unsigned int force_offset, unsigned int force_protocol); 
    void setwimax(unsigned int wimaxState);
	void PatternForceProtocol(bool isPatternEnable, long PatternOffset,  int* pattern, unsigned int PatternLength);
    bool IsCapable(DecodeCapabilities eCapability);
    bool SupportsCaptureFileType(DecodeCaptureFileTypes eFileType);

    typedef enum {PACKET_FOUND, PACKET_NOT_FOUND, SEARCH_ERROR, STILL_SEARCHING} DecodeSearchResultCode;

    // search methods
    // WARNING! when you are done searching you must call DoneSearching(...) to 
    // free any DecodeSearchState object to avoid a memory leak.
    int SearchPacketDataHex(char * hexSearchData, int searchDataSize, int startPktNum, bool allowWrapping);
    int SearchPacketDataASCII(char * asciiSearchData, int searchDataSize, int startPktNum, bool allowWrapping);
    int SearchSummaryColumn(char *searchData, int searchDataSize, int startPktNum, bool allowWrapping);
    int SearchDetail(char *searchData, int searchDataSize, int startPktNum, bool allowWrapping);
    int GetSearchResultCode(int searchSessionId);
    int GetSearchPacketNumber(int searchSessionId);
    int GetSearchStartOffset(int searchSessionId);
    int GetSearchEndOffset(int searchSessionId);
    int GetSearchLineIndex(int searchSessionId);
    void ContinueSearch(int searchSessionId);
    void DoneSearching(int searchSessionId);

    void AddDynamicPort(unsigned int appType, unsigned int ipPortNumber, bool bDefault);
    void setnumwepKeys(int numkeys);
    void setwepKeysStr(unsigned char *wepkeystr, unsigned int keyindex,unsigned int len);

    bool DecodePacketSummaryStandalone(
        unsigned char *rawPacketData,
        unsigned int len,
        unsigned int packetNumber,
        unsigned int *timeInfoArray,
        char *retSummaryBuffer,
        unsigned int retSummaryBufferLength,
        unsigned int * retSummaryDataLength,
        int *retProtocolId, unsigned int channel, unsigned int segment);

    bool DecodePacketDetailStandalone(
        unsigned char *rawPacketData, // points to a byte array containing packet data
        unsigned int rawPacketDataLength, // length of packet data array
        unsigned int packetNumber,
        char * retCharDataBuffer, // buffer to receive all label strings (concatenated)
        unsigned int charDataBufferSize, // size of retCharDataBuffer
        unsigned int * retNumberOfLines, // points one int for returning number of lines
        unsigned int * retStringIndexArray, // points to array for storing label start indeces
        unsigned int * retDepthArray, // points to array for storing label depths
        unsigned int * retOffsetStartArray, // points to array for storing packet offset starts
        unsigned int * retOffsetLenArray, // points to array for storing packet offset/lengths
        int * protocolIdArray, // points to array for storing protocol ids
        unsigned int arraySizes); // indicates size the 5 per-line arrays
    
#endif
