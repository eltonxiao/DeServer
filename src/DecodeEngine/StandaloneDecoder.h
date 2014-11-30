#ifndef __STANDALONE_DECODER_H__
#define __STANDALONE_DECODER_H__

class StandaloneDecoder
{
public:

    StandaloneDecoder(capture_file &captureFile) :
        m_standaloneFile(captureFile)
    {
		m_pPktDataBuf = NULL;
		m_pPktDataBufSize = 0;
	}

	virtual ~StandaloneDecoder()
	{
		if (m_pPktDataBuf)
		{
			delete m_pPktDataBuf;
		}
		m_pPktDataBuf = NULL;
		m_pPktDataBufSize = 0;
	}

    bool DecodeSummary(
        unsigned char *rawPacketData,
        unsigned int rawPacketDataLength,
        unsigned int packetNumber,
        unsigned int *timeInfoArray,
        char *retSummaryBuffer,
        unsigned int retSummaryBufferLength,
        unsigned int *retSummaryDataLength,
        int *retProtocolId, unsigned int channel, unsigned int segment,unsigned long datalinktype=0);

    bool DecodePacketDetail(
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
		int * retDsIndexArray,
        unsigned int arraySizes);

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

private:
    
    void InitializeCurrentFrame(
        unsigned char * rawPacketData,
        unsigned int rawPacketDataLength,
        unsigned int packetNumber,
        unsigned int * timeInfoArray);

    boolean FillSummaryBuffer(
        char *retSummaryBuffer,
        unsigned int retSummaryBufferLength,
        unsigned int *retSummaryDataLength,
        int *retProtocolId);

    int ParseDetailOutput(
        char *targetCharBuffer,
        unsigned int targetCharBufferSize,
        unsigned int *stringIndexArray,
        unsigned int *depthArray,
        unsigned int *offsetStartArray,
        unsigned int *offsetLenArray,
        int *protocolIdArray,
		int * dsIndexArray,
        int arraySizes);

    void ParseProtocolTree(proto_node *node, DetailResultsCompiler *compiler);

    capture_file & m_standaloneFile;
	guint8 * m_pPktDataBuf;
	unsigned int m_pPktDataBufSize;
};

#endif
