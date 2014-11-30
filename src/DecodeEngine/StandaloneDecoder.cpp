#include "StdAfx.h"
#ifndef __CS_LINUX

        // undefine the TRY, CATCH, etc macros defined for MFC - they conflict
        // with ethereal definitions
        #include "UndefineTryCatch.h"
#else
	#include <pthread.h>
        #include <arpa/inet.h>

        #include <boost/thread/thread.hpp>
        #include <boost/thread/mutex.hpp>
        #include <boost/thread/tss.hpp>
        #include <cstdio>
#include <string.h>
#include <stdlib.h>
        #include "decode_predef.h"
#endif

#include "PreScanProtocol.h"
#include "wtapFile.h"
#include "DetailResultsCompiler.h"

extern "C"
{
    #include "packet.h"
    #include "file.h"
    #include "util.h"
    #include "column.h"
    #include "timestamp.h"
    #include "register.h"
    #include "epan.h"
    #include "epan_dissect.h"
    #include "SummaryCols.h"   // alpha in A a format...
	#include "nstime.h" 
	void nstime_delta(nstime_t *delta, const nstime_t *b, const nstime_t *a );

}

#include "StandaloneDecoder.h"

bool StandaloneDecoder::DecodeSummary(
    unsigned char *rawPacketData,
    unsigned int rawPacketDataLength,
    unsigned int packetNumber,
    unsigned int *timeInfoArray,
    char *retSummaryBuffer,
    unsigned int retSummaryBufferLength,
    unsigned int *retSummaryDataLength,
    int *retProtocolId, unsigned int channel, unsigned int segment,
	unsigned long datalinktype)
{
    if (m_standaloneFile.edt != 0)
    {
        epan_dissect_free(m_standaloneFile.edt);
        m_standaloneFile.edt = 0;
    }

    m_standaloneFile.edt = epan_dissect_new(false, false);

    InitializeCurrentFrame(
        rawPacketData, rawPacketDataLength, packetNumber,
        timeInfoArray);

    epan_dissect_run(
        m_standaloneFile.edt,
        &m_standaloneFile.pseudo_header,
        m_standaloneFile.pd,
        m_standaloneFile.current_frame,
        &m_standaloneFile.cinfo);

    m_standaloneFile.edt->pi.fd->channel = channel;
    m_standaloneFile.edt->pi.fd->segment = segment;

    epan_dissect_fill_in_columns(m_standaloneFile.edt, true, true);

    if (!FillSummaryBuffer(
            retSummaryBuffer,
            retSummaryBufferLength,
            retSummaryDataLength,
            retProtocolId))
    {
        return false;
    }

    return true;
}

bool StandaloneDecoder::DecodePacketDetail(
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
		int* retDsIndexArray,
        unsigned int arraySizes)
{
    if (m_standaloneFile.edt != 0)
    {
        epan_dissect_free(m_standaloneFile.edt);
        m_standaloneFile.edt = 0;
    }

    m_standaloneFile.edt = epan_dissect_new(true, true);

    unsigned int timeInfo[6];
    memset((void *) timeInfo, 0, sizeof(timeInfo));

    epan_dissect_run(
        m_standaloneFile.edt,
        &m_standaloneFile.pseudo_header,
        m_standaloneFile.pd,
        m_standaloneFile.current_frame,
        0);

    *retNumberOfLines = ParseDetailOutput(
        retCharDataBuffer,
        charDataBufferSize,
        retStringIndexArray,
        retDepthArray,
        retOffsetStartArray,
        retOffsetLenArray,
        retProtocolIdArray,
		retDsIndexArray,
        arraySizes);

    return (*retNumberOfLines == -1) ? false : true;
}

void StandaloneDecoder::InitializeCurrentFrame(
    unsigned char * rawPacketData,
    unsigned int rawPacketDataLength,
    unsigned int packetNumber,
    unsigned int * timeInfoArray) // items 0-2 are absolute time, 3-5 are prev abs time
{
    // if there is no currently allocated frame_data structure
    // attached to the standalone cfile then create one now.
    // the frame data structure contains information about
    // the frame - most of which will be zero for standalone
    // frames.

	static bool initialized = false;
    static bool bFirstPacketInThis = true;
	/*USE modified
	static int startnsecs=0;
	time_t startSecs=0;
	*/
	static nstime_t start_ts;

    //now use time of start capture instead,every click start button should update start capture time.
    //timeInfoArray[6] startCaptureTime secs
    //timeInfoArray[7] startCaptureTime Usecs
    //timeInfoArray[8] startCaptureTime Nsecs
	start_ts.secs = timeInfoArray[6]; 
	start_ts.nsecs = timeInfoArray[8];  //USE modified	

	// note: this frame data is never released but is only
    // allocated once.
    if (m_standaloneFile.current_frame == 0)
    {
        m_standaloneFile.current_frame = new frame_data;
        memset(m_standaloneFile.current_frame, 0, sizeof(frame_data));
    }

    m_standaloneFile.current_frame->pkt_len = rawPacketDataLength;
    m_standaloneFile.current_frame->cap_len = rawPacketDataLength;

    m_standaloneFile.current_frame->num = packetNumber;

	m_standaloneFile.current_frame->abs_ts.secs = timeInfoArray[0];
	m_standaloneFile.current_frame->abs_ts.nsecs = timeInfoArray[2];

  /*
	if( packetNumber == 1 )
	{
		m_standaloneFile.current_frame->del_ts.secs = 0;
		m_standaloneFile.current_frame->del_ts.nsecs = 0;
	}
	else
    
	{
        *//*  USE modified
		compute_timestamp_diff(
			&m_standaloneFile.current_frame->del_ts.secs,
			&m_standaloneFile.current_frame->del_ts.nsecs,
			timeInfoArray[0], // abs_secs (current frame)
			timeInfoArray[1], // abs_usecs (current frame),
			timeInfoArray[3], // abs-secs (prev frame)
			timeInfoArray[4]); // abs_usecs (prev frame)*/
		  /* Get the time elapsed between the first packet and this packet. */
       /*
		nstime_t  prev_ts;
		prev_ts.secs = timeInfoArray[3];
		prev_ts.nsecs = timeInfoArray[5];
		nstime_delta(&m_standaloneFile.current_frame->del_ts,
			         &m_standaloneFile.current_frame->abs_ts,
			         &prev_ts);
	}
*/
        if (bFirstPacketInThis)
        {
            nstime_delta(&m_standaloneFile.current_frame->del_dis_ts,
                &m_standaloneFile.current_frame->abs_ts,
                &start_ts);
            bFirstPacketInThis = false;
        }
        else
        {
            nstime_t  prev_ts;
            prev_ts.secs = timeInfoArray[3];
            prev_ts.nsecs = timeInfoArray[5];
            nstime_delta(&m_standaloneFile.current_frame->del_dis_ts,
                &m_standaloneFile.current_frame->abs_ts,
                &prev_ts);

        }

	// relative time was not being updated previously which is why it was zero in realtime
	// USE modified
	/*compute_timestamp_diff(
        &m_standaloneFile.current_frame->rel_ts.secs,
        &m_standaloneFile.current_frame->rel_ts.nsecs,
        timeInfoArray[0], // abs_secs (current frame)
        timeInfoArray[1], // abs_usecs (current frame),
        startSecs, // abs-secs (prev frame)
        startnsecs); // abs_usecs (prev frame)
*/
	nstime_delta(&m_standaloneFile.current_frame->rel_ts,
			         &m_standaloneFile.current_frame->abs_ts,
			         &start_ts);

    // todo: have this be passed in.
    m_standaloneFile.current_frame->lnk_t = WTAP_ENCAP_ETHERNET;

    // what is the length of the pd buffer?
    memcpy(m_standaloneFile.pd, rawPacketData, rawPacketDataLength);
}

boolean StandaloneDecoder::FillSummaryBuffer(
    char *retSummaryBuffer,
    unsigned int retSummaryBufferLength,
    unsigned int *retSummaryDataLength,
    int *retProtocolId)
{
    // copy string from all the summary fields into the supplied buffer. check for buffer overruns
    // and return false if buffer is too small.
    unsigned int nextCharIndex = 0;
    int numberOfColumns = NUMBER_OF_SUMMARY_COL;
    *retProtocolId = 0;
    for (int i=0; i<numberOfColumns; i++)
    {
        const char * columnString = m_standaloneFile.cinfo.col_data[i];
        if (columnString != 0)
        {
            // if this happens to be the protocol column...
            if (i == SUMMARY_COL_PROTOCOL)
            {
                // take the opportunity to lookup the protocol id from the name
                *retProtocolId = CWtapFile::LookupProtocolId((char*)columnString);
            }

            size_t columnStringLength = strlen(columnString);
            #define MAX_COL_LENGTH 200
            if( columnStringLength > MAX_COL_LENGTH )
            {
                if (nextCharIndex + MAX_COL_LENGTH + 1 >= retSummaryBufferLength)
                    return false;

                strncpy(&retSummaryBuffer[nextCharIndex], columnString, MAX_COL_LENGTH);
                nextCharIndex += MAX_COL_LENGTH + 1;
            }
            else
            {
                if (nextCharIndex + columnStringLength + 1 >= retSummaryBufferLength)
                    return false;

                strcpy(&retSummaryBuffer[nextCharIndex], columnString);
                nextCharIndex += columnStringLength + 1;
            }            
        }
        else
        {
            if ((nextCharIndex + 1) >= retSummaryBufferLength)
                return false;

            retSummaryBuffer[nextCharIndex++] = 0;
        }
    }

    *retSummaryDataLength = nextCharIndex;

    return true;
}

int StandaloneDecoder::ParseDetailOutput(
    char *targetCharBuffer,
    unsigned int targetCharBufferSize,
    unsigned int *stringIndexArray,
    unsigned int *depthArray,
    unsigned int *offsetStartArray,
    unsigned int *offsetLenArray,
    int *protocolIdArray,
	int *dsIndexArray,
    int arraySizes)
{
    proto_node * rootNode = m_standaloneFile.edt->tree;	
    if (!rootNode)
        return 0;

	GSList* pDsList = m_standaloneFile.edt->pi.data_src;
	if(!pDsList)
		return 0;

    DetailResultsCompiler *compiler = new DetailResultsCompiler(
        pDsList,
        targetCharBuffer,
        targetCharBufferSize,
        stringIndexArray,
        depthArray,
        offsetStartArray,
        offsetLenArray,
        protocolIdArray,
		dsIndexArray,
        arraySizes);

    ParseProtocolTree(rootNode, compiler);

    int labelCount = compiler->GetLabelCount();

    delete compiler;
    compiler = 0;

    return labelCount;
}

void StandaloneDecoder::ParseProtocolTree(proto_node *node, DetailResultsCompiler *compiler)
{
    node = node->first_child;

    while (node)
    {
        compiler->Add(node);

        if (node->first_child)
            ParseProtocolTree(node, compiler);

        node = node->next;
    }
}

unsigned char* StandaloneDecoder::GetPacketDecryption(unsigned int pktNum, unsigned int dsIndex,
													  int* pPktSize, unsigned int* pAbsSecs, 
													  unsigned int* pAbsUsecs, unsigned int* pAbsNsecs,
													  bool ignoreFilter, unsigned int *pSegment)
{	    
	frame_data *fdata = NULL;
	*pPktSize = 0;
    fdata = m_standaloneFile.current_frame;
	if (fdata == NULL)
	{
		*pPktSize = 0;
		return NULL;
	}

	*pAbsSecs = unsigned int(fdata->abs_ts.secs);
	*pAbsUsecs = fdata->abs_ts.nsecs/1000;
	*pAbsNsecs = fdata->abs_ts.nsecs;
	*pSegment = fdata->segment;

	unsigned char * pRetData = NULL;
	data_source*   pDataSrc = NULL;  
	GSList* plist = m_standaloneFile.edt->pi.data_src;
	if (plist == NULL)
		return NULL;

	unsigned int dsListSize = g_slist_length(plist);

	if (dsIndex < dsListSize)
	{
		pDataSrc = (data_source*)g_slist_nth_data(plist, dsIndex);
		if (pDataSrc != NULL)
		{
			unsigned int retDataLen = pDataSrc->tvb->length;
			if(retDataLen > m_pPktDataBufSize)
			{
				if (m_pPktDataBuf)
					delete [] m_pPktDataBuf;
				m_pPktDataBuf = new guint8[retDataLen];
				m_pPktDataBufSize = retDataLen;
			}			
			memcpy(m_pPktDataBuf,pDataSrc->tvb->real_data,retDataLen);
			pRetData = m_pPktDataBuf;
			*pPktSize = retDataLen;
		}
	}

	return pRetData;

}

int StandaloneDecoder::GetPacketDataSourceCount(unsigned int pktNum)
{	
	frame_data *fdata = NULL;	
	fdata = m_standaloneFile.current_frame;
	if (fdata == NULL)	
		return 0;
	  
	GSList* plist = m_standaloneFile.edt->pi.data_src;
	if (plist == NULL)
		return 0;

	int dsCount = g_slist_length(plist);

	return dsCount;
}

char* StandaloneDecoder::GetDataSourceName(int dsIndex)
{
	frame_data *fdata = NULL;	
	data_source* pDataSrc =	NULL;
	fdata = m_standaloneFile.current_frame;
	if (fdata == NULL)	
		return 0;

	GSList* plist = m_standaloneFile.edt->pi.data_src;
	if (plist == NULL)
		return 0;
    
	pDataSrc =(data_source*)g_slist_nth_data(plist, dsIndex);
	if(pDataSrc == NULL)
		return NULL;

	return (char*)pDataSrc->name;
}