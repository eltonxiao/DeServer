//#ifndef __CS_LINUX

        // undefine the TRY, CATCH, etc macros defined for MFC - they conflict
        // with ethereal definitions
//        #include "UndefineTryCatch.h"
//#else
	#include <pthread.h>
        #include <arpa/inet.h>

        #include <boost/thread/thread.hpp>
        #include <boost/thread/mutex.hpp>
        #include <boost/thread/tss.hpp>
        #include <cstdio>
	#include <stdlib.h>
	#include <string.h>
        //#include "decode_predef.h"
//#endif

#include "PreScanProtocol.h"
#include "wtapFile.h"
#include "DetailResultsCompiler.h"

extern "C"
{
    #include "packet.h"
    #include "file.h"
    #include "column.h"
    #include "timestamp.h"
    #include "register.h"
    #include "epan.h"
    #include "epan_dissect.h"    
}

DetailResultsCompiler::DetailResultsCompiler(
	GSList* pDsList,
    char * targetCharBuffer,
    unsigned int targetCharBufferSize,
    unsigned int * stringIndexArray,
    unsigned int * depthArray,
    unsigned int * offsetStartArray,
    unsigned int * offsetLenArray,
    int * protocolIdArray,
	int * dsIndexArray,
    unsigned int arraySizes)
{
	m_pDsList = pDsList;
    m_targetCharBuffer = targetCharBuffer;
    m_targetCharBufferSize = targetCharBufferSize;
    m_depthArray = depthArray;
    m_stringIndexArray = stringIndexArray;
    m_offsetStartArray = offsetStartArray;
    m_offsetLenArray = offsetLenArray;
    m_protocolIdArray = protocolIdArray;
	m_dsIndexArray = dsIndexArray,
    m_arraySizes = arraySizes;

    m_labelCount = 0;
    m_targetIndex = 0;
    m_overflow = false;
}

bool DetailResultsCompiler::Add(proto_node *node)
{
    // don't attempt to do anything else if an overflow condition
    // has already occurred.
    if (m_overflow)
        return false;

    // get access to the field info within the node
    field_info *fieldInfo = node->finfo;
    if (!fieldInfo)
        // no field info
        return false;

    // if the field is hidden return true (we've succesfully
    // added nothing)
    bool hidden = FI_GET_FLAG(fieldInfo, FI_HIDDEN);
    if (hidden)
        return true;

    // check if we have any more space for new labels
    if ((m_labelCount + 1) >= m_arraySizes)
    {
        // string index and depth arrays are too small
        m_overflow = true;
        return false;
    }

    char * nodeLabel = GetLabelFromNode(node);
    if (!nodeLabel)
        return false;

    m_depthArray[m_labelCount] = (unsigned int) g_node_depth((GNode *) node) - 2;
    m_stringIndexArray[m_labelCount] = m_targetIndex;
    m_offsetStartArray[m_labelCount] = fieldInfo->start;
    m_offsetLenArray[m_labelCount] = fieldInfo->length;
    m_protocolIdArray[m_labelCount] = GetProtocolIdForField(fieldInfo);
	m_dsIndexArray[m_labelCount] = GetItemDataSourceIndex(fieldInfo);

    m_labelCount++;

    unsigned int labelLength = unsigned int(strlen(nodeLabel));

    unsigned int newTargetIndex = m_targetIndex + labelLength + 1;
    if ( newTargetIndex > m_targetCharBufferSize )
    {
        // target char buffer is too small
        m_overflow = true;
        return false;
    }

    strcpy(&m_targetCharBuffer[m_targetIndex], nodeLabel);

    m_targetIndex = newTargetIndex;

    return true;
}

char * DetailResultsCompiler::GetLabelFromNode(proto_node *node)
{
    if (node == 0)
        return 0;

    field_info * fieldInfo = node->finfo;
    
    gchar * labelPtr;
    if (fieldInfo->rep)
    {
        labelPtr = fieldInfo->rep->representation;
    }
    else
    {
        static gchar labelBuffer[ITEM_LABEL_LENGTH];
        proto_item_fill_label(fieldInfo, labelBuffer);
        labelPtr = labelBuffer;
    }

    return (char *) labelPtr;
}

int DetailResultsCompiler::GetProtocolIdForField(field_info *fieldInfo)
{
    if (!fieldInfo)
        return 0;

    if ( (fieldInfo->hfinfo) && (fieldInfo->hfinfo->type==FT_PROTOCOL) )
    {
        const char * filterName = fieldInfo->hfinfo->abbrev;
        if (filterName)
        {
            int etherealProtocolId = proto_get_id_by_filter_name(filterName);
            if (etherealProtocolId >= 0)
            {
                const char * shortName = proto_get_protocol_short_name(
                    find_protocol_by_id(etherealProtocolId));
                if (shortName)
                    return CWtapFile::LookupProtocolId((char*)shortName);
            }
        }
    }

    return 0;
}

int DetailResultsCompiler::GetItemDataSourceIndex(field_info *fieldInfo)
{
	int dsIndex = 0;
	tvbuff* pItemDataSourceTvb = fieldInfo->ds_tvb;
	if (!m_pDsList || !pItemDataSourceTvb)
	    return 0;
	
	guint count = g_slist_length(m_pDsList);
	
	for (guint i=0; i<count; i++)
	{
		tvbuff* tmpTvb = ((data_source*)g_slist_nth_data(m_pDsList, i))->tvb;
		if (tmpTvb == pItemDataSourceTvb)
		{
			dsIndex = i;
			break;
		}
	}		
	
	return dsIndex;	
}

