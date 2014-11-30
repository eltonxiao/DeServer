#ifndef __DETAIL_RESULTS_COMPILER__
#define __DETAIL_RESULTS_COMPILER__

#include "proto.h"

class DetailResultsCompiler
{
public:
    DetailResultsCompiler(
		GSList* pDsList,
        char * targetCharBuffer,
        unsigned int targetCharBufferSize,
        unsigned int * stringIndexArray,
        unsigned int * depthArray,
        unsigned int * offsetStartArray,
        unsigned int * offsetLenArray,
        int * protocolIdArray,
		int * dsIndexArray, 
        unsigned int arraySizes);

    bool Add(proto_node *node);

    bool GetOverflow() {return m_overflow;}

    unsigned int GetLabelCount() {return m_labelCount;}

private:
    
    char * GetLabelFromNode(proto_node *node);
    int GetProtocolIdForField(field_info *fieldInfo);
	int GetItemDataSourceIndex(field_info *fieldInfo);
      
	GSList* m_pDsList;
    char * m_targetCharBuffer;
    unsigned int * m_depthArray;
    unsigned int * m_stringIndexArray;
    unsigned int * m_offsetStartArray;
    unsigned int * m_offsetLenArray;
    int * m_protocolIdArray;
	int * m_dsIndexArray;

    unsigned int m_targetCharBufferSize;
    unsigned int m_arraySizes;

    unsigned int m_labelCount;
    unsigned int m_targetIndex;

    bool m_overflow;
};


#endif
