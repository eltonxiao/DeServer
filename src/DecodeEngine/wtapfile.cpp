
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
// wtapFile.cpp : implementation of the CWtapFile class
//
        #include "StdAfx.h"
#ifndef __CS_LINUX


        // undefine the TRY, CATCH, etc macros defined for MFC - they conflict
        // with ethereal definitions
        #include "UndefineTryCatch.h"
#else
    #include <pthread.h>
    #include <strings.h>
        #include <arpa/inet.h>

        #include <boost/thread/thread.hpp>
        #include <boost/thread/mutex.hpp>
        #include <boost/thread/tss.hpp>
        #include <cstdio>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
        #include "decode_predef.h"
#define stricmp strcasecmp
#endif

#include "wtapFile.h"
#include <sys/stat.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include "globals.h"
#include "util.h"
#include "wtap-int.h"
#include "addr_resolv.h"
//#include "DecodeEngine.h"
#include "DnsResolveName.h"
#include "WinsResolveName.h"
#include "epan_dissect.h"
#include "SummaryCols.h"
#include "nstime.h"
// [5/8/2006 Ken]
#include "protocol_force.h"
// [5/10/2006 Andrew]
#include "swap_frame_control.h"

    #include "prefs.h"
    #include "packet.h"
    #include "file.h"
    #include "column.h"
    #include "timestamp.h"
    #include "register.h"
    #include "epan.h"
    #include "epan_dissect.h"    
    //#include "summarycols.h"
    #include "addr_resolv.h"
    #include "..\..\ethereal\epan\dissectors\packet-ipsec.h"

    //ts_type timestamp_type = TS_RELATIVE;

    capture_file cfile_for_standalone;


//extern capture_file cfile;
//csa
#define ERR_OPEN_CAPFILE_NOTSUPPORT 2
#define ERR_OPEN_CAPFILE_CORRUPT 3
#define ERR_OPEN_CAPFILE_NOTSUPPORT_COMPRESSED 4

#ifdef __cplusplus
}
#endif /* __cplusplus */

//#include "StdString.h"

#pragma warning(4:4800)   // turn off performance warning


/*
#ifdef _DEBUG
#define new DEBUG_NEW
#undef THIS_FILE
static char THIS_FILE[] = __FILE__;
#endif
*/

/* Number of "frame_data" structures per memory chunk.
   XXX - is this the right number? */
#define    FRAME_DATA_CHUNK_SIZE    1024
#define IP_UDP_NETBIOS_NS    137        /* UDP: NetBios Name Service */  


DecodeSearchState::~DecodeSearchState()
{
    delete searchState; searchState = 0;
}



/////////////////////////////////////////////////////////////////////////////
// CWtapFile
CWtapFile::CWtapFile()
{
    //m_pCapFile = &cfile;//capture_file
    m_pCapFile = new capture_file;
    InitCFile(*m_pCapFile);

    m_pPktDataBufSize = 0;
    m_pFrameInfos1 = NULL;
    m_pFrameInfos2 = NULL;
    m_lastPktNumDecoded = 0;
    m_markedPktNum = 1;
    m_triggerPktNum = -1;
    m_iSplitPoint = 0;

    m_maxPktNumDecoded = 0;
    m_nFileSize = 0;

    //create a big buffer for GetPacket() to return to caller
    m_pPktDataBuf = new guint8[4096];
    m_pPktDataBufSize = 4096;

    m_pDecodePreScan = NULL;

    m_pPacketFilterIndexArray = 0;
    m_numberOfFilterIndeces = 0;

    m_bNameResolving = true;
    m_bIsGigabit = false;

    for (int i=0; i<NUMBER_OF_SEARCH_SESSION_SLOTS; i++)
        searchSessionSlots[i] = 0;
}

CWtapFile::~CWtapFile()
{
    if (m_pCapFile)
    {
	delete m_pCapFile;
	m_pCapFile = NULL;
    }

    if (m_pPktDataBuf)
        delete [] m_pPktDataBuf;
    if (m_pFrameInfos1)
        delete [] m_pFrameInfos1;
    if (m_pFrameInfos2)
        delete [] m_pFrameInfos2;
    if (m_pPacketFilterIndexArray)
    {
        delete [] m_pPacketFilterIndexArray;
        m_pPacketFilterIndexArray = 0;
    }
    
    // free up any outstanding search sessions
    for (int i=0; i<NUMBER_OF_SEARCH_SESSION_SLOTS; i++)
    {
        if (searchSessionSlots[i] != 0)
        {
            delete searchSessionSlots[i];
            searchSessionSlots[i] = 0;
        }
    }
}

void CWtapFile::ApplyFilter(unsigned int * pktIndexArray, int numOfIndeces)
{
    RemoveFilter();
    
    m_pPacketFilterIndexArray = new unsigned int[numOfIndeces];
    
    for (int i=0; i<numOfIndeces; i++)
        m_pPacketFilterIndexArray[i] = pktIndexArray[i];
        
    m_numberOfFilterIndeces = numOfIndeces;    
}

void CWtapFile::RemoveFilter()
{
    if (m_pPacketFilterIndexArray)
    {
        delete [] m_pPacketFilterIndexArray;
        m_pPacketFilterIndexArray = 0;
        m_numberOfFilterIndeces = 0;
    }
}


bool CWtapFile::WriteCapFile(const char* filename, DecodeCaptureFileTypes eFileType, bool ignoreFilter)
{
    int etherealFileType = WTAP_FILE_UNKNOWN;

    switch (eFileType)
    {
        case DECODE_FORMAT_APPDANCER:
            etherealFileType = WTAP_FILE_APPDANCER;
            break;
            
        case DECODE_FORMAT_SNIFFER:
            etherealFileType = WTAP_FILE_NGSNIFFER_UNCOMPRESSED;
            break;
	    case DECODE_FORMAT_PCAP:
            etherealFileType = WTAP_FILE_PCAP;
			break;
		case DECODE_FORMAT_NSEC_PCAP:
			etherealFileType = WTAP_FILE_PCAP_NSEC;
			break;
	    case DECODE_FORMAT_CAP:             	
			etherealFileType = WTAP_FILE_SHOMITI;
			break;
        default:
            return false;
    }

    return WriteCapFileInternal( filename, etherealFileType, ignoreFilter);
}


bool CWtapFile::WriteCapFile(const char* filename, const char * targetFileTypeName, bool ignoreFilter)
{
    if (!targetFileTypeName || strlen(targetFileTypeName)==0)
        return false;

    int etherealFileType = wtap_short_string_to_file_type( targetFileTypeName );

    if ( (etherealFileType==-1) || (etherealFileType==WTAP_FILE_UNKNOWN) )
        return false;

    return WriteCapFileInternal( filename, etherealFileType, ignoreFilter );
}

void CWtapFile::CopySegmentInfo(wtap_dumper *wtap_dumper, wtap *wtap)
{
    wtap_dumper->first_segment = wtap->first_segment;
    wtap_dumper->extra_segment_count = wtap->extra_segment_count;
    
    for (int i=0; i<wtap->extra_segment_count; i++)
    {
        wtap_dumper->extra_segments[i] = wtap->extra_segments[i];
    }
}

bool CWtapFile::WriteCapFileInternal(const char* filename, int etherealFileType, bool ignoreFilter)
{
    int err;
    wtap *wth = m_pCapFile->wth;
    gchar      *err_info;
    gboolean compressed = false;
    //open the new file to write
    wtap_dumper *pdh = wtap_dump_open(
        filename,
        etherealFileType,
        wtap_file_encap(wth),
        wtap_snapshot_length(wth),
		compressed,
        &err,
        wth->extra_segment_count);
    
    if (pdh == NULL)
        return false;

    int packetCount = GetNumOfPackets(ignoreFilter);

    frame_data *fdata;
    struct wtap_pkthdr hdr;
    guint8* buf = new guint8[WTAP_MAX_PACKET_SIZE];
    for (int i = 0; i < packetCount; i++)
    {
        fdata = GetFrameData(i+1, ignoreFilter);
        if (fdata == NULL)
        {
            delete [] buf;
            return false;    // we didn't find that frame
        }

        //setup the frame header
        hdr.ts.secs = fdata->abs_ts.secs;
        hdr.ts.nsecs = fdata->abs_ts.nsecs;
 //       hdr.nsec_resolution = fdata->flags.nsec_resolution;
 //       if (hdr.nsec_resolution)
  //          hdr.tv_nsec = fdata->abs_ts.nsecs;
  //      else
  //          hdr.tv_nsec = 0;       //USE moved

		if (etherealFileType != WTAP_FILE_APPDANCER)
		{
			static const int CRC_SIZE = 4;
			int realCrcSize = CRC_SIZE - GetCrcSize(); 

			if (fdata->pkt_len - fdata->cap_len >= guint32(realCrcSize))		// All crc were Sliced
			{
				hdr.caplen = fdata->cap_len;
			}
			else
			{
				hdr.caplen = fdata->pkt_len - realCrcSize;
			}

			hdr.len = fdata->pkt_len - realCrcSize;
		}
		else
		{
			hdr.caplen = fdata->cap_len;
			hdr.len = fdata->pkt_len ;
		}

        hdr.pkt_encap = fdata->lnk_t;
        hdr.channel = fdata->channel;
        hdr.status  = fdata->status;
        hdr.segmentId = fdata->segment;

        // Get the data in that frame.
        wtap_seek_read(wth, fdata->file_off, &m_pCapFile->pseudo_header, buf, fdata->cap_len, &err,&err_info);

        //write to the new file
        if (!wtap_dump(pdh, &hdr, &m_pCapFile->pseudo_header, buf, &err))
        {
            delete [] buf;
            return false;
        }
    }
    delete [] buf;

    CopySegmentInfo(pdh, wth);
    pdh->crc_size = wth->crc_size;

    //close the new file
    if (!wtap_dump_close(pdh, &err))
    {
        return false;
    }
    return true;
}


//copy from open_cap_file() in file.c
int CWtapFile::OpenCapFile(const char* filename, bool bPreScan)
{
    m_lastPktNumDecoded = 0;
	m_maxPktNumDecoded = 0;

    int err;
    wtap       *wth;
    gchar       *err_info;
    wth = wtap_open_offline(filename, &err, &err_info,TRUE);
    if (wth == NULL)
    {
	//csa added
	if (err == WTAP_ERR_UNSUPPORTED || err == WTAP_ERR_UNSUPPORTED_FILE_TYPE || err==WTAP_ERR_UNSUPPORTED_ENCAP
	    || err == WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED || err == WTAP_ERR_FILE_UNKNOWN_FORMAT)
	    return ERR_OPEN_CAPFILE_NOTSUPPORT;
	else if (err ==WTAP_ERR_CANT_READ || err == WTAP_ERR_SHORT_READ || err ==WTAP_ERR_BAD_RECORD || err ==WTAP_ERR_SHORT_WRITE ||
	    err ==WTAP_ERR_UNC_TRUNCATED || err ==WTAP_ERR_UNC_OVERFLOW || err ==WTAP_ERR_UNC_BAD_OFFSET)
	    return ERR_OPEN_CAPFILE_CORRUPT;
	else 
        return false;
    }
    // samuell:
    //    SetMediumType(wtap_medium_type(wth));
    //    SetSubMediumType(wtap_sub_medium_type(wth));
    //    SetBandwidth(wth->bandwidth);
    //    SetOption(wth->option);

    m_bIsGigabit = wth->first_segment.is_gigabit;

    /* Find the size of the file. */
/*
    int         fd;
    struct stat cf_stat;
    //  USE modified
    //fd = wtap_fd(wth); 
    fd = wtap_file_size(wth,&err); 
*/
    m_nFileSize = wtap_file_size(wth,&err); 
 
    //USE moved, because wtap_file_size had called fstat(fd, &cf_stat)
/* 
    if (fstat(fd, &cf_stat) < 0)
    {
        wtap_close(wth);
	{
	//csa added
	    return ERR_OPEN_CAPFILE_CORRUPT;
	}
    }
*/
    //CloseCapFile();

    // this call moved to DecodeEngine::Init() so that it will be called before
    // any standalone-decode attempts are made against the decode engine.
    // init_dissection();

    // moved to DecodeEngine::Init - see comment above
    //    init_all_protocols();


    /* We're about to start reading the file. */
    m_pCapFile->state = FILE_READ_IN_PROGRESS;

    m_pCapFile->wth = wth;
//    m_pCapFile->filed = fd;
//    m_pCapFile->f_len = cf_stat.st_size;

    m_pCapFile->cd_t      = wtap_file_type(m_pCapFile->wth);
    m_pCapFile->count     = 0;
    m_pCapFile->drops     = 0;
  //  m_pCapFile->esec      = 0;
//    m_pCapFile->eusec     = 0;
    m_pCapFile->snap      = wtap_snapshot_length(m_pCapFile->wth);

    m_pCapFile->plist_chunk = g_mem_chunk_new("frame_data_chunk", sizeof(frame_data), FRAME_DATA_CHUNK_SIZE * sizeof(frame_data), G_ALLOC_AND_FREE);
    g_assert(m_pCapFile->plist_chunk);

    //JJL, to reset the host name table which holds ip/name pairs
    remove_ipv4_name_table();
    //JJL, to reset the host name table which holds ipv6/name pairs
    remove_ipv6_name_table();
    //JJL, to reset the ether name table which holds ether/name pairs
    remove_ether_name_table();
    //ie, add_host_name(241663039, (const unsigned char*)"cinco");

    // samuell: reset channel since not every trace file has channel information
    struct wtap_pkthdr *phdr = wtap_phdr(m_pCapFile->wth);
    phdr->channel = 0;
    phdr->status  = 0;
    // must do the same for frame type.
    phdr->frame_type = 0;
    // and segment id
    phdr->segmentId = 0;

    // samuell: remove me later
    bPreScan = true;
    if (bPreScan)
    {
        PreScanInit();
    }

    while (ReadNextPacket())
        ;

    if (bPreScan)
    {
        PreScanTerminate();
    }

    //save the frame_data ptrs to speedup the lookup in GetFrameData()
    // if more then 1 mill packets start to split it up so that we don't 
    //  require so much continguous memory, it was failing to allocate
    //  46megs for a 5 mill packet trace
    if (m_pCapFile->count >= (1024 * 1024))
        m_iSplitPoint = m_pCapFile->count/2;
    else
        m_iSplitPoint = m_pCapFile->count;
    if (m_pFrameInfos1)
        delete [] m_pFrameInfos1;
    m_pFrameInfos1 = new CWtapFrameInfo[m_iSplitPoint];

    if (m_iSplitPoint < m_pCapFile->count)
    {
        // allocate the second block
        if (m_pFrameInfos2)
            delete [] m_pFrameInfos2;
        m_pFrameInfos2 = new CWtapFrameInfo[m_pCapFile->count - m_iSplitPoint];
    }
    int i = 0;
    frame_data *fdata;
    for (fdata = m_pCapFile->plist_start; (i < m_iSplitPoint) && (fdata != NULL); fdata = fdata->next)
    {
        m_pFrameInfos1[i].m_protocolId = -1;
        m_pFrameInfos1[i].m_fdata = fdata;
        i++;
    }

    // put in the next batch
    for (i = 0; fdata != NULL; fdata = fdata->next)
    {
        m_pFrameInfos2[i].m_protocolId = -1;
        m_pFrameInfos2[i].m_fdata = fdata;
        i++;
    }

    return true;
}

//copy from close_cap_file() in file.c
void CWtapFile::CloseCapFile()
{
    /* Destroy the protocol tree for that packet. */
    if (m_pCapFile->edt != 0)
    {
        epan_dissect_free(m_pCapFile->edt);
        m_pCapFile->edt = 0;
    }
    if (m_pCapFile->detail_items != NULL)
    {
        g_slist_free(m_pCapFile->detail_items);
        m_pCapFile->detail_items = NULL;
    }
    if (m_pCapFile->wth != NULL)
    {
        wtap_close(m_pCapFile->wth);
        m_pCapFile->wth = NULL;
    }
    if (m_pCapFile->plist_chunk != NULL)
    {
        g_mem_chunk_destroy(m_pCapFile->plist_chunk);
        m_pCapFile->plist_chunk = NULL;
    }
    m_pCapFile->plist_start = NULL;
    m_pCapFile->plist_end = NULL;
    if (wep_keylens)
    {	
        g_free(wep_keylens);
        wep_keylens = NULL;
    }
    for (guint i=0; i<num_wepkeys;i++)
    {
        if (wep_keys[i])
        {  
            g_free (wep_keys[i]);
            wep_keys[i] = NULL;
        }
    }
    num_wepkeys = 0;
    /* We have no file open. */
    m_pCapFile->state = FILE_CLOSED;
}

void CWtapFile::ResolveAddresses(bool resolve)
{
    // note: this option is not the same as that returned by IsNameResolvingOn().
    // that option controls prescan generation of addresses and should always be on
    // to allow for dns names to be available for this option.

    set_resolve_names(resolve); // turn ethereal name resolution on/off.
}

void CWtapFile::setIpDscp(bool ipDscp)
{

    set_ip_dscp(ipDscp); // turn ethereal ip tos on/off
}
void CWtapFile::setnumwepKeys(int numkeys)
{

    set_num_wepKeys(numkeys); // turn wep keys
}
void CWtapFile::setwepKeysStr(unsigned char *wepkeystr,unsigned int keyindex, unsigned int length)
{

    set_wepKeysStr(wepkeystr,keyindex,length); // turn wep keys
}

void CWtapFile::forceDocsis(bool forceDocsis)
{

    set_force_docsis(forceDocsis); // turn force docsis on/off
}
void CWtapFile::forceProtocol(unsigned int forceEnable)
{

    set_force_protocol_enable(forceEnable);

}
void CWtapFile::forceProtocolRule(unsigned int force_start, unsigned int force_offset, unsigned int force_protocol) 
{

    set_force_protocol_rule(force_start, force_offset, force_protocol);

}
void CWtapFile::setwimax(unsigned int wimaxState)
{

    //to do
    return;
}
void CWtapFile::setLwappSwapFrameControl(bool isSwaped) 
{

	set_Lwapp_swap_frame_control( isSwaped);

}

extern "C" {
   void proto_reg_handoff_rtp_events(void);
}

void CWtapFile::SetDTMFPayloadValue(int payloadValue)
{
    char acBuffer[100];
    sprintf(acBuffer, "rtpevent.event_payload_type_value:%d", payloadValue);
    prefs_set_pref((char *)&acBuffer[0]);
    module_t *pDstModule =prefs_find_module("rtpevent");
    if (pDstModule)
    {
        prefs_apply(pDstModule);
    }
}

void CWtapFile::setQinQEtherType(unsigned short EtherType)
{
    char acBuffer[100];
    sprintf(acBuffer, "vlan.qinq_ethertype:%x", EtherType);
    prefs_set_pref((char *)&acBuffer[0]);
    module_t *pDstModule =prefs_find_module("vlan");
    if (pDstModule)
    {
        prefs_apply(pDstModule);
    }
}

void CWtapFile::setGtpuTypePort(bool bGtpuOverTcp, unsigned short port)
{
    char acBuffer1[100], acBuffer2[100];
    if (bGtpuOverTcp)
        sprintf(acBuffer1, "gtp.dissect_gtp_over_tcp:true");
    else
        sprintf(acBuffer1, "gtp.dissect_gtp_over_tcp:false");
    sprintf(acBuffer2, "gtp.v1u_port:%d", port);
    prefs_set_pref((char *)&acBuffer1[0]);
    prefs_set_pref((char *)&acBuffer2[0]);
    module_t *pDstModule =prefs_find_module("gtp");
    if (pDstModule)
    {
        prefs_apply(pDstModule);
    }
}

void CWtapFile::setPBBEtherType(unsigned short EtherType)
{
    char acBuffer[100];
    sprintf(acBuffer, "ieee8021ah.8021ah_ethertype:%x", EtherType);
    prefs_set_pref((char *)&acBuffer[0]);
    module_t *pDstModule =prefs_find_module("ieee8021ah");
    if (pDstModule)
    {
        prefs_apply(pDstModule);
    }
}

void CWtapFile::PatternForceProtocol(bool isPatternEnable, long PatternOffset,  int* pattern, unsigned int PatternLength) 
{

    set_Pattern_force_protocol( isPatternEnable, PatternOffset,  pattern,  PatternLength);

}
void CWtapFile::AddAddressName(unsigned int address, char *name)
{
    add_ipv4_name(address, (const char *) name);
}

void CWtapFile::AddIpv6AddrName(unsigned char* address, char *name)
{
    add_ipv6_name((struct e_in6_addr *)address, (const gchar *) name);
}

void CWtapFile::AddDlcAddrName(unsigned char* address, char *name)
{
    add_ether_name(address, (const unsigned char *) name);
}

void CWtapFile::AddVendorName( char *path)
{
  epan_AddVendorName(path);
}

bool CWtapFile::ReadNextPacket()
{
    if (m_pCapFile->wth == NULL)
            return false;
    gint64 data_offset;
    int err;
      gchar      *err_info;
    if (wtap_read(m_pCapFile->wth, &err, &err_info,&data_offset))
    {
        const struct wtap_pkthdr *phdr = wtap_phdr(m_pCapFile->wth);
        union wtap_pseudo_header *pseudo_header = wtap_pseudoheader(m_pCapFile->wth);
        u_char *buf = wtap_buf_ptr(m_pCapFile->wth);

        frame_data   *fdata;
        /* Allocate the next list entry, and add it to the list. */
        fdata = (struct _frame_data *)g_mem_chunk_alloc(m_pCapFile->plist_chunk);

		// for fix bug 8346
		memset(fdata, 0, sizeof(struct _frame_data));

        fdata->next = NULL;
        fdata->prev = NULL;
        fdata->pfd  = NULL;

        // added by samuell
        fdata->channel  = phdr->channel;
        fdata->segment  = phdr->segmentId;
        fdata->status   = phdr->status;
        
        fdata->pkt_len  = phdr->len;
        fdata->cap_len  = phdr->caplen;
        fdata->file_off = data_offset;
        fdata->lnk_t = phdr->pkt_encap;
	fdata->abs_ts.secs  = phdr->ts.secs;
	fdata->abs_ts.nsecs = phdr->ts.nsecs;
//	fdata->abs_nsecs = phdr->tv_nsec;   //USE moved
        fdata->flags.encoding = PACKET_CHAR_ENC_CHAR_ASCII; //CHAR_ASCII;
        fdata->flags.visited = 0;
        fdata->flags.marked = 0;
        if ((phdr->frame_type == 1) || (phdr->frame_type == 2))
            fdata->flags.is_autonegotiation = 1;
        else
            fdata->flags.is_autonegotiation = 0;

        // for now, only gigabit decode files have gigabit resolution.
//        fdata->flags.nsec_resolution = m_bIsGigabit;  //USE moved
        //fix bug 877 - REF* intermitten bug 
        fdata->flags.ref_time = 0;
				fdata->shomiti_status = phdr->shomitiStatus.word;
        frame_data   *plist_end;
        plist_end = m_pCapFile->plist_end;
        fdata->prev = plist_end;
        if (plist_end != NULL)
            plist_end->next = fdata;
        else
            m_pCapFile->plist_start = fdata;
        m_pCapFile->plist_end = fdata;

        m_pCapFile->count++;             
        fdata->num = m_pCapFile->count;
        
        if (m_pCapFile->wth->file_type == WTAP_FILE_SHOMITI 
					&&  phdr->shomitiStatus.bits.triggered == 1)
		{
			m_triggerPktNum = m_pCapFile->count - 1;
		}

        if (IsPreScanOn())
        {
            // pass in Frame buffer and its length
            PreScanProcess(buf, phdr->caplen);
        }

        // samuell: DNS name resolution process
        if (IsNameResolvingOn())
        {
            NameResolvingProcess(buf, phdr->caplen);
        }

        return true;
    }
    else
    {
        /* We're done reading sequentially through the file. */
        m_pCapFile->state = FILE_READ_DONE;

        /* Close the sequential I/O side, to free up memory it requires. */
        wtap_sequential_close(m_pCapFile->wth);

        /* Set the file encapsulation type now; we don't know what it is until
           we've looked at all the packets, as we don't know until then whether
           there's more than one type (and thus whether it's
           WTAP_ENCAP_PER_PACKET). */
        m_pCapFile->lnk_t = wtap_file_encap(m_pCapFile->wth);
    }
    return false;
}

// const is added by tattie [6/27/2006 Ken]
int CWtapFile::GetNumOfPackets(bool ignoreFilter) const
{
    if (ignoreFilter || (m_pPacketFilterIndexArray==0))
        return m_pCapFile->count;
    else
        return m_numberOfFilterIndeces;
}

unsigned char* CWtapFile::GetPacket(
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
    int* pWholePktSize)
{
    frame_data *fdata = NULL;
    int err;
    unsigned int pktStat = 0;
  gchar      *err_info;

    if (pktNum <= unsigned int(GetNumOfPackets(ignoreFilter)))
        fdata = GetFrameData(pktNum,ignoreFilter);
    if (fdata == NULL)
    {
        *pPktSize = 0;
        return NULL;
    }

    *pAbsSecs = unsigned int(fdata->abs_ts.secs);
    *pAbsUsecs = fdata->abs_ts.nsecs/1000;
    *pAbsNsecs = fdata->abs_ts.nsecs;
  //  if (fdata->flags.nsec_resolution)
    //	*pAbsNsecs = fdata->abs_nsecs;
   // else
    //    *pAbsNsecs = 0;   //USE moved

    // added by samuell
    *pChannel     = fdata->channel;
    *pSegment     = fdata->segment;
    *pErrorStatus = (fdata->status &0x00ff);
    if (fdata->cap_len > guint32(m_pPktDataBufSize))
    {
        if (m_pPktDataBuf)
            delete [] m_pPktDataBuf;
        m_pPktDataBuf = new guint8[fdata->cap_len];
        m_pPktDataBufSize = fdata->cap_len;
    }
    /* Get the data in that frame. */
    wtap_seek_read(m_pCapFile->wth, fdata->file_off, &m_pCapFile->pseudo_header, m_pPktDataBuf, fdata->cap_len, &err,&err_info);

	*pPktSize = fdata->cap_len;
    *pWholePktSize = fdata->pkt_len;

	//if (   m_pCapFile->wth->file_type == WTAP_FILE_NETXRAY_OLD
	//	|| m_pCapFile->wth->file_type == WTAP_FILE_NETXRAY_1_0
	//	|| m_pCapFile->wth->file_type == WTAP_FILE_NETXRAY_1_1
	//	|| m_pCapFile->wth->file_type == WTAP_FILE_NETXRAY_2_00x)
	//{
	//	if (m_pCapFile->pseudo_header.eth.fcs_len == 4)
	//	{
	//		*pPktSize -= 4;
	//	    *pWholePktSize -= 4;
	//	}
	//}

    if (fdata->flags.is_autonegotiation)
        pktStat |= 0x0001;
    if (fdata->cap_len < fdata->pkt_len)
        pktStat |= 0x0002;
    *pPacketStatus = pktStat;
    
    return m_pPktDataBuf;
}

unsigned char* CWtapFile::GetPacketDecryption(
	unsigned int pktNum, 
	unsigned int dsIndex, 
	int* pPktSize, 
	unsigned int* pAbsSecs, 
	unsigned int* pAbsUsecs, 
	unsigned int* pAbsNsecs, 
	bool ignoreFilter,
	unsigned int *pSegment)
{
    frame_data *fdata = NULL;
	*pPktSize = 0;
	if (pktNum <= unsigned int(GetNumOfPackets(ignoreFilter)))
		fdata = GetFrameData(pktNum,ignoreFilter);
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
	GSList* plist = m_pCapFile->edt->pi.data_src;
	if (plist == NULL)
		return NULL;
	
	unsigned int dsListSize = g_slist_length(plist);

	if (dsIndex < dsListSize)
	{
        pDataSrc = (data_source*)g_slist_nth_data(plist, dsIndex);
		if (pDataSrc != NULL)
		{
			unsigned int retDataLen = pDataSrc->tvb->length;
			if(retDataLen > unsigned int(m_pPktDataBufSize))
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

int CWtapFile::GetPacketDataSourceCount(unsigned int pktNum)
{    
	frame_data *fdata = NULL;
	bool ignoreFilter = false;

	if (pktNum <= unsigned int(GetNumOfPackets(ignoreFilter)))
		fdata = GetFrameData(pktNum,ignoreFilter);
	if (fdata == NULL)			
		return 0;

	data_source*   pDataSrc = NULL;  
	GSList* plist = m_pCapFile->edt->pi.data_src;
	if (plist == NULL)
		return 0;
    
    int dsCount = g_slist_length(plist);

	return dsCount;
	
}

char* CWtapFile::GetDataSourceName(int dsIndex)
{
	data_source*   pDataSrc = NULL;  
	GSList* plist = m_pCapFile->edt->pi.data_src;
	if (plist == NULL)
		return NULL;

	int dsCount = g_slist_length(plist);
	if(dsCount == 0)
		return NULL;

	pDataSrc =(data_source*)g_slist_nth_data(plist, dsIndex);
	if(pDataSrc == NULL)
		return NULL;

/*
1.4.2 upgrade
	return (char*)pDataSrc->name;
*/
    return (char*)get_data_source_name(pDataSrc);
}

int CWtapFile::BulkGetPackets(
    unsigned int startPktNum, 
    unsigned int maxPktsToProcess,
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
    unsigned int* WholepktSizeArray
    )
{
    // note: startPktNum is 1-based

    unsigned int packetsProcessed = 0;
    unsigned int rawDataIndex = 0;
    unsigned int totalPacketCount = GetNumOfPackets(true);
  gchar      *err_info;

    // determine the packet number of the last packet to be processed.
    unsigned int endPacketNum = startPktNum + maxPktsToProcess - 1;
    if (endPacketNum > totalPacketCount)
        endPacketNum = totalPacketCount;

    // loop through (at most) all the remaining packets starting with the
    // packet number specified by the caller.
    for (unsigned int pktNum=startPktNum; pktNum<=endPacketNum; pktNum++)
    {
        // get meta-information about the next packet.
        // note: bulk-gets always ignore any filter
        frame_data *fdata = GetFrameData(pktNum, true);
        if (fdata == 0)
        {
            // failed to get packet info. something bad happened.
            return -1;
        }

        // if we don't have enough space in the raw data buffer to hold
        // the packet...
        unsigned int rawDataLengthRemaining = rawDataBufferSize - rawDataIndex;
        if (fdata->cap_len > rawDataLengthRemaining)
        {
            // return. this is a normal end condition.
            return packetsProcessed;
        }

        // get the raw data for the packet
        int err;
        wtap_seek_read(
            m_pCapFile->wth, 
            fdata->file_off, 
            &m_pCapFile->pseudo_header, 
            (unsigned char *) &rawDataBuffer[rawDataIndex],
            fdata->cap_len, 
            &err,&err_info);

        // fill in the parameter arrays
        pktSizeArray[packetsProcessed] = fdata->cap_len;
        absSecsArray[packetsProcessed] = unsigned int(fdata->abs_ts.secs);
        absUsecsArray[packetsProcessed] = fdata->abs_ts.nsecs/1000;
	absNsecsArray[packetsProcessed] = fdata->abs_ts.nsecs;
 //       if (fdata->flags.nsec_resolution)
//	    absNsecsArray[packetsProcessed] = fdata->abs_nsecs;
//        else
//            absNsecsArray[packetsProcessed] = 0;   //USE moved

        channelArray[packetsProcessed] = fdata->channel;
        errorStatusArray[packetsProcessed] = (fdata->status & 0x0ff);
        unsigned int pktStat = 0;
        if (fdata->flags.is_autonegotiation)
            pktStat |= 0x0001;
        if (fdata->cap_len < fdata->pkt_len)
            pktStat |= 0x0002;
        packetStatusArray[packetsProcessed] = pktStat;
        segmentArray[packetsProcessed] = fdata->segment;
        WholepktSizeArray[packetsProcessed] = fdata->pkt_len;

        // update the raw data index to next packet start
        // position.
        rawDataIndex += fdata->cap_len;

        // update the count of packets processed and abort if we've exceeded
        // the parameter array size
        packetsProcessed++;
        if ( packetsProcessed >= parameterArraySize )
        {
            // this is a normal end condition
            return packetsProcessed;
        }
    }

    // we've reached the last packet
    return packetsProcessed;
}    
    


bool CWtapFile::TiePort(const char * protocolName, int port)
{
    // the protocolName passed in is assumed to be compatible with
    // ethereal.
    bool tcp_success = (bool) tie_port(PT_TCP, port, protocolName);
    bool udp_success = (bool) tie_port(PT_UDP, port, protocolName);
    
    return tcp_success || udp_success;
}

// added by xulei for bug#5986
void CWtapFile::UnTiePort(unsigned short port)
{
    untie_port(PT_TCP, port);
    untie_port(PT_UDP, port);
}


char* CWtapFile::GetSummaryOutput(int index)
{
    return (char*)m_pCapFile->cinfo.col_data[index];
}

//return num of detail lines
int CWtapFile::ParseDetailOutput()
{
    if (m_pCapFile->edt->tree)
    {
        if (m_pCapFile->detail_items != NULL)
        {
            g_slist_free(m_pCapFile->detail_items);
            m_pCapFile->detail_items = NULL;
        }

        ParseProtocolTree((proto_node*)m_pCapFile->edt->tree, m_pCapFile->detail_items);
        return g_slist_length(m_pCapFile->detail_items);
    }
    return 0;
}

void CWtapFile::ParseProtocolTree(proto_node *node, GSList * &list)
{

    node = node->first_child; 
    while (node)
    {
        proto_node *current;
        current = node;
        node = current->next;

        field_info    *fi = current->finfo; 

        if (!(FI_GET_FLAG(fi, FI_HIDDEN))) //not hidden
	{
            list = g_slist_append(list, current);
	}
        if (current->first_child)
            ParseProtocolTree(current,list);
    }

}

char* CWtapFile::GetDetailOutput(int lineIndex, int* depth, int* offsetStart, int* offsetLen, int* protocolId, int *dsIndex)
{
    proto_node *node = (proto_node*)g_slist_nth_data(m_pCapFile->detail_items, lineIndex);
    field_info    *fi = node->finfo;
    static gchar label_str[ITEM_LABEL_LENGTH];
    gchar *label_ptr;
    /* was a free format label produced? */
    if (fi->rep)
    {
        label_ptr = fi->rep->representation;
    }
    else
    { /* no, make a generic label */
        label_ptr = label_str;
        proto_item_fill_label(fi, label_str);
    }
    *depth = g_node_depth((GNode *)node) - 2;
    *offsetStart = fi->start;
    *offsetLen = fi->length;

    tvbuff* pItemDataSourceTvb = fi->ds_tvb;
	GSList* pList = m_pCapFile->edt->pi.data_src;
	guint count = g_slist_length(pList);
	 *dsIndex = 0;
	if (pItemDataSourceTvb != NULL && pList != NULL)
	{
		for (guint i=0; i<count; i++)
		{
			tvbuff* tmpTvb = ((data_source*)g_slist_nth_data(pList, i))->tvb;
			if (tmpTvb == pItemDataSourceTvb)
			{
				*dsIndex = i;
				break;
			}
		}		
	}	

    // if possible, fill in the protocol id for this item. in general
    // we only have this information for top level items (depth==0).
    *protocolId = 0; // unknown
    if ( (fi->hfinfo) && (fi->hfinfo->type==FT_PROTOCOL) )
    {
        const char * filterName = fi->hfinfo->abbrev;
        if (filterName)
        {
            int etherealProtocolId = proto_get_id_by_filter_name(filterName);
            if (etherealProtocolId >= 0)
            {
                const char * shortName = proto_get_protocol_short_name(find_protocol_by_id(etherealProtocolId));
                if (shortName)
                    *protocolId = LookupProtocolId((char*)shortName); // may return 0 if name not found
            }
        }
    }

    return label_ptr;
}

unsigned int CWtapFile::GetRealPktNum(unsigned int pktNum)
{

     if (!m_pPacketFilterIndexArray)

        return pktNum;

      //check out of range

      if (pktNum > m_numberOfFilterIndeces)

            return -1;

    return m_pPacketFilterIndexArray[pktNum-1] + 1;

}


int CWtapFile::GetPacketPosition(unsigned int pktNum, bool matchClosest)
{
    // given a 1-based packet number indexing into the unfiltered packet list,
    // return a 0-based packet position in the current filtered list. if there
    // is no active filter, the index (packet number - 1) is returned, if valid.

    int packetIndex = pktNum-1;

    // if we don't have a filter...
    if (!m_pPacketFilterIndexArray)
    {
        // just return the index or -1
        if (packetIndex >= GetNumOfPackets(true))
            return -1;
        return packetIndex;
    }

    // find the filter index which refers to the index of the packet whose
    // packet number was passed in.
    for (unsigned int i=0; i<m_numberOfFilterIndeces; i++)
    {
        int filteredIndex = m_pPacketFilterIndexArray[i];

        if (filteredIndex == packetIndex)
            return i;

        if (matchClosest && (filteredIndex>packetIndex) )
        {
            // return previous index if it's closer to the requested packet.
            if ( (i>0) && ( (packetIndex-m_pPacketFilterIndexArray[i-1]) < unsigned int(filteredIndex-packetIndex) ) )
                return i-1;
            return i;
        }
	// add by tattie for bug#5473 [6/27/2006 Ken]
	if(filteredIndex > packetIndex)
	    return i;
    }

    if (matchClosest && (m_numberOfFilterIndeces>0))
        return m_numberOfFilterIndeces-1;

    return -1;

}

//pktNum is 1-based
frame_data* CWtapFile::GetFrameData(unsigned int pktNum, bool ignoreFilter)
{
    frame_data *fdata = 0;
    int packetnumber;
    if (ignoreFilter)
        packetnumber = pktNum - 1;
    else
        packetnumber = GetRealPktNum(pktNum) - 1;
    if (packetnumber < 0) //bug3959 - space in the pktnumber
	return 0;
    // was it split
    if (packetnumber >= m_iSplitPoint)
         fdata = m_pFrameInfos2[packetnumber - m_iSplitPoint].m_fdata;
    else
        fdata = m_pFrameInfos1[packetnumber].m_fdata;

    return fdata;
}

void CWtapFile::SetProtocolId(unsigned int pktNum, int protocolId, bool ignoreFilter)
{
    int packetnumber;
    if (ignoreFilter)
        packetnumber = pktNum - 1;
    else
        packetnumber = GetRealPktNum(pktNum) - 1;
    // was it split
    if (packetnumber >= m_iSplitPoint)
        m_pFrameInfos2[packetnumber - m_iSplitPoint].m_protocolId = protocolId;
    else
        m_pFrameInfos1[packetnumber].m_protocolId = protocolId;
}

int CWtapFile::GetProtocolId(unsigned int pktNum, bool ignoreFilter)
{
    int packetnumber;
    if (ignoreFilter)
        packetnumber = pktNum - 1;
    else
        packetnumber = GetRealPktNum(pktNum) - 1;
    // was it split
    if (packetnumber >= m_iSplitPoint)
        return m_pFrameInfos2[packetnumber - m_iSplitPoint].m_protocolId;
    else
        return m_pFrameInfos1[packetnumber].m_protocolId;
}

int CWtapFile::GetProtocolId()
{
    if (m_lastPktNumDecoded == 0)
        return -1;

    int packetnumber = m_lastPktNumDecoded - 1;

    // was it split
    if (packetnumber >= m_iSplitPoint)
        return m_pFrameInfos2[packetnumber - m_iSplitPoint].m_protocolId;
    else
        return m_pFrameInfos1[packetnumber].m_protocolId;
}

//mark this pkt for relative time info
void CWtapFile::SetMarked(unsigned int pktNum)
{
    m_markedPktNum = pktNum;
}
int CWtapFile::GetMarked()
{
    return m_markedPktNum;
}

//pktNum is 1-based
bool CWtapFile::DecodePacket(unsigned int pktNum, bool bSummaryOnly, bool ignoreFilter)
{
    frame_data *fdata;
    frame_data *first_fdata;
    frame_data *prev_fdata;
    frame_data *prev_cap_fdata;

    nstime_t prev_cap_ts;
    first_fdata = GetFrameData(m_markedPktNum, true);
    const unsigned int realPktNum = ignoreFilter ? pktNum : GetRealPktNum(pktNum);
    if( realPktNum > m_maxPktNumDecoded + 1)
    {
        int protocolId = -1;
        for(unsigned int i = m_maxPktNumDecoded + 1; i < realPktNum; i++)
        {
            fdata = GetFrameData(i, true);
            if (fdata == NULL) continue;    /* we didn't find that frame */

            DecodePacket(fdata, first_fdata, NULL, true, protocolId);
        }
        m_maxPktNumDecoded = realPktNum;
    }
    fdata = GetFrameData(pktNum, ignoreFilter);
    if (fdata == NULL)
        return false;    /* we didn't find that frame */

    //first_fdata is used to calc time info only
    // samuell: 10-25-2002 
    // since the markted frame is the real packet number so turn ignoreFileter to TRUE
//    first_fdata = GetFrameData(m_markedPktNum, ignoreFilter);
    first_fdata = GetFrameData(m_markedPktNum, true);

    if (pktNum==1)
        prev_fdata = NULL;
    else
        prev_fdata = GetFrameData(pktNum-1, ignoreFilter);

    int protocolId = -1;
	if (realPktNum == 1)
	{
		prev_cap_fdata = fdata;
		prev_cap_ts = fdata->abs_ts;
	}
	else
	{
		prev_cap_fdata = GetFrameData(realPktNum-1, true);
		prev_cap_ts = prev_cap_fdata->abs_ts;
	}
    nstime_delta(&fdata->del_cap_ts,&fdata->abs_ts,&prev_cap_ts); 
    bool bRet = DecodePacket(fdata, first_fdata, prev_fdata, bSummaryOnly, protocolId);

    m_lastPktNumDecoded = ignoreFilter ? pktNum : GetRealPktNum(pktNum);
	if(realPktNum > m_maxPktNumDecoded) m_maxPktNumDecoded = realPktNum;
    
    if (bRet && bSummaryOnly && (GetProtocolId(pktNum, ignoreFilter)==-1))
        SetProtocolId(pktNum, protocolId, ignoreFilter);

    return bRet;
}

bool CWtapFile::DecodePacket(frame_data *fdata, frame_data *first_fdata, frame_data *prev_fdata, bool bSummaryOnly, int &protocolId)
{
  gchar      *err_info;
    protocolId = -1;

    /* Record that this frame is the current frame. */
    m_pCapFile->current_frame = fdata;
    
    /* Get the time elapsed between the first packet and this packet. for rel. time*/
    //USE modified
    //compute_timestamp_diff(&fdata->rel_ts.secs, &fdata->rel_ts.nsecs, fdata->abs_ts.secs, fdata->abs_ts.nsecs, first_fdata->abs_ts.secs, first_fdata->abs_ts.nsecs);
    nstime_delta(&fdata->rel_ts,&fdata->abs_ts,&first_fdata->abs_ts);
    // for gigabit (or any decode file having nanosecond resolution), do a 
    // similar calulation using nanoseconds instead of microseconds
  /*  if (fdata->flags.nsec_resolution)
    {
        /* gint32 dummy_secs;
           compute_nsec_timestamp_diff(
	    &dummy_secs, &fdata->rel_ts.nsecs,
	    fdata->abs_ts.secs, fdata->abs_ts.nsecs, 
	    first_fdata->abs_ts.secs, first_fdata->abs_ts.nsecs);
	    */
    /*	nstime_t dummy_ts;
	nstime_delta(&dummy_ts,&fdata->abs_ts,&first_fdata->abs_ts);
	fdata->rel_ts.nsecs = dummy_ts.nsecs;
    }*/

    /* Get the time elapsed between the previous displayed packet and this packet. for delta time*/
    // USE modified
    //guint32 prevsec, prevusec, prevnsec;
    nstime_t prev_ts;
    if (prev_fdata == NULL)
    {
	/*
        prevsec = fdata->abs_ts.secs;
        prevusec = fdata->abs_ts.nsecs/1000;
        prevnsec = fdata->abs_ts.nsecs;
	*/
	prev_ts.secs = fdata->abs_ts.secs;
	prev_ts.nsecs = fdata->abs_ts.nsecs;
    }
    else
    {
	/*
        prevsec = prev_fdata->abs_ts.secs;
        prevusec = prev_fdata->abs_ts.nsecs/1000;
        prevnsec = prev_fdata->abs_ts.nsecs;
	*/
	prev_ts.secs = prev_fdata->abs_ts.secs;
	prev_ts.nsecs = prev_fdata->abs_ts.nsecs;

    }
    //compute_timestamp_diff(&fdata->del_ts.secs, &fdata->del_ts.nsecs, fdata->abs_ts.secs, fdata->abs_ts.nsecs, prevsec, prevusec);
    nstime_delta(&fdata->del_dis_ts,&fdata->abs_ts,&prev_ts);
    // for gigabit (or any decode file having nanosecond resolution), do a 
    // similar calulation using nanoseconds instead of microseconds
/*
    if (fdata->flags.nsec_resolution)
    {
       /* gint32 dummy_secs;
        compute_nsec_timestamp_diff(
	    &dummy_secs, &fdata->del_ts.nsecs,
            fdata->abs_ts.secs, fdata->abs_ts.nsecs,
            prevsec, prevnsec);*/
/*	nstime_ts dummy_t;
	nstime_delta(&dummy_t,&fdata->abs_ts,&prev_ts);
    }*/

    /* Get the data in that frame. */
    int err;
    wtap_seek_read(m_pCapFile->wth, fdata->file_off, &m_pCapFile->pseudo_header, m_pCapFile->pd, fdata->cap_len, &err,&err_info);

    /* free any old packet decode info (also frees any protocol tree) */
    if (m_pCapFile->edt != 0)
    {
        epan_dissect_free(m_pCapFile->edt);
        m_pCapFile->edt = 0;
    }
#ifdef _MSC_VER
    __try
    {
#endif
        /* Decode the current frame */
/*
		if (m_pCapFile->pseudo_header.eth.fcs_len == 4)
		{
			m_pCapFile->current_frame->cap_len += m_pCapFile->pseudo_header.eth.fcs_len;
			m_pCapFile->current_frame->pkt_len += m_pCapFile->pseudo_header.eth.fcs_len;
		}
*/
        if (bSummaryOnly)
        {
            m_pCapFile->edt = epan_dissect_new(TRUE, FALSE); // for customer extend with plugin, need tree to get Summmary information. refer bug#9962

            // note: initialization of the column info in m_pCapFile->edt->pi.cinfo is now done by epan_dissect_run call (it copies
            // the column info passed in in the last param)
            epan_dissect_run(m_pCapFile->edt, &m_pCapFile->pseudo_header, m_pCapFile->pd, m_pCapFile->current_frame, &m_pCapFile->cinfo);

            epan_dissect_fill_in_columns(m_pCapFile->edt, true, true);

            protocolId = LookupProtocolId((char*)m_pCapFile->edt->pi.cinfo->col_data[SUMMARY_COL_PROTOCOL]); // convert prototype short name to externalizable protocol id
        }
        else
        {
            m_pCapFile->edt = epan_dissect_new(TRUE,TRUE); // initializes protocol tree
            if (m_pCapFile->wth->file_type == WTAP_FILE_SHOMITI)
							m_pCapFile->edt->pi.is_shomiti_type = 1;			
						else			
							m_pCapFile->edt->pi.is_shomiti_type = 0;
            epan_dissect_run(m_pCapFile->edt, &m_pCapFile->pseudo_header, m_pCapFile->pd, m_pCapFile->current_frame, 0);
        }

/*		if (m_pCapFile->pseudo_header.eth.fcs_len == 4)
		{
			m_pCapFile->current_frame->cap_len -= m_pCapFile->pseudo_header.eth.fcs_len;
			m_pCapFile->current_frame->pkt_len -= m_pCapFile->pseudo_header.eth.fcs_len;
		}
*/
#ifdef _MSC_VER
    }
__except(TRUE /* handle all exceptions */)
    {
        return false;
    }
#endif

    return true;
}

//pktNum is 1-based
/*+---------------------------------------------------------
 *    Pre-Scan functions
 *----------------------------------------------------------
-*/
void CWtapFile::PreScanInit()
{
    m_pDecodePreScan = new CDecodePreScan();
}

void CWtapFile::PreScanTerminate()
{
    if (m_pDecodePreScan)
    {
        delete m_pDecodePreScan;
        m_pDecodePreScan = NULL;
    }
}

bool CWtapFile::IsNameResolvingOn()
{
    return m_bNameResolving;
}

void CWtapFile::SetNameResolving(bool enabled)
{
    m_bNameResolving = enabled;
}


void CWtapFile::NameResolvingProcess(unsigned char *pFrameStart, int frameLen)
{
    e_iphdr  *pIpHdr;
    e_udphdr *pUdpHdr;
    e_tcphdr *pTcpHdr;
    int           appOffset;
#define LLC_LEN        14

    if (frameLen < 60)
        return;


    pIpHdr = (e_iphdr *)(pFrameStart + LLC_LEN);

    switch  (pIpHdr->ip_p)
    {
        case UDP_PROTOCOL:
            pUdpHdr = (e_udphdr *)(pIpHdr + 1);
            if (ntohs(pUdpHdr->uh_dport) == DNS_PORT || 
                ntohs(pUdpHdr->uh_sport) == DNS_PORT)
            {
                // process DNS name resolving
                appOffset = LLC_LEN + sizeof(e_iphdr) + sizeof(e_udphdr);
                DnsResolveName(pFrameStart+appOffset, frameLen - appOffset);
            }
            
            if (ntohs(pUdpHdr->uh_dport) == IP_UDP_NETBIOS_NS || 
                ntohs(pUdpHdr->uh_sport) == IP_UDP_NETBIOS_NS)
            {
                unsigned char *pAppStart;
                // process WINS name resolving
                appOffset = LLC_LEN + sizeof(e_iphdr) + sizeof(e_udphdr);
                
                pAppStart = pFrameStart + appOffset;
                if (pAppStart[2] & 0x80)
                {
                    WinsResolveName(pAppStart, frameLen - appOffset);
                }
            }
            break;

        case TCP_PROTOCOL:
            pTcpHdr = (e_tcphdr *)pIpHdr;
            pTcpHdr = (e_tcphdr *)(pTcpHdr + 1);
            if (ntohs(pTcpHdr->th_dport) == DNS_PORT || 
                ntohs(pTcpHdr->th_sport) == DNS_PORT)
            {
                // process DNS name resolving
                appOffset = LLC_LEN + sizeof(e_iphdr) + sizeof(e_tcphdr);
                DnsResolveName(pFrameStart+appOffset+2, frameLen - appOffset - 2);
                
            }
            break;

        default:
            break;
    }

}

bool CWtapFile::IsPreScanOn()
{
    return m_pDecodePreScan != NULL;
}

void CWtapFile::PreScanProcess(unsigned char *pFrameStart, int frameLen)
{
    // samuell: fill in data
    m_pDecodePreScan->Process(pFrameStart, frameLen);
}


static unsigned int HexToBin(char c)
{
    c = tolower(c);
    return (c>='a' && c<='f') ? 10+c-'a' : c-'0';
}

int CWtapFile::SearchPacketDataHex(char * inHexSearchData, int searchDataSize, int startPktNum, bool allowWrapping)
{
    if ( !inHexSearchData || (startPktNum<1) )
        return 0;

    DecodeSearchState * pDecodeSearchState = new DecodeSearchState;

    InternalSearchState * pSearchState = new InternalSearchState;
    InternalSearchState &searchState = *pSearchState;

    pDecodeSearchState->searchState = pSearchState;

    searchState.SetSearchType( InternalSearchState::HEX_DATA_SEARCH );

    searchState.SetStartPacketNumber(startPktNum);
    searchState.SetPacketNumber(startPktNum);
    searchState.SetAllowWrapping(allowWrapping);
    searchState.SetStartOffset(0);
    searchState.SetEndOffset(-1);

    // convert the ascii hex representation to binary

    char *buffer = new char[searchDataSize+1];
    memcpy(buffer, inHexSearchData, searchDataSize);
    buffer[searchDataSize] = 0;

    searchState.AllocateSearchData(searchDataSize); // shouldn't ever need more than this

    bool ok = true;
    char * token = strtok( buffer, " \n" );
    while (token)
    {
        if (strlen(token) != 2)
        {
            ok = false;
            break;
        }

        guint8 value = (HexToBin(token[0]) << 4) + HexToBin(token[1]);

        searchState.AddSearchData(value);

        token = strtok( 0, " \n" );
    }

    delete [] buffer; buffer = 0;

    if (!ok)
    {
        // something bad happened in decoding.
        // note: decode search state will automatically delete the internal
        // search state.
        delete pDecodeSearchState;
        return 0;
    }

    // do the search
    SearchPacketDataBinary( pSearchState );

    // put results into search state
    searchState.FillInDecodeSearchState( pDecodeSearchState );

    // create a session id from the search state
    int searchSessionId = CreateNewSearchSession(pDecodeSearchState);

    return searchSessionId;
}


int CWtapFile::SearchPacketDataASCII(char * asciiSearchData, int searchDataSize, int startPktNum, bool allowWrapping)
{
    if ( !asciiSearchData || (startPktNum<1) )
        return 0;

    DecodeSearchState * pDecodeSearchState = new DecodeSearchState;

    InternalSearchState * pSearchState = new InternalSearchState;
    InternalSearchState &searchState = *pSearchState;

    pDecodeSearchState->searchState = pSearchState;

    searchState.SetSearchType( InternalSearchState::ASCII_DATA_SEARCH );

    searchState.SetStartPacketNumber(startPktNum);
    searchState.SetPacketNumber(startPktNum);
    searchState.SetAllowWrapping(allowWrapping);
    searchState.SetStartOffset(0);
    searchState.SetEndOffset(-1);

    searchState.CopySearchData((guint8 *) asciiSearchData, searchDataSize);

    SearchPacketDataBinary( pSearchState );

    searchState.FillInDecodeSearchState( pDecodeSearchState );

    int searchSessionId = CreateNewSearchSession(pDecodeSearchState);

    return searchSessionId;
}

int CWtapFile::SearchColumn(char *searchData, int searchDataSize, int columnIndex, int startPktNum, bool allowWrapping)
{
    if (!searchData)
        return 0;

    DecodeSearchState * pDecodeSearchState = new DecodeSearchState;

    InternalSearchState * pSearchState = new InternalSearchState;
    InternalSearchState &searchState = *pSearchState;

    pDecodeSearchState->searchState = pSearchState;

    searchState.SetSearchType( InternalSearchState::COLUMN_SEARCH );

    searchState.SetStartPacketNumber(startPktNum);
    searchState.SetPacketNumber(startPktNum);
    searchState.SetAllowWrapping(allowWrapping);
    searchState.SetStartOffset(0);
    searchState.SetEndOffset(-1);
    searchState.SetColumnIndex(columnIndex);

    searchState.CopySearchData((guint8 *) searchData, searchDataSize);

    SearchColumnData( pSearchState );
    
    searchState.FillInDecodeSearchState( pDecodeSearchState );
    
    int searchSessionId = CreateNewSearchSession(pDecodeSearchState);

    return searchSessionId;
}


int CWtapFile::SearchDetail(char *searchData, int searchDataSize, int startPktNum, bool allowWrapping)
{
    if (!searchData)
        return 0;

    DecodeSearchState * pDecodeSearchState = new DecodeSearchState;

    InternalSearchState * pSearchState = new InternalSearchState;
    InternalSearchState &searchState = *pSearchState;

    pDecodeSearchState->searchState = pSearchState;

    searchState.SetSearchType( InternalSearchState::PROTO_TREE_SEARCH );

    searchState.SetStartPacketNumber(startPktNum);
    searchState.SetPacketNumber(startPktNum);
    searchState.SetAllowWrapping(allowWrapping);
    searchState.SetStartOffset(0);
    searchState.SetEndOffset(-1);
    searchState.SetLineIndex(0);

    searchState.CopySearchData((guint8 *) searchData, searchDataSize);

    SearchProtoTreeData( pSearchState );
    
    searchState.FillInDecodeSearchState( pDecodeSearchState );
    
    int searchSessionId = CreateNewSearchSession(pDecodeSearchState);

    return searchSessionId;
}

int CWtapFile::GetSearchResultCode(int sessionId)
{
    if (sessionId == 0)
        return -1;

    DecodeSearchState * pDecodeSearchState = GetSearchStateFromSessionId(
        sessionId);

    if (!pDecodeSearchState)
        return -1;

    return (int) pDecodeSearchState->result;
}    

int CWtapFile::GetSearchPacketNumber(int sessionId)
{
    if (sessionId == 0)
        return -1;

    DecodeSearchState * pDecodeSearchState = GetSearchStateFromSessionId(
        sessionId);

    if (!pDecodeSearchState)
        return -1;

    return (int) pDecodeSearchState->packetNumber;    
}    

int CWtapFile::GetSearchStartOffset(int sessionId)
{
    if (sessionId == 0)
        return -1;

    DecodeSearchState * pDecodeSearchState = GetSearchStateFromSessionId(
        sessionId);

    if (!pDecodeSearchState)
        return -1;

    return (int) pDecodeSearchState->startOffset;    
}    

int CWtapFile::GetSearchEndOffset(int sessionId)
{
    if (sessionId == 0)
        return -1;

    DecodeSearchState * pDecodeSearchState = GetSearchStateFromSessionId(
        sessionId);

    if (!pDecodeSearchState)
        return -1;

    return (int) pDecodeSearchState->endOffset;        
}   
 
int CWtapFile::GetSearchLineIndex(int sessionId)
{
    if (sessionId == 0)
        return -1;

    DecodeSearchState * pDecodeSearchState = GetSearchStateFromSessionId(
        sessionId);

    if (!pDecodeSearchState)
        return -1;

    return (int) pDecodeSearchState->lineIndex;    
}    

void CWtapFile::ContinueSearch(int searchSessionId)
{
    DecodeSearchState * pDecodeSearchState = GetSearchStateFromSessionId(
        searchSessionId);

    if (!pDecodeSearchState)
        return;

    InternalSearchState *pSearchState = (InternalSearchState *) pDecodeSearchState->searchState;

    if (!pSearchState)
    {
        pDecodeSearchState->result = SEARCH_ERROR;
        return;
    }

    if (pSearchState->GetSearchResult() == SEARCH_ERROR)
    {
        // don't try to continue after an error
        pSearchState->FillInDecodeSearchState( pDecodeSearchState );
        return;
    }

    switch( pSearchState->GetSearchType() )
    {
        case InternalSearchState::HEX_DATA_SEARCH:
        case InternalSearchState::ASCII_DATA_SEARCH:
        {
            if (pSearchState->GetSearchResult() == PACKET_FOUND)
                pSearchState->SetStartOffset( pSearchState->GetStartOffset() + 1 ); // so we don't search the same thing we found last time (if any)

            SearchPacketDataBinary( pSearchState );

            break;
        }

        case InternalSearchState::COLUMN_SEARCH:
        {
            if (pSearchState->GetSearchResult() == PACKET_FOUND)
                pSearchState->SetStartOffset( pSearchState->GetStartOffset() + 1 ); // so we don't search the same thing we found last time (if any)

            SearchColumnData( pSearchState );

            break;
        }

        case InternalSearchState::PROTO_TREE_SEARCH:
        {
            if (pSearchState->GetSearchResult() == PACKET_FOUND)
                // don't search the same thing again
                pSearchState->SetStartOffset( pSearchState->GetStartOffset() + 1 ); 

            SearchProtoTreeData( pSearchState );
                
            break;
        }

        default:
            assert(false);
    }

    pSearchState->FillInDecodeSearchState( pDecodeSearchState );
}

void CWtapFile::DoneSearching( int searchSessionId )
{
    CleanupSearchSession(searchSessionId);
}

int CWtapFile::CreateNewSearchSession(DecodeSearchState *pDecodeSearchState)
{
    for (int i=0; i<NUMBER_OF_SEARCH_SESSION_SLOTS; i++)
    {
        if (searchSessionSlots[i] == 0)
        {
            searchSessionSlots[i] = pDecodeSearchState;
            return i+1;
        }
    }

    return 0;
}    

DecodeSearchState * CWtapFile::GetSearchStateFromSessionId(int searchSessionId)
{
    if (searchSessionId == 0)
        return 0;

    int index = searchSessionId - 1;

    if (index >= NUMBER_OF_SEARCH_SESSION_SLOTS)
        return 0;

    return searchSessionSlots[index];
}    


void CWtapFile::CleanupSearchSession(int searchSessionId)
{
    if (searchSessionId == 0)
        return;

    int index = searchSessionId - 1;

    if (index >= NUMBER_OF_SEARCH_SESSION_SLOTS)
        return;

    delete searchSessionSlots[index];
    
    searchSessionSlots[index] = 0;
}    

    
void CWtapFile::SearchPacketDataBinary( InternalSearchState *pSearchState )
{
    assert(pSearchState);
    InternalSearchState &searchState = *pSearchState;

    int startOffset = searchState.GetStartOffset();
    int endOffset = -1;

    int packetsSearched = 0;
    guint8 dataBuf[WTAP_MAX_PACKET_SIZE];        
  gchar      *err_info;
    while( true )
    {
        frame_data *fdata = GetFrameData(searchState.GetPacketNumber());
        if (fdata == NULL)
        {
            searchState.SetSearchResult( SEARCH_ERROR );
            break;
        }

        union wtap_pseudo_header pseudoHeader;
        int err;
        wtap_seek_read(m_pCapFile->wth, fdata->file_off, &pseudoHeader, dataBuf, fdata->cap_len, &err,&err_info);

        if (SearchForData( 
                dataBuf, 
                fdata->cap_len,
                searchState.GetSearchDataPtr(),
                searchState.GetSearchDataSize(),
                startOffset,
                endOffset))
        {
            searchState.SetSearchResult( PACKET_FOUND );
            searchState.SetStartOffset(startOffset);
            searchState.SetEndOffset(endOffset);
            break;
        }

        packetsSearched++;
        startOffset = 0;

        searchState.IncPacketNumber();

        if (searchState.GetPacketNumber() > GetNumOfPackets(false)) // packet numbers are 1-based
        {
            if (searchState.AllowWrapping())
                searchState.SetPacketNumber(1);
            else
            {
                searchState.SetSearchResult( PACKET_NOT_FOUND );
                break;
            }
        }

        if (searchState.GetPacketNumber() == searchState.GetStartPacketNumber())
        {
            searchState.SetSearchResult( PACKET_NOT_FOUND );
            break;
        }


        if ( (searchState.PacketsPerSearch() > 0) &&
             (packetsSearched >= searchState.PacketsPerSearch()) )
        {
            searchState.SetStartOffset(0);
            searchState.SetSearchResult( STILL_SEARCHING );
            break;
        }
    }
}



void CWtapFile::SearchColumnData( InternalSearchState *pSearchState )
{
    assert(pSearchState);
    InternalSearchState &searchState = *pSearchState;

    int packetsSearched = 0;
    int columnIndex = searchState.GetColumnIndex();
    int startOffset = searchState.GetStartOffset();
    int endOffset = -1;
    guint8 dataBuf[WTAP_MAX_PACKET_SIZE];        
  gchar      *err_info;
    while( true )
    {
        // get frame meta-info
        frame_data *fdata = GetFrameData(searchState.GetPacketNumber());
        if (fdata == NULL)
        {
            searchState.SetSearchResult( SEARCH_ERROR );
            break;
        }

        // read frame data
        union wtap_pseudo_header pseudoHeader;
        int err;
        wtap_seek_read(m_pCapFile->wth, fdata->file_off, &pseudoHeader, dataBuf, fdata->cap_len, &err,&err_info);


        try
        {
            // dissect packet (w/o creating protocol tree)
            // note: we're utilizing the column info in the capture file struct. this will destroy any
            // old column info.
            epan_dissect_t *edt = epan_dissect_new(FALSE,FALSE);
            epan_dissect_run(edt, &pseudoHeader, dataBuf, fdata, &m_pCapFile->cinfo);
            // fill in column info
            epan_dissect_fill_in_columns(edt, true, true);

            // free dissect info
            epan_dissect_free(edt);

            // search the desired column
            const char * columnString = m_pCapFile->cinfo.col_data[columnIndex];
            if (columnString && strlen(columnString) &&
                SearchForData(
                    (guint8 *) columnString, 
                    unsigned int(strlen(columnString)), 
                    searchState.GetSearchDataPtr(),
                    searchState.GetSearchDataSize(),
                    startOffset,
                    endOffset))
            {
                searchState.SetSearchResult( PACKET_FOUND );
                searchState.SetStartOffset(startOffset);
                searchState.SetEndOffset(endOffset);
                break;
            };
        }
        catch(...)
        {
        }

        packetsSearched++;
        startOffset = 0;

        searchState.IncPacketNumber();

        if (searchState.GetPacketNumber() > GetNumOfPackets(false)) // packet numbers are 1-based
        {
            if (searchState.AllowWrapping())
                searchState.SetPacketNumber(1);
            else
            {
                searchState.SetSearchResult( PACKET_NOT_FOUND );
                break;
            }
        }

        if (searchState.GetPacketNumber() == searchState.GetStartPacketNumber())
        {
            searchState.SetSearchResult( PACKET_NOT_FOUND );
            break;
        }


        if ( (searchState.PacketsPerSearch() > 0) &&
             (packetsSearched >= searchState.PacketsPerSearch()) )
        {
            searchState.SetStartOffset( 0 );
            searchState.SetSearchResult( STILL_SEARCHING );
            break;
        }
    }
}


void CWtapFile::SearchProtoTreeData( InternalSearchState *pSearchState )
{
    assert(pSearchState);
    InternalSearchState &searchState = *pSearchState;

    int packetsSearched = 0;
    int startOffset = searchState.GetStartOffset();
    int endOffset = -1;
    guint8 dataBuf[WTAP_MAX_PACKET_SIZE];        
  gchar      *err_info;
    while( true )
    {
        // get frame meta-info
        frame_data *fdata = GetFrameData(searchState.GetPacketNumber());
        if (fdata == NULL)
        {
            searchState.SetSearchResult( SEARCH_ERROR );
            break;
        }

        // read frame data
        union wtap_pseudo_header pseudoHeader;
        int err;
        wtap_seek_read(m_pCapFile->wth, fdata->file_off, &pseudoHeader, dataBuf, fdata->cap_len, &err,&err_info);

        try
        {
            // create the protocol tree by dissecting the frame data
            epan_dissect_t *edt = epan_dissect_new(TRUE,TRUE);
            epan_dissect_run(edt,&pseudoHeader, dataBuf, fdata, 0);

            // create a list of items in the protocol tree
            GSList * treeItemList = 0;
            ParseProtocolTree( edt->tree, treeItemList );

            // determine number of items in the list
            int itemsInList = g_slist_length(treeItemList);

            // loop through each item in the list looking for the search pattern
            while (searchState.GetLineIndex() < itemsInList)
            {
                // get the text for this tree item
                gchar * pLabel = 0;
                unsigned int labelLength = 0;
                {
                    proto_node *node = (proto_node *) g_slist_nth_data(treeItemList, searchState.GetLineIndex());
                    field_info    *fi = node->finfo; 
                    if (fi->rep)
                        pLabel = fi->rep->representation;
                    else
                    {
                        static gchar buffer[ITEM_LABEL_LENGTH];
                        pLabel = buffer;
                        proto_item_fill_label(fi, pLabel);
                    }
                    labelLength = unsigned int(strlen(pLabel));
                }

                if (pLabel && labelLength &&
                    SearchForData(
                        (guint8 *) pLabel,
                        labelLength,
                        searchState.GetSearchDataPtr(),
                        searchState.GetSearchDataSize(),
                        startOffset,
                        endOffset))
                {
                    // free the item list and proto tree
                    g_slist_free(treeItemList); treeItemList = 0;
                    // free dissect info (including tree)
                    epan_dissect_free(edt);
                    edt = 0;

                    // set return values that aren't set already (line index is already set)
                    searchState.SetSearchResult( PACKET_FOUND );
                    searchState.SetStartOffset(startOffset);
                    searchState.SetEndOffset(endOffset);

                    // can't 'break' here - we're in an inner loop
                    return;
                };

                searchState.IncLineIndex();
                startOffset = 0;
            }

            // free the item list and proto tree
            g_slist_free(treeItemList); treeItemList = 0;
            // free dissect info (including tree)
            epan_dissect_free(edt);
            edt = 0;
        }
        catch(...)
        {
        }

        packetsSearched++;
        startOffset = 0;
        searchState.SetLineIndex(0);

        searchState.IncPacketNumber();

        if (searchState.GetPacketNumber() > GetNumOfPackets(false)) // packet numbers are 1-based
        {
            if (searchState.AllowWrapping())
                searchState.SetPacketNumber(1);
            else
            {
                searchState.SetSearchResult( PACKET_NOT_FOUND );
                break;
            }
        }

        if (searchState.GetPacketNumber() == searchState.GetStartPacketNumber())
        {
            searchState.SetSearchResult( PACKET_NOT_FOUND );
            break;
        }


        if ( (searchState.PacketsPerSearch() > 0) &&
             (packetsSearched >= searchState.PacketsPerSearch()) )
        {
            searchState.SetStartOffset( 0 );
            searchState.SetSearchResult( STILL_SEARCHING );
            break;
        }
    }
}



bool CWtapFile::SearchForData(
    guint8 *packetData,
    unsigned int packetDataSize,
    guint8 *searchData,
    unsigned int searchDataSize,
    int & startOffset,
    int & endOffset )
{
    guint8 *packetPointer = packetData + startOffset;
    guint8 *packetEndPointer = packetData + packetDataSize;
    guint8 *searchPointer = searchData;
    guint8 *searchEndPointer = searchData + searchDataSize;
    
    while (packetPointer < packetEndPointer)
    {
        if (*packetPointer == *searchPointer)
        {
            guint8 *packetScanPointer = packetPointer+1;
            searchPointer++;

            while ( 
                (packetScanPointer < packetEndPointer) &&
                (searchPointer < searchEndPointer) &&
                (*packetScanPointer == *searchPointer) )
            {
                packetScanPointer++;
                searchPointer++;
            }
            
            if (searchPointer >= searchEndPointer)
            {
                startOffset = int(packetPointer - packetData);
                endOffset = int(packetScanPointer - packetData - 1);
                return true;        
            }

            searchPointer = searchData;
        }

        packetPointer++;
    }

    return false;
}      
  
//#include <strings.h>

// returns external protocol id (or -1 if error)
// -1 = error, 0=unrecognized, 1="ethernet", 2="IP", etc
int CWtapFile::LookupProtocolId(char *protocolShortName)
{    
    static char * recognizedNames[] = {
        "Ethernet", "IP", "TCP", "UDP", "HTTP", "FTP", "H.225", "SIP",
        "RTP", "Q931", "SNMP", "ICMP", "IGMP", "IGRP", "Vines FRP",
        "OSPF", "DNS", "LDAP", "NetBIOS", "NNTP", "POP", "Rlogin",
        "RSH", "SMTP", "RPC", "TELNET", "X11", "BOOTP/DHCP", 
        "NFS", "RIP", "Syslog", "TFTP", "WHO", "TDS", "DCERPC",
        "SMB", "SMB Pipe", "EPM", "AutoNeg", "GigLink", "STP", "MEGACO",
        "RSVP"
    };

    static int count = sizeof(recognizedNames) / sizeof(recognizedNames[0]);

    for (int i=0; i<count; i++)
    {
        if (_stricmp(recognizedNames[i], protocolShortName) == 0)
            return i+1;
    }

    return 0;
}


unsigned int CWtapFile::GetNumberOfSegments() 
{
    return 1 + m_pCapFile->wth->extra_segment_count;
}

wchar_t * CWtapFile::GetSegmentName(unsigned int segmentIndex)
{
    if (segmentIndex == 0)
    {
        return (wchar_t *) &m_pCapFile->wth->first_segment.name[0];
    }

    if (segmentIndex > 3)
        return 0;

    return (wchar_t *) &m_pCapFile->wth->extra_segments[segmentIndex-1].name[0];
}

void CWtapFile::InitCFile(capture_file &_cfile)
{
    int i;
    /* Initialize the capture file struct */
    _cfile.plist_start  = NULL;
    _cfile.plist_end    = NULL;
    _cfile.wth        = NULL;
    _cfile.filename    = NULL;
    _cfile.user_saved    = FALSE;
    _cfile.is_tempfile    = FALSE;
    _cfile.rfcode        = NULL;
    _cfile.displayfilter        = NULL;
//    _cfile.dfcode        = NULL;
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
    _cfile.cinfo.col_fmt[SUMMARY_COL_DELTA_TIME] = COL_DELTA_TIME_DIS; //COL_DELTA_TIME;
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
    for (i = 0; i < _cfile.cinfo.num_cols; i++)
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
			_cfile.cinfo.col_expr.col_expr[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_INFO_LEN);
            _cfile.cinfo.col_expr.col_expr_val[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_INFO_LEN);
        }
        else
        {
            _cfile.cinfo.col_buf[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
            _cfile.cinfo.col_expr.col_expr[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
            _cfile.cinfo.col_expr.col_expr_val[i] = (gchar *) g_malloc(sizeof(gchar) * COL_MAX_LEN);
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

void CWtapFile::Init()
{
    // create the environment variable so that it packet-radius can find the dictionary
#ifndef __CS_LINUX
    char szPath[512];
    char szDrive[_MAX_DRIVE];
    char szDir[_MAX_DIR];
    if (GetModuleFileName(NULL, szPath, 512) != 0)
    {
        _splitpath(szPath, szDrive, szDir, 0, 0);
        wsprintf(szPath, "%s%s", szDrive, szDir);
    }
    // set it to our current installed program dir
    char szEnv[sizeof(szPath)+10];
    strcpy(szEnv, "APPDATA=");
    strcat(szEnv, szPath);
    _putenv(szEnv);
#else
    // on linux system, we don't need this variable.
#endif


    //***************** should only be called once, JJL
    /* Register all dissectors; we must do this before checking for the
       "-G" flag, as the "-G" flag dumps a list of fields registered
       by the dissectors, and we must do it before we read the preferences,
       in case any dissectors register preferences. */
    epan_init(register_all_protocols,register_all_protocol_handoffs,NULL,NULL,NULL,NULL, NULL, NULL);


    CWtapFile::InitCFile(cfile_for_standalone);

    // Initialize all data structures used for dissection
    // note: we need to call this now (we didn't before) because it calls
    // epan_conversation_init() (we did call this previously) AND 
    // reassemble_init(). reassemble_init must now be called because a new
    // dissector (packet-fc.c) requires it so that certain g_mem_chunk_alloc
    //  calls will not fail (see packet-fc.c and reassemble.c in ethereal)
    init_dissection();
    init_all_protocols();
}

void CWtapFile::Cleanup()
{
    epan_cleanup();
}

int CWtapFile::GetLastPktNum() const
{
    assert((int)GetNumOfPackets(false) != 0);
    return m_pPacketFilterIndexArray != NULL ? m_pPacketFilterIndexArray[m_numberOfFilterIndeces-1] + 1 : m_pCapFile->count;
}

int CWtapFile::GetFirstPktNum() const
{
    assert(GetNumOfPackets(false) != 0);
    return m_pPacketFilterIndexArray != NULL ? m_pPacketFilterIndexArray[0] + 1 : 1;
}

//<--------------Antonio 2007-10-19, for IPsec-------------

void CWtapFile::setAttemptToDecodeEspPayload(bool bEnable)
{
	for (int i=0; i<IPSEC_NB_SA; i++)
	{
		g_esp_sad.table[i].is_valid = bEnable;
	}

	g_esp_enable_encryption_decode = bEnable;

}

void CWtapFile::setAttemptToCheckEspAuthentication(bool bEnable)
{
	g_esp_enable_authentication_check = bEnable;
}

void CWtapFile::clearEspParamSet(void)
{
	
	for (int i=0; i<g_esp_sad.nb; i++)
	{
		if (g_esp_sad.table[i].sa != NULL)
		{
			g_free((void *)g_esp_sad.table[i].sa);
			g_esp_sad.table[i].sa = NULL;
		}
		
		if (g_esp_sad.table[i].encryption_key != NULL)
		{
			g_free((void *)g_esp_sad.table[i].encryption_key);
			g_esp_sad.table[i].encryption_key = NULL;
		}
		
		if (g_esp_sad.table[i].authentication_key != NULL)
		{
			g_free((void *)g_esp_sad.table[i].authentication_key);
			g_esp_sad.table[i].authentication_key = NULL;
		}
	}

	g_esp_sad.nb = 0;
	
}

void CWtapFile::addEspParamSet(int addressType, const char * sourceAddress, const char * destinationAddress, 
							   const char * securityParameterIndex, int encryptionAlgorithm, const char * encryptionKey,
							   int authenticationAlgorithm, const char * authenticationKey)
{
	
	if (g_esp_sad.nb < IPSEC_NB_SA)
	{
		g_esp_sad.table[g_esp_sad.nb].sa = (gchar *)g_malloc(strlen("IPV4|") + strlen(sourceAddress) + strlen("|") + strlen(destinationAddress) + strlen("|") + strlen(securityParameterIndex) + 1);
		
	
		if (addressType == IPSEC_SA_IPV6)
		{
			strcpy((char *)g_esp_sad.table[g_esp_sad.nb].sa, "IPV6|");
		}else
		{
			strcpy((char *)g_esp_sad.table[g_esp_sad.nb].sa, "IPV4|");
		}

		strcpy((char *)(g_esp_sad.table[g_esp_sad.nb].sa + strlen(g_esp_sad.table[g_esp_sad.nb].sa)), sourceAddress);
		strcpy((char *)(g_esp_sad.table[g_esp_sad.nb].sa + strlen(g_esp_sad.table[g_esp_sad.nb].sa)), "|");
		strcpy((char *)(g_esp_sad.table[g_esp_sad.nb].sa + strlen(g_esp_sad.table[g_esp_sad.nb].sa)), destinationAddress);
		strcpy((char *)(g_esp_sad.table[g_esp_sad.nb].sa + strlen(g_esp_sad.table[g_esp_sad.nb].sa)), "|");
		strcpy((char *)(g_esp_sad.table[g_esp_sad.nb].sa + strlen(g_esp_sad.table[g_esp_sad.nb].sa)), securityParameterIndex);
			
		g_esp_sad.table[g_esp_sad.nb].typ = addressType;

		g_esp_sad.table[g_esp_sad.nb].encryption_algo = encryptionAlgorithm;
		g_esp_sad.table[g_esp_sad.nb].authentication_algo = authenticationAlgorithm;

		g_esp_sad.table[g_esp_sad.nb].encryption_key = (const gchar *)g_malloc(strlen(encryptionKey) + 1);
		strcpy((char *)g_esp_sad.table[g_esp_sad.nb].encryption_key, encryptionKey);

		g_esp_sad.table[g_esp_sad.nb].authentication_key = (const gchar *)g_malloc(strlen(authenticationKey) + 1);
		strcpy((char *)g_esp_sad.table[g_esp_sad.nb].authentication_key, authenticationKey);
		
		
		g_esp_sad.nb++;
	}
	
}


//--------------Antonio 2007-10-19, for IPsec------------->

int CWtapFile::GetTriggerFrameIndex()
{	
	//return GetPacketPosition(m_triggerPktNum , false);
	return m_triggerPktNum;
}
bool CWtapFile::IsShomitiFile()
{
	return m_pCapFile->wth->file_type == WTAP_FILE_SHOMITI;
}
