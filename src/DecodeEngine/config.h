
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
/* $Id: config.h.win32,v 1.21 2000/11/20 17:10:24 gram Exp $ */
/* config.h.win32 Generated manually. :-) */
/* config.h.  Generated automatically by configure.  */
/* config.h.in.  Generated automatically from configure.in by autoheader.  */

/* Define if you have the ANSI C header files.  */
#define STDC_HEADERS 1

/* Define if your processor stores words with the most significant
   byte first (like Motorola and SPARC, unlike Intel and VAX).  */
/* #undef WORDS_BIGENDIAN */

/* Define if lex declares yytext as a char * by default, not a char[].  */
/* #undef YYTEXT_POINTER */

#define HAVE_PLUGINS		1
#define PLUGINS_NEED_ADDRESS_TABLE 1

/* #undef HAVE_SA_LEN */

#define DATAFILE_DIR "/usr/local/etc"

/* #undef NEED_SNPRINTF_H */

/* #undef NEED_STRERROR_H */

#define NEED_MKSTEMP 1

#define HAVE_LIBPCAP 1

/* Define if you have the gethostbyname2 function.  */
/* #undef HAVE_GETHOSTBYNAME2 */

/* Define if you have the getprotobynumber function.  */
/* #undef HAVE_GETPROTOBYNUMBER */

/* Define if you have the <arpa/inet.h> header file.  */
/* #undef HAVE_ARPA_INET_H */

/* Define if you have the <dlfcn.h> header file.  */
/* #undef HAVE_DLFCN_H */

/* Define if you have the <fcntl.h> header file.  */
#define HAVE_FCNTL_H 1

/* Define if you have the <netdb.h> header file.  */
/* #undef HAVE_NETDB_H */

/* Define if you have the <netinet/in.h> header file.  */
/* #define HAVE_NETINET_IN_H 1 */

/* Define if you have the <snmp/snmp.h> header file.  */
/* #undef HAVE_SNMP_SNMP_H */

/* Define if you have the <snmp/version.h> header file.  */
/* #undef HAVE_SNMP_VERSION_H */

/* Define if you have the <stdarg.h> header file.  */
#define HAVE_STDARG_H 1

/* Define if you have the <stddef.h> header file.  */
/* #undef HAVE_STDDEF_H */

/* Define if you have the <sys/ioctl.h> header file.  */
/* #undef HAVE_SYS_IOCTL_H */

/* Define if you have the <sys/socket.h> header file.  */
/* #undef HAVE_SYS_SOCKET_H */

/* Define if you have the <sys/sockio.h> header file.  */
/* #undef HAVE_SYS_SOCKIO_H */

/* Define if you have the <sys/stat.h> header file.  */
#define HAVE_SYS_STAT_H 1

/* Define if you have the <sys/time.h> header file.  */
/* #define HAVE_SYS_TIME_H 1 */

/* Define if you have the <sys/types.h> header file.  */
#define HAVE_SYS_TYPES_H 1

/* Define if you have the <sys/wait.h> header file.  */
/* #undef HAVE_SYS_WAIT_H */

/* Define if you have the <ucd-snmp/snmp.h> header file.  */
/* #undef HAVE_UCD_SNMP_SNMP_H */

/* Define if you have the <ucd-snmp/version.h> header file.  */
/* #undef HAVE_UCD_SNMP_VERSION_H */

/* Define if you have the <unistd.h> header file.  */
/* #define HAVE_UNISTD_H 1 */

/* Define if you have the z library (-lz).  */
/*#define HAVE_LIBZ 1*/

#ifndef WIN32
#define WIN32			1
#endif

#ifndef __CS_LINUX
#define HAVE_WINDOWS_H		1
#define HAVE_WINSOCK_H		1
#define HAVE_DIRECT_H		1
#define HAVE_IO_H		1
#define NEED_INET_ATON_H	1
#define NEED_INET_V6DEFS_H	1
#define NEED_GETOPT_H		1
#define snprintf 		_snprintf
#if _MSC_VER < 1500
#define vsnprintf 		_vsnprintf
#endif
#define strcasecmp		stricmp
#define strncasecmp		strnicmp
#define open			_open
#define close			_close
#define popen			_popen
#define pclose			_pclose
#endif

/* Needed for zlib, according to http://www.winimage.com/zLibDll/ */
/*#define ZLIB_DLL                1
#define _WINDOWS                1*/

/* Name of package */
#define PACKAGE "ethereal"

/* Version number of package */
#define VERSION "0.8.14"

/* Plugin installation directory */
#define PLUGIN_DIR "/usr/local/lib/ethereal/plugins/0.8.14"

