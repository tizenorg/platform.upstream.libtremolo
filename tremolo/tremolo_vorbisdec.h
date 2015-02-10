/*
 * libtremolo-vorbisdecode
 *
 * Copyright (c) 2000 - 2013 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Joungkook Seo <jk7704.seo@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef __OGG_VORBIS_DEC_H__
#define __OGG_VORBIS_DEC_H__

#ifdef __cplusplus
extern "C"
{
#endif // __cplusplus

//#include "ogg.h"                  //for structure of ogg_buffer, ogg_reference, ogg_packet
#include "codec_internal.h"    //for vorbis_dsp_synthesis


#define LINUX_MM_SOUND
#ifndef ONLY_C
        #include <mm_debug.h>
        #define DEBUG_MSG     debug_msg
#else
        #define DEBUG_MSG     printf
#endif

#define _DONT_USED_
//#define _OGG_DEBUG_        //for debug


#define TRUE             1
#define FALSE          0
#define ERROR        -1

/**** BUFFER ****/
//#define FILE_SIZE	(50 * 1024)      //50K - test case
#define PCM_SIZE    4096                    // MAX (1024)*(2ch)*(short) = 1024*2*2
                                                               // take 4k out of the data segment, not the stack


#define OGGSYNC		0x4F676753            /* 'OggS' */
#define VORBSYNC	0x766f7262            /* 'vorb' */
#define VORBISSYNC	0x766f72626973    /* 'vorbis' */

#define OGG_MIN_SIZE                         27
#define OGG_PAGE_HEADER_SIZE      27

#define guint8       unsigned char
#define guint         unsigned int
#define guint32     unsigned int
#ifdef LINUX_MM_SOUND
#define gint64       long long
#define guint64     long long
#else
#define gint64       __int64
#define guint64     unsigned __int64
#endif

/* Define PUT and GET functions for unaligned memory */
#define _GST_GET(__data, __idx, __size, __shift) \
        (((guint##__size) (((const guint8 *) (__data))[__idx])) << (__shift))

/* Read an 8 bit unsigned integer value from the memory buffer */
#define GST_READ_UINT8(data)        (_GST_GET (data, 0,  8,  0))

/* Read a 32 bit unsigned integer value in big endian format from the memory buffer */
#define GST_READ_UINT32_BE(data)        (_GST_GET (data, 0, 32, 24) | \
                                                                        _GST_GET (data, 1, 32, 16) | \
                                                                        _GST_GET (data, 2, 32,  8) | \
                                                                        _GST_GET (data, 3, 32,  0))

/* Read a 32 bit unsigned integer value in little endian format from the memory buffer */
#define GST_READ_UINT32_LE(data)        (_GST_GET (data, 3, 32, 24) | \
                                                                        _GST_GET (data, 2, 32, 16) | \
                                                                        _GST_GET (data, 1, 32,  8) | \
                                                                        _GST_GET (data, 0, 32,  0))

/* Read a 64 bit unsigned integer value in little endian format from the memory buffer */
#define GST_READ_UINT64_LE(data)        (_GST_GET (data, 7, 64, 56) | \
                                                                        _GST_GET (data, 6, 64, 48) | \
                                                                        _GST_GET (data, 5, 64, 40) | \
                                                                        _GST_GET (data, 4, 64, 32) | \
                                                                        _GST_GET (data, 3, 64, 24) | \
                                                                        _GST_GET (data, 2, 64, 16) | \
                                                                        _GST_GET (data, 1, 64,  8) | \
                                                                        _GST_GET (data, 0, 64,  0))


/*************************************/
/**** STRUCTURE FOR OGG API ****/
/*************************************/

typedef struct {
        //Page Header (common)
        guint Syncword;                             /* 4 :  4 */  /*'OggS'*/
        guint Stream_version;                 /* 1 :  5 */
        guint Header_type;                       /* 1 :  6 */
        guint Granule_positon;                /* 8 : 14 */
        guint Serial_number;                   /* 4 : 18 */
        guint Page_sequence_no;          /* 4 : 22 */
        guint Page_checksum;               /* 4 : 26 */
        guint Page_segment;                  /* 1 : 27 */
        unsigned char Page_table[255];   /* n : [PageSegments] */
        //Page Header (extension)
        guint Page_header_len;
        guint Page_data_len;
        guint Page_length;
        guint Frame_number;
        guint Need_nextpage;
        guint Page_lastframe;
} OGG_DEC_PAGE_HEADER;

typedef struct
{
        //Identification Header (packet type 1) 30bytes
        guint packet_type;
        guint vorbis_version;
        guint audio_channel;
        guint audio_sample_rate;
        guint bitrate_maximum;
        guint bitrate_normal;
        guint bitrate_minimum;
        guint bitrate_average;
#ifndef _DONT_USED_
        guint block_size0;
        guint block_size1;
        float spf0;               /* frame duration = sample / sf (msec/1frame) */
        float spf1;
        float fps;                 /* frame per second = sf / sample (frame/1sec) */
#endif
}OGG_DEC_PACKET1_HEADER;

typedef struct
{
        int   version;
        int   sampleRate;    /* Hz */
        int   bitRate;             /* bps */
        int   channels;         /* ch */
        int   bits;          /* always '16'*/
}OGG_DEC_PARAMETERS;

typedef struct
{
        /* Parser Info. */
        OGG_DEC_PARAMETERS              *sParm;
        OGG_DEC_PAGE_HEADER            *sPage;
        OGG_DEC_PACKET1_HEADER      *sPacket;
        /* Decoder Info.(internal) */
        vorbis_dsp_state            *mState;
        vorbis_info                      *mVi;
        /* Decoder Info.(interface) */
        ogg_buffer                      *buf;
        ogg_reference                *ref;
        oggpack_buffer              *bits;
        ogg_packet                     *pack;
        unsigned char                 *bookbuf;          /* books packet buffer[8192]*/
        unsigned char                 *framebuf;        /* valid frame buffer[2048]*/

        /* Basic info.*/
        int                                     frame_count;      /* frame count */
        /* OGG Buffer */
        int                                     filesize;                 /* total    - gint64 */
        int                                     filepos;                  /* position - gint64 */
        int                                     page_remainbyte;
        /* PCM Buffer */
        int                                     pcmsize;               /* (sample*2*ch) */
        unsigned int                     pcmsize_total;
        unsigned int                    sample_sum;        /* sample = vd->out_end */
        int                                    need_moredata;
#ifdef _USED_CASE_
        /* external input parameter */
        unsigned char                 *filebuf;                   /* file buffering */
        char                                 *outpcm;                /* pcm buffering */
#endif
}OGG_DEC_HANDLE;

int ogg_decode_create(OGG_DEC_HANDLE **handle);
int ogg_decode_reset(OGG_DEC_HANDLE *handle);
void ogg_decode_delete(OGG_DEC_HANDLE *handle);
void ogg_decode_memset(OGG_DEC_HANDLE *handle);
int ogg_decode_initial(OGG_DEC_HANDLE *handle, unsigned char *ogg_data, int *used_size);
int ogg_decode_getinfo(OGG_DEC_HANDLE *handle, unsigned char *ogg_data, int *used_size,int mInputBufferCount);
int ogg_decode_findsyncpage(OGG_DEC_HANDLE *handle, unsigned char *ogg_data);
int ogg_decode_frame(OGG_DEC_HANDLE *handle, unsigned char *ogg_data, int postion, int *used_size, char *decoded_pcm, int *decoded_len);
int ogg_parse_valid_sync (unsigned char *data, unsigned int avail, int *skipsize);
unsigned int ogg_parse_calculate_page_len (OGG_DEC_PAGE_HEADER *oggpage, guint8 * data);
unsigned int ogg_parse_check_page_header (OGG_DEC_PAGE_HEADER *oggpage, guint8 *data, guint avail, guint *framesize, int flag, int *type);
unsigned int ogg_parse_page_header (OGG_DEC_PAGE_HEADER *oggpage, guint8 *buf);
int ogg_parse_vorbis_header (OGG_DEC_PACKET1_HEADER *oggpacket, guint8 *data);
int ogg_parse_find_duration (unsigned char *data, unsigned int size);

#ifdef __cplusplus
   }
#endif // __cplusplus

#endif	//__OGG_VORBIS_DEC_H__
