/********************************************************************
 *                                                                  *
 * THIS FILE IS PART OF THE OggVorbis 'TREMOR' CODEC SOURCE CODE.   *
 *                                                                  *
 * USE, DISTRIBUTION AND REPRODUCTION OF THIS LIBRARY SOURCE IS     *
 * GOVERNED BY A BSD-STYLE SOURCE LICENSE INCLUDED WITH THIS SOURCE *
 * IN 'COPYING'. PLEASE READ THESE TERMS BEFORE DISTRIBUTING.       *
 *                                                                  *
 * THE OggVorbis 'TREMOR' SOURCE CODE IS (C) COPYRIGHT 1994-2003    *
 * BY THE Xiph.Org FOUNDATION http://www.xiph.org/                  *
 *                                                                  *
 ********************************************************************

 function: stdio-based convenience library for opening/seeking/decoding

 ********************************************************************/

#ifndef _OV_FILE_H_
#define _OV_FILE_H_

#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */

#include <stdio.h>
#include "ivorbiscodec.h"

/* The function prototypes for the callbacks are basically the same as for
 * the stdio functions fread, fseek, fclose, ftell. 
 * The one difference is that the FILE * arguments have been replaced with
 * a void * - this is to be used as a pointer to whatever internal data these
 * functions might need. In the stdio case, it's just a FILE * cast to a void *
 * 
 * If you use other functions, check the docs for these functions and return
 * the right values. For seek_func(), you *MUST* return -1 if the stream is
 * unseekable
 */
typedef struct {
  size_t (*read_func)  (void *ptr, size_t size, size_t nmemb, void *datasource);
  int    (*seek_func)  (void *datasource, ogg_int64_t offset, int whence);
  int    (*close_func) (void *datasource);
  long   (*tell_func)  (void *datasource);
} ov_callbacks;

typedef struct OggVorbis_File {
  void            *datasource; /* Pointer to a FILE *, etc. */
  int              seekable;
  ogg_int64_t      offset;
  ogg_int64_t      end;
  ogg_sync_state   *oy; 

  /* If the FILE handle isn't seekable (eg, a pipe), only the current
     stream appears */
  int              links;
  ogg_int64_t     *offsets;
  ogg_int64_t     *dataoffsets;
  ogg_uint32_t    *serialnos;
  ogg_int64_t     *pcmlengths;
  vorbis_info     vi;
  vorbis_comment  vc;

  /* Decoding working state local storage */
  ogg_int64_t      pcm_offset;
  int              ready_state;
  ogg_uint32_t     current_serialno;
  int              current_link;

  ogg_int64_t      bittrack;
  ogg_int64_t      samptrack;

  ogg_stream_state *os; /* take physical pages, weld into a logical
                          stream of packets */
  vorbis_dsp_state *vd; /* central working state for the packet->PCM decoder */

  ov_callbacks callbacks;

} OggVorbis_File;

extern int ov_clear_tremolo(OggVorbis_File *vf);
extern int ov_open_tremolo(FILE *f,OggVorbis_File *vf,char *initial,long ibytes);
extern int ov_open_callbacks_tremolo(void *datasource, OggVorbis_File *vf,
		char *initial, long ibytes, ov_callbacks callbacks);

extern int ov_test_tremolo(FILE *f,OggVorbis_File *vf,char *initial,long ibytes);
extern int ov_test_callbacks_tremolo(void *datasource, OggVorbis_File *vf,
		char *initial, long ibytes, ov_callbacks callbacks);
extern int ov_test_open_tremolo(OggVorbis_File *vf);

extern long ov_bitrate_tremolo(OggVorbis_File *vf,int i);
extern long ov_bitrate_instant_tremolo(OggVorbis_File *vf);
extern long ov_streams_tremolo(OggVorbis_File *vf);
extern long ov_seekable_tremolo(OggVorbis_File *vf);
extern long ov_serialnumber_tremolo(OggVorbis_File *vf,int i);

extern ogg_int64_t ov_raw_total_tremolo(OggVorbis_File *vf,int i);
extern ogg_int64_t ov_pcm_total_tremolo(OggVorbis_File *vf,int i);
extern ogg_int64_t ov_time_total_tremolo(OggVorbis_File *vf,int i);

extern int ov_raw_seek_tremolo(OggVorbis_File *vf,ogg_int64_t pos);
extern int ov_pcm_seek_tremolo(OggVorbis_File *vf,ogg_int64_t pos);
extern int ov_pcm_seek_page_tremolo(OggVorbis_File *vf,ogg_int64_t pos);
extern int ov_time_seek_tremolo(OggVorbis_File *vf,ogg_int64_t pos);
extern int ov_time_seek_page_tremolo(OggVorbis_File *vf,ogg_int64_t pos);

extern ogg_int64_t ov_raw_tell_tremolo(OggVorbis_File *vf);
extern ogg_int64_t ov_pcm_tell_tremolo(OggVorbis_File *vf);
extern ogg_int64_t ov_time_tell_tremolo(OggVorbis_File *vf);

extern vorbis_info *ov_info_tremolo(OggVorbis_File *vf,int link);
extern vorbis_comment *ov_comment_tremolo(OggVorbis_File *vf,int link);

extern long ov_read_tremolo(OggVorbis_File *vf,void *buffer,int length,
		    int *bitstream);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif


