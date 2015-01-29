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

#ifndef __OGG_DECODER_API__
#define __OGG_DECODER_API__

#ifdef __cplusplus
extern "C" 
{
#endif // __cplusplus

/*! tremolo_OGG instance identifier for decoder */
typedef void *OGGDEC;

#define OGGDEC_FAIL                  (  0)
#define OGGDEC_SUCCESS         (  1)
#define OGGDEC_ERROR              (-1)

typedef struct 
{
        int samplerate;      /* Hz */
        int bitrate;               /* bps */
        int channels;          /* ch */
        int bits;                    /* always '16'*/
        int duration;           /* duration (msec)*/
}OGG_DEC_INFO;


//#############################################
int OGGDEC_CreateDecode(OGGDEC *id);
int OGGDEC_ResetDecode(OGGDEC id);
int OGGDEC_DeleteDecode(OGGDEC id);

int OGGDEC_PreparseDecode(unsigned char *ogg_data, int ogg_size, OGG_DEC_INFO *ogginfo);
int OGGDEC_InitDecode(OGGDEC id, unsigned char *ogg_data, int ogg_size, int *skipsize);
int OGGDEC_InfoDecode(OGGDEC id, unsigned char *ogg_data, int *usedsize, OGG_DEC_INFO *ogginfo);
int OGGDEC_FrameDecode(OGGDEC id, unsigned char *ogg_data, int *used_size, char *decoded_pcm, int *decoded_len);
//#############################################


#ifdef __cplusplus
   }
#endif // __cplusplus

#endif	//__OGG_DECODER_API__
