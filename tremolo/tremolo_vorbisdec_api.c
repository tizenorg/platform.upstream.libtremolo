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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>

#include "tremolo_vorbisdec_api.h"
#include "tremolo_vorbisdec.h"

#ifdef LINUX_MM_SOUND
	#define EXPORT_API __attribute__((__visibility__("default")))
#else
	#define EXPORT_API
#endif

/* Prinf for debug */
EXPORT_API
void OGGDEC_H_DEBUG_PRINT(unsigned char *ogg_data)
{
#ifdef _OGG_DEBUG_
	unsigned int page_header1, page_header2;
	page_header1 = GST_READ_UINT32_BE (ogg_data + 0);
	page_header2 = GST_READ_UINT32_BE (ogg_data + 4);
	DEBUG_MSG("[BUF] header=0x%08X %08X \n", page_header1, page_header2);
#endif
}

/* Pre-valid ogg check */
EXPORT_API
int OGGDEC_PreparseDecode(unsigned char *ogg_data, int ogg_size, OGG_DEC_INFO *ogginfo)
{
	unsigned int Header, Identi_sync;
	int version, flags;
	int page_segment, page_headerlen;
	int packet_type;
	int samplerate =0;
	int channels = 0;
	int bitrate = 0;
	int granule = 0;

	DEBUG_MSG("Preparse enter\n");
	Header = GST_READ_UINT32_BE (ogg_data);
	if (Header == OGGSYNC) {
		if (OGG_MIN_SIZE > ogg_size) {
			/* We have found a possible frame header candidate, but can't be sure */
			DEBUG_MSG ("NEED MORE DATA: we need %d, available %d \n", OGG_MIN_SIZE, ogg_size);
			return FALSE;
		}

		version = ogg_data[4];
		flags = ogg_data[5];
		if ((version == 0) && (flags == 2)) {
			page_segment = ogg_data[26];
			page_headerlen = OGG_PAGE_HEADER_SIZE + page_segment;
			packet_type = ogg_data[page_headerlen];
			if (packet_type == 1) {
				Identi_sync = GST_READ_UINT32_BE(ogg_data + page_headerlen + 1);
				if (Identi_sync == VORBSYNC) {
					DEBUG_MSG (">>>> Identification Header (packet type 1) 30 bytes \n");
					channels = GST_READ_UINT8(ogg_data + page_headerlen + 11);
					samplerate = GST_READ_UINT32_LE(ogg_data + page_headerlen + 12);
					bitrate     = GST_READ_UINT32_LE(ogg_data + page_headerlen + 20);
				} else {
					DEBUG_MSG ("[ERROR]...Don't find 'vorbis' header \n");
					return FALSE;
				}
			} else {
				DEBUG_MSG ("[ERROR]...Not Identification Header (packet type 1) \n");
				return FALSE;
			}
		}
	}

	if ((samplerate > 0) && (channels > 0)) {
		ogginfo->samplerate = samplerate;
		ogginfo->channels    = channels;
		ogginfo->bitrate    = bitrate;
		ogginfo->bits             = 16;

		/* duration calculation for prepare step */
		granule = ogg_parse_find_duration(ogg_data, (unsigned int)ogg_size);
		if (granule > 0) {
			ogginfo->duration = ((granule * 1000) / samplerate);
#ifdef _OGG_DEBUG_
			DEBUG_MSG("[Exact] Last Granule position (%6d) -> Convert Time (%3f) sec \n", granule, (float)ogginfo->duration / (float)1000);
#endif
		} else {
			if (bitrate != 0)
				ogginfo->duration = ((ogg_size * 8 * 1000) / bitrate);
			else
				ogginfo->duration = 0;
#ifdef _OGG_DEBUG_
			DEBUG_MSG("[Estimate] Last Granule position (%6d) -> Convert Time (%3f) sec \n", granule, (float)ogginfo->duration / (float)1000);
#endif
		}
		return TRUE;
	} else {
		return ERROR;
	}
}

EXPORT_API
int OGGDEC_CreateDecode(OGGDEC *id)
{
	OGG_DEC_HANDLE *mOGGHandle;
	int int_ret;
	DEBUG_MSG("OGGDEC_CreateDecode start\n");
#ifdef _OGG_DEBUG_
#ifdef ARM_LITTLE_ENDIAN
	DEBUG_MSG("[_ARM_ASSEM_] ARM  Mode [ARM_LITTLE_ENDIAN]\n");
#else
	DEBUG_MSG("[ONLY_C] C Mode\n");
#endif
#endif
	int_ret = ogg_decode_create(&mOGGHandle);
	if (mOGGHandle != NULL) {
		*id = (void *) mOGGHandle;
		return TRUE;
	}
	return FALSE;
}

EXPORT_API
int OGGDEC_ResetDecode(OGGDEC id)
{
	OGG_DEC_HANDLE *mOGGHandle = (OGG_DEC_HANDLE *)id;
	int rel_ret;

	DEBUG_MSG("OGGDEC_FrameDecode() used [%8d / %8d] byte.\n",mOGGHandle->filepos, mOGGHandle->filesize);
	rel_ret = ogg_decode_reset(mOGGHandle);
	if (rel_ret != 1) {
		DEBUG_MSG("Error in OGGDEC_CloseDecode() \n");
		return ERROR;
	}
	return TRUE;
}

EXPORT_API
int OGGDEC_DeleteDecode(OGGDEC id)
{
	OGG_DEC_HANDLE *mOGGHandle = (OGG_DEC_HANDLE *)id;
	ogg_decode_delete(mOGGHandle);
	return TRUE;
}

/* Valid ogg check (skip byte calculate) */
EXPORT_API
int OGGDEC_InitDecode(OGGDEC id, unsigned char *ogg_data, int ogg_size, int *skipsize)
{
	OGG_DEC_HANDLE *mOGGHandle = (OGG_DEC_HANDLE *)id;
	int int_ret = 0;

	OGGDEC_H_DEBUG_PRINT(ogg_data);

	ogg_decode_memset(mOGGHandle);
	mOGGHandle->filesize = ogg_size;
	int_ret = ogg_decode_initial(mOGGHandle, ogg_data, skipsize);
	if(int_ret == FALSE) {
		DEBUG_MSG("\n INITIAL Fail \n");
		return FALSE;
	}

	mOGGHandle->filepos += (*skipsize);
	OGGDEC_H_DEBUG_PRINT(ogg_data);

	return TRUE;
}

/* Get (header/page) information for decoding */
EXPORT_API
int OGGDEC_InfoDecode(OGGDEC id, unsigned char *ogg_data, int *used_size, OGG_DEC_INFO *ogginfo)
{
	OGG_DEC_HANDLE *mOGGHandle = (OGG_DEC_HANDLE *)id;
	OGG_DEC_PARAMETERS *pparm = mOGGHandle->sParm;
	int int_ret = 0;

	int_ret = ogg_decode_getinfo(mOGGHandle, ogg_data, used_size, 0);
	if (int_ret) {
		if ((pparm->sampleRate <= 0) || (pparm->channels <= 0)) {
			return ERROR;
		}
		ogginfo->samplerate = pparm->sampleRate;
		ogginfo->bitrate = pparm->bitRate;
		ogginfo->channels = pparm->channels;
		ogginfo->bits = 16;
	} else {
		return ERROR;
	}

	mOGGHandle->filepos += (*used_size);
	OGGDEC_H_DEBUG_PRINT(ogg_data);

	return TRUE;
}

/* Do frame decoding */
EXPORT_API
int OGGDEC_FrameDecode(OGGDEC id, unsigned char *ogg_data, int *used_size, char *decoded_pcm, int *decoded_len)
{
	OGG_DEC_HANDLE *mOGGHandle = (OGG_DEC_HANDLE *)id;
	OGG_DEC_PARAMETERS *pparm = mOGGHandle->sParm;
	OGG_DEC_PAGE_HEADER *ppage = mOGGHandle->sPage;

	/********************/
	/* CHECK Process    */
	/********************/
	if (mOGGHandle->page_remainbyte == 0) {
		int page_size = 0;
		page_size = ogg_decode_findsyncpage(mOGGHandle, ogg_data);
		if (page_size > 0) {
			if (ppage->Page_segment > 0) {
				ogg_data += ppage->Page_header_len;                                    /* for skip of header size */
				mOGGHandle->filepos += ppage->Page_header_len;
				mOGGHandle->page_remainbyte = ppage->Page_data_len;      /* only data size check */
				if (mOGGHandle->sPage->Need_nextpage) {
					int i = 1;
					int tmp_size = ppage->Page_table[0];
					ogg_data += tmp_size;
					while (tmp_size == 255) {
						tmp_size = ppage->Page_table[i];
						ogg_data += tmp_size;
						i++;
					}
				}
			}
		} else {
			return ERROR;
		}
	}

	/********************/
	/* RUN Process      */
	/********************/
	if (ppage->Frame_number != ppage->Page_segment) {
		int usedbyte = 0;
		int postion = ppage->Page_data_len;
		ppage->Frame_number = ogg_decode_frame(mOGGHandle, ogg_data, postion, &usedbyte, decoded_pcm, decoded_len);
		if ((*decoded_len)  == 0) {
			mOGGHandle->filepos += usedbyte;
			DEBUG_MSG("\nDecoded End (EOF) (total %5d frames & used byte(%5d))\n", mOGGHandle->frame_count, mOGGHandle->filepos);
			return 3;
		} else if ((*decoded_len)  > 0) {
			mOGGHandle->frame_count++;
			mOGGHandle->pcmsize = (*decoded_len) * sizeof(short) * pparm->channels;
			mOGGHandle->pcmsize_total += mOGGHandle->pcmsize;
#ifdef _OGG_DEBUG_
			DEBUG_MSG("Decoded count: %5d frames (size : %4d) used byte(%5d) \n", mOGGHandle->frame_count, mOGGHandle->pcmsize, usedbyte);
#endif
			*decoded_len = mOGGHandle->pcmsize;
			if (mOGGHandle->page_remainbyte == ppage->Page_data_len) {
				*used_size = (ppage->Page_header_len) + usedbyte;
				mOGGHandle->page_remainbyte -= usedbyte;
			} else {
				*used_size = usedbyte;
				mOGGHandle->page_remainbyte -= usedbyte;
			}

			mOGGHandle->filepos += usedbyte;
			postion -= usedbyte;
			if (mOGGHandle->filepos == mOGGHandle->filesize) {
				return 2;
			}
		} else {
			DEBUG_MSG("\n Decoded Fail \n");
			return ERROR;
		}
	}
	return TRUE;
}
