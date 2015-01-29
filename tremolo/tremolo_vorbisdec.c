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

#include "tremolo_vorbisdec.h"

#include "ivorbiscodec.h"
#include "ivorbisfile.h"

extern int _vorbis_unpack_info_tremolo(vorbis_info *vi,oggpack_buffer *opb);
extern int _vorbis_unpack_books_tremolo(vorbis_info *vi,oggpack_buffer *opb);
extern int vorbis_dsp_init_tremolo(vorbis_dsp_state *v,vorbis_info *vi);
extern void vorbis_dsp_clear_tremolo(vorbis_dsp_state *v);

int ogg_decode_create(OGG_DEC_HANDLE **handle)
{
	OGG_DEC_HANDLE *pHandle = 0;

	pHandle = (OGG_DEC_HANDLE*)malloc(sizeof(OGG_DEC_HANDLE));
	memset(pHandle, 0, sizeof(OGG_DEC_HANDLE));

	pHandle->sParm = (OGG_DEC_PARAMETERS *)malloc(sizeof(OGG_DEC_PARAMETERS));
	memset(pHandle->sParm,0, sizeof(OGG_DEC_PARAMETERS));

	pHandle->sPage = (OGG_DEC_PAGE_HEADER *)malloc(sizeof(OGG_DEC_PAGE_HEADER));
	memset(pHandle->sPage,0, sizeof(OGG_DEC_PAGE_HEADER));

	pHandle->sPacket = (OGG_DEC_PACKET1_HEADER *)malloc(sizeof(OGG_DEC_PACKET1_HEADER));
	memset(pHandle->sPacket,0, sizeof(OGG_DEC_PACKET1_HEADER));

	pHandle->buf = (ogg_buffer *)malloc(sizeof(ogg_buffer));
	memset(pHandle->buf,0, sizeof(ogg_buffer));

	pHandle->ref = (ogg_reference *)malloc(sizeof(ogg_reference));
	memset(pHandle->ref,0, sizeof(ogg_reference));

	pHandle->bits = (oggpack_buffer *)malloc(sizeof(oggpack_buffer));
	memset(pHandle->bits,0, sizeof(oggpack_buffer));

	pHandle->pack = (ogg_packet *)malloc(sizeof(ogg_packet));
	memset(pHandle->pack,0, sizeof(ogg_packet));

	pHandle->bookbuf = (unsigned char*)malloc(8192 * sizeof(unsigned char));
	memset(pHandle->bookbuf,0, 8192 * sizeof(unsigned char));

	pHandle->framebuf = (unsigned char*)malloc(2048 * sizeof(unsigned char));
	memset(pHandle->framebuf,0, 2048 * sizeof(unsigned char));

	pHandle->mState = NULL;
	pHandle->mVi = NULL;

	*handle = pHandle;
	return TRUE;
}

void ogg_decode_delete(OGG_DEC_HANDLE *handle)
{
	if(handle) {
		if(handle->sPacket) {
			free(handle->sPacket);
			handle->sPacket = NULL;
		}

		if(handle->sPage) {
			free(handle->sPage);
			handle->sPage = NULL;
		}

		if(handle->sParm) {
			free(handle->sParm);
			handle->sParm = NULL;
		}

		if(handle->buf) {
			free(handle->buf);
			handle->buf = NULL;
		}

		if(handle->ref) {
			free(handle->ref);
			handle->ref = NULL;
		}

		if(handle->bits) {
			free(handle->bits);
			handle->bits = NULL;
		}

		if(handle->pack) {
			free(handle->pack);
			handle->pack = NULL;
		}

		if(handle->bookbuf) {
			free(handle->bookbuf);
			handle->bookbuf = NULL;
		}

		if(handle->framebuf) {
			free(handle->framebuf);
			handle->framebuf = NULL;
		}
		free(handle);
		handle = NULL;
	}
}

int ogg_decode_reset(OGG_DEC_HANDLE *handle)
{
	int ret = TRUE;

	/* OGG Decoder (internal memory) Reset */
	if(handle) {
		if (handle->mState != NULL) {
			vorbis_dsp_clear_tremolo(handle->mState);
			free(handle->mState);
			handle->mState = NULL;
		} else {
			DEBUG_MSG("[WARN] mState is NULL");
		}

		if (handle->mVi != NULL) {
			vorbis_info_clear_tremolo(handle->mVi);
			free(handle->mVi);
			handle->mVi = NULL;
		} else {
			DEBUG_MSG("[WARN] mVi is NULL");
		}

	}else {
		ret = FALSE;
	}
	return ret;
}

void ogg_decode_memset(OGG_DEC_HANDLE *handle)
{
	memset(handle->sParm, 0, sizeof(OGG_DEC_PARAMETERS));
	memset(handle->sPage, 0, sizeof(OGG_DEC_PAGE_HEADER));
	memset(handle->sPacket, 0, sizeof(OGG_DEC_PACKET1_HEADER));
	memset(handle->buf, 0, sizeof(ogg_buffer));
	memset(handle->ref, 0, sizeof(ogg_reference));
	memset(handle->bits, 0, sizeof(oggpack_buffer));
	memset(handle->pack, 0, sizeof(ogg_packet));
	memset(handle->bookbuf, 0, (8192 * sizeof(unsigned char)));
	memset(handle->framebuf, 0, (2048 * sizeof(unsigned char)));

	handle->frame_count = 0;
	handle->filesize = 0;
	handle->filepos = 0;
	handle->page_remainbyte = 0;
	handle->pcmsize = 0;
	handle->pcmsize_total = 0;
	handle->sample_sum = 0;
	handle->need_moredata = 0;
}

int ogg_decode_initial(OGG_DEC_HANDLE *handle, unsigned char *ogg_data, int *used_size)
{
	int ret = 0;
	int offset = 0;
	gint64 in_szie = handle->filesize;

	/* OGG Decoder (internal memory) Initialization */
	handle->mState = (vorbis_dsp_state *)malloc(sizeof(vorbis_dsp_state));
	memset(handle->mState,0, sizeof(vorbis_dsp_state));

	handle->mVi = (vorbis_info *)malloc(sizeof(vorbis_info));
	memset(handle->mVi,0, sizeof(vorbis_info));

	ret = ogg_parse_valid_sync (ogg_data, (unsigned int) in_szie, &offset);
	if (ret) {
		*used_size = 0;           /* sync found at (buf+0) size */
		DEBUG_MSG("[SUCCESS] Detect OGG Header 'OggS' at first bitstream\n");
		return TRUE;
	} else {
		*used_size = offset;     /* sync found at (buf+offset) size */
		DEBUG_MSG("[WARN] Detect OGG Header Type 'OggS' at %d bytes\n", offset);
		return FALSE;
	}
}

void ogg_decode_bitreader(OGG_DEC_HANDLE *handle, const void *data, size_t size)
{
	ogg_buffer *buf = handle->buf;
	ogg_reference *ref = handle->ref;
	oggpack_buffer *bits = handle->bits;

	buf->data = (unsigned char *)data;
	buf->size = size;
	buf->refcount = 1;
	buf->ptr.owner = NULL;

	ref->buffer = buf;
	ref->begin = 0;
	ref->length = size;
	ref->next = NULL;

	oggpack_readinit_tremolo(bits, ref);     //only teremolo
}

int ogg_decode_getinfo(OGG_DEC_HANDLE *handle, unsigned char *ogg_data, int *used_size,int mInputBufferCount)
{
	int noffset = handle->filesize;
	OGG_DEC_PACKET1_HEADER *ppacket = handle->sPacket;
	OGG_DEC_PAGE_HEADER *ppage = handle->sPage;

	vorbis_dsp_state *mState = handle->mState;
	vorbis_info *mVi = handle->mVi;
	oggpack_buffer *bits = handle->bits;

	int ret = 0;
	const unsigned char *data;
	int size;
	unsigned int frame_size = 0;
	int page_type = 0;

	/* (Page[0] - packet type #1) */
	ret = ogg_parse_check_page_header (ppage, ogg_data, noffset, &frame_size, 0, &page_type);
	if (ret) {
#ifdef _OGG_DEBUG_
		DEBUG_MSG(">>>> Confirm [OGG] Header Type \n");
#endif
		ret = ogg_parse_vorbis_header (ppacket, ogg_data);
#ifndef _DONT_USED_
		ppacket->spf0 = ((float)ppacket->block_size0/(2*ppacket->audio_channel)) / ppacket->audio_sample_rate;
		ppacket->spf1 = ((float)ppacket->block_size1/(2*ppacket->audio_channel)) / ppacket->audio_sample_rate;
#endif

		handle->sParm->channels = ppacket->audio_channel;
		handle->sParm->bitRate  = ppacket->bitrate_normal;
		handle->sParm->sampleRate = ppacket->audio_sample_rate;
		handle->sParm->version = ppacket->vorbis_version;
#ifdef _OGG_DEBUG_
		DEBUG_MSG("-------------------------------------------- \n");
		DEBUG_MSG("[DUMMY DATA FOUND] SYNC BUFFER OFFSET IS %d BYTE\n", 0);
		DEBUG_MSG("-------------------------------------------- \n");
		DEBUG_MSG ("[PARSE INFO] PACKET TYPE.......%6d \n", ppacket->packet_type);
		DEBUG_MSG ("[PARSE INFO] VORBIS VERSION....%6d \n", ppacket->vorbis_version);
		DEBUG_MSG ("[PARSE INFO] CHANNELS..........%6d channel\n", ppacket->audio_channel);
		DEBUG_MSG ("[PARSE INFO] SAMPLE RATE.......%6d hz\n", ppacket->audio_sample_rate);
		DEBUG_MSG ("[PARSE INFO] (MAX) BIT RATE....%6d bps\n", ppacket->bitrate_maximum);
		DEBUG_MSG ("[PARSE INFO] (MIN) BIT RATE....%6d bps\n", ppacket->bitrate_minimum);
		DEBUG_MSG ("[PARSE INFO] (NOR) BIT RATE....%6d bps\n", ppacket->bitrate_normal);
#ifndef _DONT_USED_
		DEBUG_MSG ("[PARSE INFO] (AVG) BIT RATE....%6d bps\n", ppacket->bitrate_average);
		DEBUG_MSG ("[PARSE INFO] SAMPLE SIZE1......%6d sample\n", ppacket->block_size0/(2*ppacket->audio_channel));
		DEBUG_MSG ("[PARSE INFO] SAMPLE SIZE2......%6d sample\n", ppacket->block_size1/(2*ppacket->audio_channel));
#endif
		DEBUG_MSG ("-------------------------------------------------\n");
#endif
		data = ogg_data + OGG_PAGE_HEADER_SIZE + ppage->Page_segment;
		size = ppage->Page_data_len;
		ogg_decode_bitreader(handle, (const unsigned char *)data + 7, size - 7);
		vorbis_info_init_tremolo(mVi);
		ret = _vorbis_unpack_info_tremolo(mVi, bits);
		if (ret < 0) {
			DEBUG_MSG ("[ERROR] _vorbis_unpack_info_tremolo() return error (%d)\n", ret);
			return FALSE;          //NOT VALID INFO ERROR
		}
		*used_size = OGG_PAGE_HEADER_SIZE + ppage->Page_segment + ppage->Page_data_len;
		ogg_data += OGG_PAGE_HEADER_SIZE + ppage->Page_segment + ppage->Page_data_len;
	} else {
		DEBUG_MSG ("[WARN]..........buffer didn't contain valid frame \n");
		DEBUG_MSG ("[WARN]..........Try Again find out valid frame \n");
		if (frame_size >= (unsigned int)noffset) {
			DEBUG_MSG ("[ERROR].........SKIP size is bigger than MAX_PULL_RANGE_BUF \n");
			return FALSE;        //NOT VALID FRAME ERROR
		}
	}

	/* (Page[1] - packet type #3(skip) and packet type #5) */
	frame_size = 0;
	ret = ogg_parse_check_page_header (ppage, ogg_data, noffset, &frame_size, 1, &page_type);
	if (ret) {
        int i = 0;
        int skip_segment = 0;
#ifdef _OGG_DEBUG_
		DEBUG_MSG(">>>> Confirm packet type #3(skip) \n");
#endif
		/* ppage->Page_table[0] is "packet type #3"'s byte*/
        do {
            skip_segment += ppage->Page_table[i];
            i++;
        } while (ppage->Page_table[i-1] == 255);
        data = ogg_data + OGG_PAGE_HEADER_SIZE + ppage->Page_segment + skip_segment;
        size = ppage->Page_data_len - skip_segment;

		if(page_type == 1) {
#ifdef _OGG_DEBUG_
			DEBUG_MSG("page_type : continued page type (01) \n");
#endif
			memcpy(handle->bookbuf, data, size);
			*used_size += OGG_PAGE_HEADER_SIZE + ppage->Page_segment + ppage->Page_data_len;
			ogg_data += OGG_PAGE_HEADER_SIZE + ppage->Page_segment + ppage->Page_data_len;
			ret = ogg_parse_check_page_header (ppage, ogg_data, noffset, &frame_size, 0, &page_type);
			data = ogg_data + OGG_PAGE_HEADER_SIZE + ppage->Page_segment;
			memcpy(handle->bookbuf + size, data, ppage->Page_data_len);
			ogg_decode_bitreader(handle, (const unsigned char *)handle->bookbuf + 7, (size + ppage->Page_data_len) - 7);
		} else {
			ogg_decode_bitreader(handle, (const unsigned char *)data + 7, size - 7);
		}

		ret = _vorbis_unpack_books_tremolo(mVi, bits);
		ret = vorbis_dsp_init_tremolo(mState, mVi);                 //vorbis_dsp_create()
		if (ret < 0) {
			DEBUG_MSG ("[ERROR] vorbis_dsp_init_tremolo() return error (%d)\n", ret);
			return FALSE;
		}
		if (ppage->Granule_positon != 0) {
			int tmp_size = ppage->Page_table[0];
			ppage->Frame_number++;
			while (ppage->Page_table[ppage->Frame_number] == 255) {
				tmp_size += ppage->Page_table[ppage->Frame_number];
				ppage->Frame_number++;
			}
			tmp_size += ppage->Page_table[ppage->Frame_number];
			ppage->Frame_number++;
			*used_size += OGG_PAGE_HEADER_SIZE + ppage->Page_segment + tmp_size;
			ogg_data += OGG_PAGE_HEADER_SIZE + ppage->Page_segment + tmp_size;
			handle->page_remainbyte = ppage->Page_data_len - tmp_size;
		} else {
			*used_size += OGG_PAGE_HEADER_SIZE + ppage->Page_segment + ppage->Page_data_len;
			ogg_data += OGG_PAGE_HEADER_SIZE + ppage->Page_segment + ppage->Page_data_len;
		}
	}

	return TRUE;
}

int ogg_decode_findsyncpage(OGG_DEC_HANDLE *handle, unsigned char *ogg_data)
{
	OGG_DEC_PAGE_HEADER *ppage = handle->sPage;
	int noffset = handle->filesize;
	unsigned int page_size = 0;
	int ret;
	int page_type = 0;

	ret = ogg_parse_check_page_header (ppage, ogg_data, noffset, &page_size, 0, &page_type);
	if (ret == TRUE && page_size > 0) {
		return (int) page_size;
	} else {
		return 0;
	}
}

int ogg_decode_frame(OGG_DEC_HANDLE *handle, unsigned char *ogg_data, int postion, int *used_size, char *decoded_pcm, int *decoded_len)
{
	OGG_DEC_PAGE_HEADER *ppage = handle->sPage;
	vorbis_dsp_state *mState = handle->mState;
	ogg_buffer *buf = handle->buf;
	ogg_reference *ref = handle->ref;
	ogg_packet *pack = handle->pack;

	int numFrames = 0;
	int err;
	guint ff_size = 0;

	if (ppage->Page_segment == (ppage->Frame_number + 2)) {
		if (ppage->Page_table[ppage->Frame_number + 1] == 0xff) {
			if (ppage->Page_table[ppage->Frame_number] == 0xff)
				ff_size = 255;
		} else {
			ff_size = 0;
		}
	}

	if ((ppage->Page_segment == (ppage->Frame_number + 1)) || (ff_size == 255)) {
		if (ppage->Page_table[ppage->Frame_number] == 0xff) {
			unsigned char *next_data;
			guint next_sync, next_type, next_segment, next_granule;
			guint next_header_len, curr_pagesize, next_pagesize;
			int i;

			ff_size += 255;
			next_data = ogg_data + ff_size;
			next_sync = GST_READ_UINT32_BE (next_data);
			if (next_sync != OGGSYNC) {
				DEBUG_MSG("\n next sync not found\n");
				return -1;           /* Sync not found */
			}
			next_type = next_data[5];
			if ((next_type == 0x01) || (next_type == 0x04) || (next_type == 0x05)) {
				handle->need_moredata = 1;
				next_segment = next_data[26];
				if (next_segment == 1) {
					next_granule = GST_READ_UINT64_LE (&next_data[6]);
					handle->sPage->Granule_positon = next_granule;
					handle->sPage->Page_lastframe = 1;
				}
				next_header_len = OGG_PAGE_HEADER_SIZE + next_segment;
				i = 0;
				next_pagesize = 0;
				do {
					curr_pagesize = next_data[OGG_PAGE_HEADER_SIZE + i];
					next_pagesize += curr_pagesize;
					i++;
				} while (curr_pagesize == 255);
				next_data += next_header_len;
				memset(handle->framebuf, 0, (2048 * sizeof(unsigned char)));
				memcpy(handle->framebuf, ogg_data, ff_size);
				memcpy(handle->framebuf + ff_size, next_data, next_pagesize);
			}
		}
	}

	if (handle->need_moredata) {
		buf->data = handle->framebuf;
		handle->need_moredata = 0;
	} else {
		buf->data = ogg_data;
	}

	buf->size = postion;
	buf->refcount = 1;
	buf->ptr.owner = NULL;

	ref->buffer = buf;
	ref->begin = 0;
	ref->length = buf->size;
	ref->next = NULL;

	pack->packet = ref;
	pack->bytes = ref->length;
	pack->b_o_s = 0;
	pack->e_o_s = 0;
	pack->granulepos = 0;
	pack->packetno = 0;

	while (1) {
		err = vorbis_dsp_synthesis(mState, pack, 1);
		if (err != 0) {
			DEBUG_MSG("\n 1st vorbis_dsp_synthesis returned %d\n", err);
			*decoded_len = -1;
			*used_size += ppage->Page_table[ppage->Frame_number];
			buf->data += ppage->Page_table[ppage->Frame_number];
			ppage->Frame_number++;
			err = vorbis_dsp_synthesis(mState, pack, 1);
			if (err != 0) {
				DEBUG_MSG("\n 2nd vorbis_dsp_synthesis returned %d\n", err);
			return -1;
			}
		}

		handle->sample_sum += mState->out_end;
		if ((ppage->Header_type == 0x04) || (ppage->Header_type == 0x05) || ppage->Page_lastframe) {
			if (handle->sample_sum > ppage->Granule_positon) {
				int extra= handle->sample_sum - ppage->Granule_positon;
				if (mState->out_end > extra) {
					mState->out_end -= extra;
					handle->sample_sum -= extra;
				} else {
					while (ppage->Page_segment > ppage->Frame_number) {
						*used_size += ppage->Page_table[ppage->Frame_number];
						ppage->Frame_number++;
					};
					*decoded_len = 0;
					return 0;
				}
			}
		}

		numFrames = vorbis_dsp_pcmout(mState, (short *)decoded_pcm, 4096);
		if (numFrames < 0) {
			DEBUG_MSG("vorbis_dsp_pcmout returned minus value (%d)\n", numFrames);
			numFrames = 0;
		} else if (numFrames == 0) {
			*used_size += ppage->Page_table[ppage->Frame_number];
			buf->data += ppage->Page_table[ppage->Frame_number];
			ppage->Frame_number++;
		} else {
			if (ppage->Need_nextpage) {
				/* For skip used byte in previous continue frame */
				while (ppage->Page_table[ppage->Frame_number] == 255) {
					*used_size += ppage->Page_table[ppage->Frame_number];
					ppage->Frame_number++;
				}
				*used_size += ppage->Page_table[ppage->Frame_number];
				ppage->Frame_number++;
				ppage->Need_nextpage = 0;
			}

			while (1) {
				if (ppage->Page_segment > (ppage->Frame_number + 1)) {
					if (ppage->Page_table[ppage->Frame_number] == 0xff) {
						*used_size += ppage->Page_table[ppage->Frame_number];
						ppage->Frame_number++;
					} else {
						break;
					}
				} else {
					break;
				}
			}

			*used_size += ppage->Page_table[ppage->Frame_number];
			*decoded_len = numFrames;
			ppage->Frame_number++;
			if (ppage->Page_segment == ppage->Frame_number) {
				if (ppage->Page_table[ppage->Page_segment - 1] == 0xff) {
					ppage->Need_nextpage = 1;
				}
			}

			return ppage->Frame_number;
		}
	}
}

//**************************************************
// Function   : Check SYNC Probability
//**************************************************
int ogg_parse_valid_sync (unsigned char *data, unsigned int avail, int *skipsize)
{
	int found = FALSE;
	guint i = 0;

	/* Can we even parse the header? */
	if (avail < OGG_MIN_SIZE)
		return FALSE;

	for (i = 0; i < avail - 4; i++) {
		if ((data[i+0] == 0x4F) &&          /* 'O' */
			(data[i+1] == 0x67) &&      /* 'g' */
			(data[i+2] == 0x67) &&      /* 'g' */
			(data[i+3] == 0x53)) {        /* 'S' */
			found = TRUE;
			break;
		}
	}

	if (i) {
		*skipsize = i;
		return FALSE;
	} else {
		*skipsize = 0;
		return TRUE;
	}
}

//**************************************************
// Function   : This function calculates page length from the given header.
//**************************************************
unsigned int ogg_parse_calculate_page_len (OGG_DEC_PAGE_HEADER *ppage, guint8 * data)
{
	guint i;

	ppage->Header_type = data[5];
	ppage->Granule_positon	= GST_READ_UINT64_LE (&data[6]);
	ppage->Page_segment = data[26];
	ppage->Page_header_len = OGG_PAGE_HEADER_SIZE + ppage->Page_segment;

	ppage->Page_data_len = 0;
	for (i = 0; i < ppage->Page_segment; i++) {
		ppage->Page_table[i] = data[OGG_PAGE_HEADER_SIZE + i];
		ppage->Page_data_len +=  ppage->Page_table[i];
	}
	ppage->Page_length = ppage->Page_header_len + ppage->Page_data_len;
	ppage->Frame_number = 0;
	return ppage->Page_length;
}

//**************************************************
// Function   : TRUE if the given data contains a valid OGG page header.
//**************************************************
unsigned int ogg_parse_check_page_header (OGG_DEC_PAGE_HEADER *ppage, guint8 *data, guint avail, guint *framesize, int flag, int *type)
{
	unsigned int Header;
	int Version, Flags;

	Version = data[4];
	Flags = data[5];
	if ((Version == 0) && (Flags < 8)) {
		*framesize = ogg_parse_calculate_page_len (ppage, data);

		if (*framesize + OGG_MIN_SIZE > avail) {
			/* We have found a possible frame header candidate, but can't be sure since
				we don't have enough data to check the next frame */
			DEBUG_MSG ("NEED MORE DATA: we need %d, available %d \n", *framesize + OGG_MIN_SIZE, avail);
			return FALSE;
		}

		if (flag) {
			Header = GST_READ_UINT32_BE (data + (*framesize));
			if (Header == OGGSYNC) {
				Flags = (data + (*framesize))[5];
				if (Flags == 1) {
					*type = 1;
				} else {
					*type = 0;
				}
#ifdef _OGG_DEBUG_
				guint nextlen = ogg_parse_calculate_page_len (ppage, data + (*framesize));
				DEBUG_MSG (">>>> OGG Page Header found, 1st len: %d bytes, 2nd len: %d bytes \n", *framesize, nextlen);
#endif
				return TRUE;
			} else {
				return FALSE;        /* 2nd Sync not found */
			}
		}
		return TRUE;
	}
	return FALSE;
}



//**************************************************
// Function   : Simple Page Header Parse
//**************************************************
unsigned int ogg_parse_page_header (OGG_DEC_PAGE_HEADER *ppage, guint8 *buf)
{
	unsigned char *page_header = buf;        //header[27];
	unsigned int length = 0;

	/* The caller has ensured we have a valid header, so bitrate can't be zero here. */
	ppage->Syncword = GST_READ_UINT32_BE (page_header);
	if (ppage->Syncword != OGGSYNC) {
		return -1;        /* Sync not found */
	}

	ppage->Stream_version = page_header[4];        /* Always '0' */
	if (ppage->Stream_version != 0) {
		return -2;        /* Wrong version  */
	}

	ppage->Header_type = page_header[5];            /* 2 : BOS, 4 : EOS*/
	if (ppage->Header_type & ~7) {
		return -3;        /* Only bits 0-2 are defined in version 0. */
	}

	ppage->Granule_positon       = GST_READ_UINT64_LE (&page_header[6]);
	ppage->Serial_number          = GST_READ_UINT32_LE (&page_header[14]);
	ppage->Page_sequence_no = GST_READ_UINT32_LE (&page_header[18]);
	ppage->Page_checksum       = GST_READ_UINT32_LE (&page_header[22]);

	length = ogg_parse_calculate_page_len(ppage, buf);

	if (ppage->Page_sequence_no > 1 && length > 0)
		ppage->Frame_number += ppage->Page_segment;

	return TRUE;
}


//**************************************************
// Function   : vorbis header parse (Identification Header (packet type 1)).
//**************************************************
int ogg_parse_vorbis_header (OGG_DEC_PACKET1_HEADER *oggpacket, guint8 *data)
{
	int page_segment;
	int header_len = 0;
	int identi_sync;

	page_segment = data[26];
	header_len = OGG_PAGE_HEADER_SIZE + page_segment;
	oggpacket->packet_type = data[header_len];
	if (oggpacket->packet_type == 1) {
		identi_sync = GST_READ_UINT32_BE(data + header_len + 1);
		if (identi_sync == VORBSYNC) {
#ifdef _OGG_DEBUG_
			DEBUG_MSG (">>>> Identification Header (packet type 1) 30 bytes \n");
#endif
			oggpacket->vorbis_version        = GST_READ_UINT32_LE (data + header_len + 7);
			oggpacket->audio_channel        = GST_READ_UINT8(data + header_len + 11);
			oggpacket->audio_sample_rate = GST_READ_UINT32_LE(data + header_len + 12);
			oggpacket->bitrate_maximum     = GST_READ_UINT32_LE(data + header_len + 16);
			oggpacket->bitrate_normal         = GST_READ_UINT32_LE(data + header_len + 20);
			oggpacket->bitrate_minimum       = GST_READ_UINT32_LE(data + header_len + 24);
			oggpacket->bitrate_average       = (oggpacket->bitrate_maximum + oggpacket->bitrate_minimum) / 2;
#ifndef _DONT_USED_
			oggpacket->block_size0             = (int) pow(2, (data[header_len + 28] & 0x0f));
			oggpacket->block_size1             = (int) pow(2, (data[header_len + 28] & 0xf0) >> 4);
#endif
		} else {
			DEBUG_MSG ("[ERROR]...Don't find 'vorbis' header \n");
			return FALSE;
		}
	} else {
		DEBUG_MSG ("[ERROR]...Not Identification Header (packet type 1) \n");
		return FALSE;
	}

	return TRUE;
}

//**************************************************
// Function   : Preparsing for extact duration
//**************************************************
int ogg_parse_find_duration (unsigned char *data, unsigned int size)
{
	unsigned char *buf = data;
	guint syncword = 0;
	guint i = 0;
	guint skipsize = 0;
	guint header_type = 0;
	guint granule_positon = 0;
	guint page_segment = 0;
	guint segment_len = 0;
	guint page_datalen = 0;

	/* Only find 1st 'OggS' sync offset */
	for (i = 0; i < size - 4; i++) {
		if ((buf[i+0] == 0x4F) &&           /* 'O' */
			(buf[i+1] == 0x67) &&       /* 'g' */
			(buf[i+2] == 0x67) &&       /* 'g' */
			(buf[i+3] == 0x53)) {         /* 'S' */
			skipsize = i;
			break;
		} else {
			if (i == (size - 4)) {
				return -2;               /* Sync not found */
			}
		}
	}
	buf += skipsize;

	do {
		syncword = GST_READ_UINT32_BE (buf);
		if (syncword != OGGSYNC) {
			return -2;
		}

		header_type = buf[5];             /* 0,2 : BOS, 4,5 : EOS*/
		if (header_type & ~7) {
			return -3;
		}

		if ((header_type == 0x04) || (header_type == 0x05)) {
			granule_positon = GST_READ_UINT64_LE (&buf[6]);
#ifdef _OGG_DEBUG_
			DEBUG_MSG ("[Find] last granule position (%d) for duration!\n", granule_positon);
#endif
			break;
		}
		page_segment = buf[26];

		for (i = 0; i < page_segment; i++) {
			page_datalen += buf[OGG_PAGE_HEADER_SIZE + i];
		}
		skipsize = (OGG_PAGE_HEADER_SIZE + page_segment + page_datalen);
		buf += skipsize;
		skipsize = 0;
		page_datalen = 0;
	} while (1);

	return granule_positon;
}
