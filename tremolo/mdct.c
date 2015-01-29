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

 function: normalized modified discrete cosine transform
           power of two length transform only [64 <= n ]
 last mod: $Id: mdct.c,v 1.9.6.5 2003/04/29 04:03:27 xiphmont Exp $

 Original algorithm adapted long ago from _The use of multirate filter
 banks for coding of high quality digital audio_, by T. Sporer,
 K. Brandenburg and B. Edler, collection of the European Signal
 Processing Conference (EUSIPCO), Amsterdam, June 1992, Vol.1, pp
 211-214

 The below code implements an algorithm that no longer looks much like
 that presented in the paper, but the basic structure remains if you
 dig deep enough to see it.

 This module DOES NOT INCLUDE code to generate/apply the window
 function.  Everybody has their own weird favorite including me... I
 happen to like the properties of y=sin(.5PI*sin^2(x)), but others may
 vehemently disagree.

 ********************************************************************/

#include "ivorbiscodec.h"
#include "os.h"
#include "misc.h"
#include "mdct.h"
#include "mdct_lookup.h"

#include <stdio.h>

#if defined(ONLY_C)
STIN void presymmetry_tremolo(DATA_TYPE *in,int n2,int step){
  DATA_TYPE *aX;
  DATA_TYPE *bX;
  LOOKUP_T *T;
  int n4=n2>>1;

  aX            = in+n2-3;
  T             = sincos_lookup0;

  do{
    REG_TYPE  s0= aX[0];
    REG_TYPE  s2= aX[2];
    XPROD31( s0, s2, T[0], T[1], &aX[0], &aX[2] ); T+=step;
    aX-=4;
  }while(aX>=in+n4);
  do{
    REG_TYPE  s0= aX[0];
    REG_TYPE  s2= aX[2];
    XPROD31( s0, s2, T[1], T[0], &aX[0], &aX[2] ); T-=step;
    aX-=4;
  }while(aX>=in);

  aX            = in+n2-4;
  bX            = in;
  T             = sincos_lookup0;
  do{
    REG_TYPE  ri0= aX[0];
    REG_TYPE  ri2= aX[2];
    REG_TYPE  ro0= bX[0];
    REG_TYPE  ro2= bX[2];

    XNPROD31( ro2, ro0, T[1], T[0], &aX[0], &aX[2] ); T+=step;
    XNPROD31( ri2, ri0, T[0], T[1], &bX[0], &bX[2] );

    aX-=4;
    bX+=4;
  }while(aX>=bX);
}

/* 8 point butterfly (in place) */
STIN void mdct_butterfly_8_tremolo(DATA_TYPE *x){

  REG_TYPE s0   = x[0] + x[1];
  REG_TYPE s1   = x[0] - x[1];
  REG_TYPE s2   = x[2] + x[3];
  REG_TYPE s3   = x[2] - x[3];
  REG_TYPE s4   = x[4] + x[5];
  REG_TYPE s5   = x[4] - x[5];
  REG_TYPE s6   = x[6] + x[7];
  REG_TYPE s7   = x[6] - x[7];

	   x[0] = s5   + s3;
	   x[1] = s7   - s1;
	   x[2] = s5   - s3;
	   x[3] = s7   + s1;
           x[4] = s4   - s0;
	   x[5] = s6   - s2;
           x[6] = s4   + s0;
	   x[7] = s6   + s2;
	   MB();
}

/* 16 point butterfly (in place, 4 register) */
STIN void mdct_butterfly_16_tremolo(DATA_TYPE *x){

  REG_TYPE s0, s1, s2, s3;

	   s0 = x[ 8] - x[ 9]; x[ 8] += x[ 9];
	   s1 = x[10] - x[11]; x[10] += x[11];
	   s2 = x[ 1] - x[ 0]; x[ 9]  = x[ 1] + x[0];
	   s3 = x[ 3] - x[ 2]; x[11]  = x[ 3] + x[2];
	   x[ 0] = MULT31((s0 - s1) , cPI2_8);
	   x[ 1] = MULT31((s2 + s3) , cPI2_8);
	   x[ 2] = MULT31((s0 + s1) , cPI2_8);
	   x[ 3] = MULT31((s3 - s2) , cPI2_8);
	   MB();

	   s2 = x[12] - x[13]; x[12] += x[13];
	   s3 = x[14] - x[15]; x[14] += x[15];
	   s0 = x[ 4] - x[ 5]; x[13]  = x[ 5] + x[ 4];
	   s1 = x[ 7] - x[ 6]; x[15]  = x[ 7] + x[ 6];
	   x[ 4] = s2; x[ 5] = s1;
	   x[ 6] = s3; x[ 7] = s0;
	   MB();

	   mdct_butterfly_8_tremolo(x);
	   mdct_butterfly_8_tremolo(x+8);
}

/* 32 point butterfly (in place, 4 register) */
STIN void mdct_butterfly_32_tremolo(DATA_TYPE *x){

  REG_TYPE s0, s1, s2, s3;

	   s0 = x[16] - x[17]; x[16] += x[17];
	   s1 = x[18] - x[19]; x[18] += x[19];
	   s2 = x[ 1] - x[ 0]; x[17]  = x[ 1] + x[ 0];
	   s3 = x[ 3] - x[ 2]; x[19]  = x[ 3] + x[ 2];
	   XNPROD31( s0, s1, cPI3_8, cPI1_8, &x[ 0], &x[ 2] );
	   XPROD31 ( s2, s3, cPI1_8, cPI3_8, &x[ 1], &x[ 3] );
	   MB();

	   s0 = x[20] - x[21]; x[20] += x[21];
	   s1 = x[22] - x[23]; x[22] += x[23];
	   s2 = x[ 5] - x[ 4]; x[21]  = x[ 5] + x[ 4];
	   s3 = x[ 7] - x[ 6]; x[23]  = x[ 7] + x[ 6];
	   x[ 4] = MULT31((s0 - s1) , cPI2_8);
	   x[ 5] = MULT31((s3 + s2) , cPI2_8);
	   x[ 6] = MULT31((s0 + s1) , cPI2_8);
	   x[ 7] = MULT31((s3 - s2) , cPI2_8);
	   MB();

	   s0 = x[24] - x[25]; x[24] += x[25];
	   s1 = x[26] - x[27]; x[26] += x[27];
	   s2 = x[ 9] - x[ 8]; x[25]  = x[ 9] + x[ 8];
	   s3 = x[11] - x[10]; x[27]  = x[11] + x[10];
	   XNPROD31( s0, s1, cPI1_8, cPI3_8, &x[ 8], &x[10] );
	   XPROD31 ( s2, s3, cPI3_8, cPI1_8, &x[ 9], &x[11] );
	   MB();

	   s0 = x[28] - x[29]; x[28] += x[29];
	   s1 = x[30] - x[31]; x[30] += x[31];
	   s2 = x[12] - x[13]; x[29]  = x[13] + x[12];
	   s3 = x[15] - x[14]; x[31]  = x[15] + x[14];
	   x[12] = s0; x[13] = s3;
	   x[14] = s1; x[15] = s2;
	   MB();

	   mdct_butterfly_16_tremolo(x);
	   mdct_butterfly_16_tremolo(x+16);
}

/* N/stage point generic N stage butterfly (in place, 2 register) */
STIN void mdct_butterfly_generic_tremolo(DATA_TYPE *x,int points,int step){
  LOOKUP_T   *T  = sincos_lookup0;
  DATA_TYPE *x1  = x + points - 4;
  DATA_TYPE *x2  = x + (points>>1) - 4;
  REG_TYPE   s0, s1, s2, s3;

  do{
    s0 = x1[0] - x1[1]; x1[0] += x1[1];
    s1 = x1[3] - x1[2]; x1[2] += x1[3];
    s2 = x2[1] - x2[0]; x1[1]  = x2[1] + x2[0];
    s3 = x2[3] - x2[2]; x1[3]  = x2[3] + x2[2];
    XPROD31( s1, s0, T[0], T[1], &x2[0], &x2[2] );
    XPROD31( s2, s3, T[0], T[1], &x2[1], &x2[3] ); T+=step;
    x1-=4;
    x2-=4;
  }while(T<sincos_lookup0+1024);
  x1 = x + (points>>1) + (points>>2) - 4;
  x2 = x +               (points>>2) - 4;
  T = sincos_lookup0+1024;
  do{
    s0 = x1[0] - x1[1]; x1[0] += x1[1];
    s1 = x1[2] - x1[3]; x1[2] += x1[3];
    s2 = x2[0] - x2[1]; x1[1]  = x2[1] + x2[0];
    s3 = x2[3] - x2[2]; x1[3]  = x2[3] + x2[2];
    XNPROD31( s0, s1, T[0], T[1], &x2[0], &x2[2] );
    XNPROD31( s3, s2, T[0], T[1], &x2[1], &x2[3] ); T-=step;
    x1-=4;
    x2-=4;
  }while(T>sincos_lookup0);
}

STIN void mdct_butterflies_tremolo(DATA_TYPE *x,int points,int shift){

  int stages=7-shift;
  int i,j;

  for(i=0;--stages>=0;i++){
    for(j=0;j<(1<<i);j++)
    {
        mdct_butterfly_generic_tremolo(x+(points>>i)*j,points>>i,4<<(i+shift));
    }
  }

  for(j=0;j<points;j+=32)
    mdct_butterfly_32_tremolo(x+j);
}

static unsigned char bitrev[16]={0,8,4,12,2,10,6,14,1,9,5,13,3,11,7,15};

STIN int bitrev12_tremolo(int x){
  return bitrev[x>>8]|(bitrev[(x&0x0f0)>>4]<<4)|(((int)bitrev[x&0x00f])<<8);
}

STIN void mdct_bitreverse_tremolo(DATA_TYPE *x,int n,int shift){
  int          bit   = 0;
  DATA_TYPE   *w     = x+(n>>1);

  do{
    DATA_TYPE  b     = bitrev12_tremolo(bit++);
    DATA_TYPE *xx    = x + (b>>shift);
    REG_TYPE  r;

               w    -= 2;

	       if(w>xx){

		 r      = xx[0];
		 xx[0]  = w[0];
		 w[0]   = r;

		 r      = xx[1];
		 xx[1]  = w[1];
		 w[1]   = r;
	       }
  }while(w>x);
}

STIN void mdct_step7_tremolo(DATA_TYPE *x,int n,int step){
  DATA_TYPE   *w0    = x;
  DATA_TYPE   *w1    = x+(n>>1);
  LOOKUP_T    *T = (step>=4)?(sincos_lookup0+(step>>1)):sincos_lookup1;
  LOOKUP_T    *Ttop  = T+1024;
  REG_TYPE     s0, s1, s2, s3;

  do{
	      w1    -= 2;

              s0     = w0[0]  + w1[0];
              s1     = w1[1]  - w0[1];
	      s2     = MULT32(s0, T[1]) + MULT32(s1, T[0]);
	      s3     = MULT32(s1, T[1]) - MULT32(s0, T[0]);
	      T+=step;

	      s0     = (w0[1] + w1[1])>>1;
              s1     = (w0[0] - w1[0])>>1;
	      w0[0]  = s0     + s2;
	      w0[1]  = s1     + s3;
	      w1[0]  = s0     - s2;
	      w1[1]  = s3     - s1;

	      w0    += 2;
  }while(T<Ttop);
  do{
	      w1    -= 2;

              s0     = w0[0]  + w1[0];
              s1     = w1[1]  - w0[1];
	      T-=step;
	      s2     = MULT32(s0, T[0]) + MULT32(s1, T[1]);
	      s3     = MULT32(s1, T[0]) - MULT32(s0, T[1]);

	      s0     = (w0[1] + w1[1])>>1;
              s1     = (w0[0] - w1[0])>>1;
	      w0[0]  = s0     + s2;
	      w0[1]  = s1     + s3;
	      w1[0]  = s0     - s2;
	      w1[1]  = s3     - s1;

	      w0    += 2;
  }while(w0<w1);
}
#endif

STIN void mdct_step8_tremolo(DATA_TYPE *x, int n, int step){
  LOOKUP_T *T;
  LOOKUP_T *V;
  DATA_TYPE *iX =x+(n>>1);

  switch(step) {
#if defined(ONLY_C)
  default:
    T=(step>=4)?(sincos_lookup0+(step>>1)):sincos_lookup1;
    do{
      REG_TYPE     s0  =  x[0];
      REG_TYPE     s1  = -x[1];
                   XPROD31( s0, s1, T[0], T[1], x, x+1); T+=step;
                   x  +=2;
    }while(x<iX);
    break;
#endif

  case 1:
    {
      /* linear interpolation between table values: offset=0.5, step=1 */
      REG_TYPE    t0,t1,v0,v1,s0,s1;
      T         = sincos_lookup0;
      V         = sincos_lookup1;
      t0        = (*T++)>>1;
      t1        = (*T++)>>1;
      do{
	    s0  =  x[0];
	    s1  = -x[1];
	    t0 += (v0 = (*V++)>>1);
	    t1 += (v1 = (*V++)>>1);
	    XPROD31( s0, s1, t0, t1, x, x+1 );

	    s0  =  x[2];
	    s1  = -x[3];
	    v0 += (t0 = (*T++)>>1);
	    v1 += (t1 = (*T++)>>1);
	    XPROD31( s0, s1, v0, v1, x+2, x+3 );

	    x += 4;
      }while(x<iX);
      break;
    }

  case 0:
    {
      /* linear interpolation between table values: offset=0.25, step=0.5 */
      REG_TYPE    t0,t1,v0,v1,q0,q1,s0,s1;
      T         = sincos_lookup0;
      V         = sincos_lookup1;
      t0        = *T++;
      t1        = *T++;
      do{


	v0  = *V++;
	v1  = *V++;
	t0 +=  (q0 = (v0-t0)>>2);
	t1 +=  (q1 = (v1-t1)>>2);
	s0  =  x[0];
	s1  = -x[1];
	XPROD31( s0, s1, t0, t1, x, x+1 );
	t0  = v0-q0;
	t1  = v1-q1;
	s0  =  x[2];
	s1  = -x[3];
	XPROD31( s0, s1, t0, t1, x+2, x+3 );

	t0  = *T++;
	t1  = *T++;
	v0 += (q0 = (t0-v0)>>2);
	v1 += (q1 = (t1-v1)>>2);
	s0  =  x[4];
	s1  = -x[5];
	XPROD31( s0, s1, v0, v1, x+4, x+5 );
	v0  = t0-q0;
	v1  = t1-q1;
	s0  =  x[6];
	s1  = -x[7];
	XPROD31( s0, s1, v0, v1, x+5, x+6 );

	x+=8;
      }while(x<iX);
      break;
    }
  }
}

extern int mdct_backwardARM(int n, DATA_TYPE *in);

/* partial; doesn't perform last-step deinterleave/unrolling.  That
   can be done more efficiently during pcm output */
void mdct_backward_tremolo(int n, DATA_TYPE *in){
  int step;

#if defined(ONLY_C)
  int shift;

  for (shift=4;!(n&(1<<shift));shift++);
  shift=13-shift;
  step=2<<shift;

  presymmetry_tremolo(in,n>>1,step);
  mdct_butterflies_tremolo(in,n>>1,shift);
  mdct_bitreverse_tremolo(in,n,shift);
  mdct_step7_tremolo(in,n,step);
  mdct_step8_tremolo(in,n,step>>2);
#else
  step = mdct_backwardARM(n, in);
  if (step < 1)
    mdct_step8_tremolo(in,n,step);
#endif
}

#if defined(ONLY_C)
void mdct_shift_right_tremolo(int n, DATA_TYPE *in, DATA_TYPE *right){
  int i;
  n>>=2;
  in+=1;

  for(i=0;i<n;i++)
    right[i]=in[i<<1];
}
#endif

extern ogg_int16_t *mdct_unroll_prelap_tremolo(ogg_int16_t *out,
                                       DATA_TYPE   *post,
                                       DATA_TYPE   *l,
                                       int          step);
extern ogg_int16_t *mdct_unroll_part2_tremolo(ogg_int16_t *out,
                                      DATA_TYPE   *post,
                                      DATA_TYPE   *l,
                                      DATA_TYPE   *r,
                                      int          step,
                                      LOOKUP_T    *wL,
                                      LOOKUP_T    *wR);
extern ogg_int16_t *mdct_unroll_part3_tremolo(ogg_int16_t *out,
                                      DATA_TYPE   *post,
                                      DATA_TYPE   *l,
                                      DATA_TYPE   *r,
                                      int          step,
                                      LOOKUP_T    *wL,
                                      LOOKUP_T    *wR);
extern ogg_int16_t *mdct_unroll_postlap_tremolo(ogg_int16_t *out,
                                        DATA_TYPE   *post,
                                        DATA_TYPE   *l,
                                        int          step);

void mdct_unroll_lap_tremolo(int n0,int n1,
		     int lW,int W,
		     DATA_TYPE *in,
		     DATA_TYPE *right,
		     LOOKUP_T *w0,
		     LOOKUP_T *w1,
		     ogg_int16_t *out,
		     int step,
		     int start, /* samples, this frame */
		     int end    /* samples, this frame */){

  DATA_TYPE *l=in+(W&&lW ? n1>>1 : n0>>1);
  DATA_TYPE *r=right+(lW ? n1>>2 : n0>>2);
  DATA_TYPE *post;
  LOOKUP_T *wR=(W && lW ? w1+(n1>>1) : w0+(n0>>1));
  LOOKUP_T *wL=(W && lW ? w1         : w0        );

  int preLap=(lW && !W ? (n1>>2)-(n0>>2) : 0 );
  int halfLap=(lW && W ? (n1>>2) : (n0>>2) );
  int postLap=(!lW && W ? (n1>>2)-(n0>>2) : 0 );
  int n,off;

  /* preceeding direct-copy lapping from previous frame, if any */
  if(preLap){
    n      = (end<preLap?end:preLap);
    off    = (start<preLap?start:preLap);
    post   = r-n;
    r     -= off;
    start -= off;
    end   -= n;
#if defined(ONLY_C)
    while(r>post){
      *out = CLIP_TO_15((*--r)>>9);
      out+=step;
    }
#else
    out = mdct_unroll_prelap_tremolo(out,post,r,step);
    n -= off;
    if (n < 0)
      n = 0;
    r -= n;
#endif
  }

  /* cross-lap; two halves due to wrap-around */
  n      = (end<halfLap?end:halfLap);
  off    = (start<halfLap?start:halfLap);
  post   = r-n;
  r     -= off;
  l     -= off*2;
  start -= off;
  wR    -= off;
  wL    += off;
  end   -= n;
#if defined(ONLY_C)
  while(r>post){
    l-=2;
    *out = CLIP_TO_15((MULT31(*--r,*--wR) + MULT31(*l,*wL++))>>9);
    out+=step;
  }
#else
  out = mdct_unroll_part2_tremolo(out, post, l, r, step, wL, wR);
  n -= off;
  if (n < 0)
      n = 0;
  l -= 2*n;
  r -= n;
  wR -= n;
  wL += n;
#endif

  n      = (end<halfLap?end:halfLap);
  off    = (start<halfLap?start:halfLap);
  post   = r+n;
  r     += off;
  l     += off*2;
  start -= off;
  end   -= n;
  wR    -= off;
  wL    += off;
#if defined(ONLY_C)
  while(r<post){
    *out = CLIP_TO_15((MULT31(*r++,*--wR) - MULT31(*l,*wL++))>>9);
    out+=step;
    l+=2;
  }
#else
  out = mdct_unroll_part3_tremolo(out, post, l, r, step, wL, wR);
  n -= off;
  if (n < 0)
      n = 0;
  l += 2*n;
  r += n;
  wR -= n;
  wL += n;
#endif

  /* preceeding direct-copy lapping from previous frame, if any */
  if(postLap){
    n      = (end<postLap?end:postLap);
    off    = (start<postLap?start:postLap);
    post   = l+n*2;
    l     += off*2;
#if defined(ONLY_C)
    while(l<post){
      *out = CLIP_TO_15((-*l)>>9);
      out+=step;
      l+=2;
    }
#else
    out = mdct_unroll_postlap_tremolo(out,post,l,step);
#endif
  }
}
