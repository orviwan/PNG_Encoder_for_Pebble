/*
Derived from LodePNG version 20140823
------------------------------------------------------------------------------------------

Copyright (c) 2005-2014 Lode Vandevenne

------------------------------------------------------------------------------------------
Stripped back to include only encoding functionality for Pebble - 2014-10-18 - Jon Barlow
------------------------------------------------------------------------------------------

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

    1. The origin of this software must not be misrepresented; you must not
    claim that you wrote the original software. If you use this software
    in a product, an acknowledgment in the product documentation would be
    appreciated but is not required.

    2. Altered source versions must be plainly marked as such, and must not be
    misrepresented as being the original software.

    3. This notice may not be removed or altered from any source
    distribution.
*/
#include <string.h> 

typedef enum LodePNGColorType
{
  LCT_GREY = 0, 
  LCT_RGB = 2, 
  LCT_PALETTE = 3, 
  LCT_GREY_ALPHA = 4, 
  LCT_RGBA = 6 
} LodePNGColorType;

unsigned lodepng_encode_memory(unsigned char** out, size_t* outsize,
                               const unsigned char* image, unsigned w, unsigned h,
                               LodePNGColorType colortype, unsigned bitdepth);

unsigned lodepng_encode32(unsigned char** out, size_t* outsize,
                          const unsigned char* image, unsigned w, unsigned h);


unsigned lodepng_encode24(unsigned char** out, size_t* outsize,
                          const unsigned char* image, unsigned w, unsigned h);

typedef struct LodePNGCompressSettings LodePNGCompressSettings;
struct LodePNGCompressSettings 
{
  unsigned btype; 
  unsigned use_lz77; 
  unsigned windowsize; 
  unsigned minmatch; 
  unsigned nicematch; 
  unsigned lazymatching; 
  unsigned (*custom_zlib)(unsigned char**, size_t*,
                          const unsigned char*, size_t,
                          const LodePNGCompressSettings*);
  unsigned (*custom_deflate)(unsigned char**, size_t*,
                             const unsigned char*, size_t,
                             const LodePNGCompressSettings*);
  const void* custom_context; 
};

extern const LodePNGCompressSettings lodepng_default_compress_settings;
void lodepng_compress_settings_init(LodePNGCompressSettings* settings);

typedef struct LodePNGColorMode
{
  LodePNGColorType colortype; 
  unsigned bitdepth;
  unsigned char* palette; 
  size_t palettesize; 
  unsigned key_defined; 
  unsigned key_r;       
  unsigned key_g;       
  unsigned key_b;       
} LodePNGColorMode;

void lodepng_color_mode_init(LodePNGColorMode* info);
void lodepng_color_mode_cleanup(LodePNGColorMode* info);

unsigned lodepng_color_mode_copy(LodePNGColorMode* dest, const LodePNGColorMode* source);

void lodepng_palette_clear(LodePNGColorMode* info);

unsigned lodepng_palette_add(LodePNGColorMode* info,
                             unsigned char r, unsigned char g, unsigned char b, unsigned char a);

unsigned lodepng_get_bpp(const LodePNGColorMode* info);

unsigned lodepng_get_channels(const LodePNGColorMode* info);

unsigned lodepng_is_greyscale_type(const LodePNGColorMode* info);

unsigned lodepng_is_alpha_type(const LodePNGColorMode* info);

unsigned lodepng_is_palette_type(const LodePNGColorMode* info);

unsigned lodepng_has_palette_alpha(const LodePNGColorMode* info);

unsigned lodepng_can_have_alpha(const LodePNGColorMode* info);

size_t lodepng_get_raw_size(unsigned w, unsigned h, const LodePNGColorMode* color);

typedef struct LodePNGInfo
{
  
  unsigned compression_method;
  unsigned filter_method;     
  unsigned interlace_method;  
  LodePNGColorMode color;     

} LodePNGInfo;

void lodepng_info_init(LodePNGInfo* info);

void lodepng_info_cleanup(LodePNGInfo* info);

unsigned lodepng_info_copy(LodePNGInfo* dest, const LodePNGInfo* source);


unsigned lodepng_convert(unsigned char* out, const unsigned char* in,
                         LodePNGColorMode* mode_out, const LodePNGColorMode* mode_in,
                         unsigned w, unsigned h);

typedef enum LodePNGFilterStrategy
{
  LFS_ZERO,  
  LFS_MINSUM,  
  LFS_ENTROPY,  
  LFS_BRUTE_FORCE,
  LFS_PREDEFINED
} LodePNGFilterStrategy;


typedef struct LodePNGColorProfile
{
  unsigned colored; 
  unsigned key; 
  unsigned short key_r; 
  unsigned short key_g;
  unsigned short key_b;
  unsigned alpha; 
  unsigned numcolors; 
  unsigned char palette[1024]; 
  unsigned bits; 
} LodePNGColorProfile;

void lodepng_color_profile_init(LodePNGColorProfile* profile);


unsigned get_color_profile(LodePNGColorProfile* profile,
                           const unsigned char* image, unsigned w, unsigned h,
                           const LodePNGColorMode* mode_in);

unsigned lodepng_auto_choose_color(LodePNGColorMode* mode_out,
                                   const unsigned char* image, unsigned w, unsigned h,
                                   const LodePNGColorMode* mode_in);

typedef struct LodePNGEncoderSettings
{
  LodePNGCompressSettings zlibsettings; 
  unsigned auto_convert;   
  unsigned filter_palette_zero;  
  LodePNGFilterStrategy filter_strategy;  
  const unsigned char* predefined_filters;  
  unsigned force_palette;
} LodePNGEncoderSettings;

void lodepng_encoder_settings_init(LodePNGEncoderSettings* settings);

typedef struct LodePNGState
{

  LodePNGEncoderSettings encoder; 

  LodePNGColorMode info_raw; 
  LodePNGInfo info_png; 
  unsigned error;

} LodePNGState;

void lodepng_state_init(LodePNGState* state);
void lodepng_state_cleanup(LodePNGState* state);
void lodepng_state_copy(LodePNGState* dest, const LodePNGState* source);

unsigned lodepng_encode(unsigned char** out, size_t* outsize,
                        const unsigned char* image, unsigned w, unsigned h,
                        LodePNGState* state);

unsigned lodepng_chunk_length(const unsigned char* chunk);

void lodepng_chunk_type(char type[5], const unsigned char* chunk);

unsigned char lodepng_chunk_type_equals(const unsigned char* chunk, const char* type);

unsigned char lodepng_chunk_ancillary(const unsigned char* chunk);

unsigned char lodepng_chunk_private(const unsigned char* chunk);

unsigned char lodepng_chunk_safetocopy(const unsigned char* chunk);

unsigned char* lodepng_chunk_data(unsigned char* chunk);
const unsigned char* lodepng_chunk_data_const(const unsigned char* chunk);

unsigned lodepng_chunk_check_crc(const unsigned char* chunk);

void lodepng_chunk_generate_crc(unsigned char* chunk);

unsigned char* lodepng_chunk_next(unsigned char* chunk);
const unsigned char* lodepng_chunk_next_const(const unsigned char* chunk);

unsigned lodepng_chunk_append(unsigned char** out, size_t* outlength, const unsigned char* chunk);

unsigned lodepng_chunk_create(unsigned char** out, size_t* outlength, unsigned length,
                              const char* type, const unsigned char* data);

unsigned lodepng_crc32(const unsigned char* buf, size_t len);
