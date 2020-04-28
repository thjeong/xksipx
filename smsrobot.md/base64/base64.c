/*
Copyright (C) Information Equipment co.,LTD.
All rights reserved.
Code by JaeHyuk Cho <mailto:minzkn@infoeq.com>
CVSTAG="$Header$"

- Simple is best !
*/

#if !defined(__def_mzapi_source_base64_c__)
#define __def_mzapi_source_base64_c__ "base64.c"

#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <malloc.h>

#if !defined(__mzapi_peek_vector__)
# define __mzapi_peek_vector__(m_cast,m_base,m_sign,m_offset)         ((m_cast)(((unsigned char *)(m_base)) m_sign (size_t)(m_offset)))
#endif
#if !defined(mzapi_peek_byte)
# define mzapi_peek_byte(m_base,m_offset)                             (*__mzapi_peek_vector__(unsigned char *,m_base,+,m_offset))
#endif
#if !defined(mzapi_poke_byte)
# define mzapi_poke_byte(m_base,m_offset,m_value)                     (*__mzapi_peek_vector__(unsigned char *,m_base,+,m_offset)) = (unsigned char)(m_value)
#endif

static unsigned long (__mzapi_decode_base64__)(int s_character)
{
 if((s_character) >= ((int)'a'))return((((unsigned long)(s_character)) - ((unsigned long)'a')) + 26lu);
 else if((s_character) >= ((int)'A'))return(((unsigned long)(s_character)) - ((unsigned long)'A'));
 else if((s_character) >= ((int)'0'))return((((unsigned long)(s_character)) - ((unsigned long)'0')) + 52lu);
 else if((s_character) == ((int)'+'))return(62lu);
 else if((s_character) == ((int)'/'))return(63lu);
 return(0lu);
}

char * (mzapi_encode_base64)(const char * s_string, size_t s_length)
{
 static const unsigned char c_alpha_table[] = {"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="};
 char * s_result;
 size_t s_source_offset = (size_t)0, s_target_offset = (size_t)0;
 unsigned long s_value;
 int s_quad, s_trip;
 s_result = (char *)malloc((((s_length + ((size_t)2)) / ((size_t)3)) << 2) + ((size_t)1));
 if(s_result == ((char *)0))return((char *)0);
 while(s_source_offset < s_length)
 {
  s_value = ((unsigned long)(mzapi_peek_byte((void *)s_string, s_source_offset) & ((int)0xff))) << 8;
  if((s_source_offset + ((size_t)1)) < s_length)
  {
   s_value |= (unsigned long)(mzapi_peek_byte((void *)s_string, s_source_offset + ((size_t)1)) & ((int)0xff));
   s_trip = (int)1;
  }
  else s_trip = (int)0;
  s_value <<= 8;
  if((s_source_offset + ((size_t)2)) < s_length)
  {
   s_value |= (unsigned long)(mzapi_peek_byte((void *)s_string, s_source_offset + ((size_t)2)) & ((int)0xff));
   s_quad = (int)1;
  }
  else s_quad = (int)0;
  mzapi_poke_byte((void *)s_result, s_target_offset + ((size_t)3), (int)c_alpha_table[(s_quad == (int)1) ? (s_value & 0x3flu) : 64]);
  s_value >>= 6;
  mzapi_poke_byte((void *)s_result, s_target_offset + ((size_t)2), (int)c_alpha_table[(s_trip == (int)1) ? (s_value & 0x3flu) : 64]);
  s_value >>= 6;
  mzapi_poke_byte((void *)s_result, s_target_offset + ((size_t)1), (int)c_alpha_table[s_value & 0x3flu]);
  s_value >>= 6;
  mzapi_poke_byte((void *)s_result, s_target_offset, (int)c_alpha_table[s_value & 0x3flu]);
  s_source_offset += (size_t)3, s_target_offset += (size_t)4;
 }
 mzapi_poke_byte((void *)s_result, s_target_offset, (int)'\0');
 return(s_result);
}

char * (mzapi_decode_base64)(const char * s_string, size_t *s_size)
{
 char * s_result;
 size_t s_length = strlen(s_string), s_source_offset = (size_t)0, s_target_offset = (size_t)0;
 unsigned long s_value;
 if(s_size != ((size_t *)0))*(s_size) = (size_t)0;
 s_result = (char *)malloc((((s_length + ((size_t)3)) >> 2) * ((size_t)3)) + ((size_t)1));
 if(s_result == ((char *)0))return((char *)0);
 while(s_source_offset < s_length)
 {
  s_value  = ((__mzapi_decode_base64__(mzapi_peek_byte((void *)s_string, s_source_offset)) & 0x3flu) << 18) |
             ((__mzapi_decode_base64__(mzapi_peek_byte((void *)s_string, s_source_offset + ((size_t)1))) & 0x3flu) << 12) |
             ((__mzapi_decode_base64__(mzapi_peek_byte((void *)s_string, s_source_offset + ((size_t)2))) & 0x3flu) << 6) |
             (__mzapi_decode_base64__(mzapi_peek_byte((void *)s_string, s_source_offset + ((size_t)3))) & 0x3flu);
  mzapi_poke_byte((void *)s_result, s_target_offset++, (int)((s_value >> 16) & 0xfflu));
  if(mzapi_peek_byte((void *)s_string, s_source_offset + ((size_t)2)) != ((int)'='))
  {
   mzapi_poke_byte((void *)s_result, s_target_offset++, (int)((s_value >> 8) & 0xfflu));
   if(mzapi_peek_byte((void *)s_string, s_source_offset + ((size_t)3)) != ((int)'='))mzapi_poke_byte((void *)s_result, s_target_offset++, (int)(s_value & 0xfflu));
  }
  s_source_offset += (size_t)4;
 }
 mzapi_poke_byte((void *)s_result, s_target_offset, (int)'\0');
 if(s_size != ((size_t *)0))*(s_size) = s_target_offset;
 return(s_result);
}

/*
int main(int s_argc, char **s_argv)
{
 static char s_default[] = {
  "This is \"base64\" test function - by minzkn\n"
  "Copyright (c) INFOEQ co.,LTD. All rights reserved.\n"
 };
 char *s_this, *s_encode, *s_decode;
 size_t s_decode_size;
 
 if(s_argc >= 2)s_this = (char *)(&s_argv[1][0]);
 else s_this = s_default;
 
 (void)fprintf(stdout, "original: {\n%s} (%d)\n\n", s_this, (int)strlen(s_this));
 
 s_encode = mzapi_encode_base64(s_this, strlen(s_this));
 if(s_encode == ((char *)0))return(1); // error
 (void)fprintf(stdout, "encode  : \"%s\" (%d)\n\n", s_encode, (int)strlen(s_encode));

 s_decode = mzapi_decode_base64(s_encode, (size_t *)(&s_decode_size));
 if(s_decode == ((char *)0))
 { // error
  free((void *)s_encode);
  return(1);
 }
 (void)fprintf(stdout, "decode  : {\n%s} (%d / %lu)\n\n", s_decode, (int)strlen(s_decode), (unsigned long)s_decode_size);
 
 free((void *)s_decode);
 free((void *)s_encode);
 return(0);
}
*/

#endif

/* End of source */ 
