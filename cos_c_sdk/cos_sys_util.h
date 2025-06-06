#ifndef COS_C_SDK_V5_COS_C_SDK_COS_SYS_UTIL_H_
#define COS_C_SDK_V5_COS_C_SDK_COS_SYS_UTIL_H_

#include "cos_buf.h"
#include "cos_string.h"
#include "cos_sys_define.h"
#include "cos_fstack.h"

#include <mxml.h>
#include <apr_md5.h>
#include <apr_sha1.h>

COS_CPP_START


typedef enum {
    sign_content_header,
    sign_content_query_params
} sign_content_type_e;

int cos_parse_xml_body(cos_list_t *bc, mxml_node_t **root);

void cos_gnome_sort(const char **headers, int size);

int cos_convert_to_gmt_time(char* date, const char* format, apr_time_exp_t *tm);
int cos_get_gmt_str_time(char datestr[COS_MAX_GMT_TIME_LEN]);

/**
 * URL-encodes a string from [src] into [dest]. [dest] must have at least
 * 3x the number of characters that [source] has. At most [maxSrcSize] bytes
 * from [src] are encoded; if more are present in [src], 0 is returned from
 * urlEncode, else nonzero is returned.
 */
int cos_url_encode(char *dest, const char *src, int maxSrcSize);

const char* cos_http_method_to_string(http_method_e method);

const char* cos_http_method_to_string_lower(http_method_e method);


/**
 * encode query string, check query args < COS_MAX_QUERY_ARG_LEN
 * result string "?a&b=x"
 */
int cos_query_params_to_string(cos_pool_t *p, cos_table_t *query_params, cos_string_t *querystr);

/**
 * base64 encode bytes. The output buffer must have at least
 * ((4 * (inLen + 1)) / 3) bytes in it.  Returns the number of bytes written
 * to [out].
 */
int cos_base64_encode(const unsigned char *in, int inLen, char *out);

/**
 * Compute HMAC-SHA-1 with key [key] and message [message], storing result
 * in [hmac]
 */
void HMAC_SHA1(unsigned char hmac[20], const unsigned char *key, int key_len,
               const unsigned char *message, int message_len);

unsigned char* cos_md5(cos_pool_t* pool, const char* in, apr_size_t in_len);

int cos_url_decode(const char *in, char *out);

/*
 * Convert a string to a long long integer.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
 */
int64_t cos_strtoll(const char *nptr, char **endptr, int base);

/*
 * @brief Convert a string to int64_t.
**/
int64_t cos_atoi64(const char *nptr);

/*
 * @brief Convert a string to an unsigned long long integer.
 *
 * Ignores `locale' stuff.  Assumes that the upper and lower case
 * alphabets and digits are each contiguous.
**/
uint64_t cos_strtoull(const char *nptr, char **endptr, int base);

/*
 * @brief Convert a string to uint64_t.
**/
uint64_t cos_atoui64(const char *nptr);

void cos_get_hex_from_digest(unsigned char hexdigest[40], unsigned char digest[20]);

void cos_get_hmac_sha1_hexdigest(unsigned char hexdigest[40], const unsigned char *key, int key_len,
                                               const unsigned char *message, int message_len);

void cos_get_sha1_hexdigest(unsigned char hexdigest[40], const unsigned char *message, int message_len);

/*
 * @brief query params and header to sign format string.
**/
void cos_table_sort_by_dict(cos_table_t *table);
int cos_table_to_string(cos_pool_t *p, const cos_table_t *table, cos_string_t *querystr, sign_content_type_e sign_type);
int cos_table_key_to_string(cos_pool_t *p, const cos_table_t *table, cos_string_t *querystr, sign_content_type_e sign_type);

int get_retry_change_domin();
void set_retry_change_domin(int user_retry_change_domin);
int get_test_retry_change_domin_config();
void set_test_retry_change_domin_config(int user_retry_change_domin);
int get_object_key_simplify_check();
void set_object_key_simplify_check(int user_object_key_simplify_check);

/*
 * @brief init/deinit sign header table.
**/
void cos_init_sign_header_table();
void cos_deinit_sign_header_table();


COS_CPP_END

#endif  //  COS_C_SDK_V5_COS_C_SDK_COS_SYS_UTIL_H_
