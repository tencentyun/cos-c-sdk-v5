#ifndef COS_C_SDK_V5_COS_C_SDK_COS_AUTH_H_
#define COS_C_SDK_V5_COS_C_SDK_COS_AUTH_H_

#include "cos_sys_util.h"
#include "cos_string.h"
#include "cos_http_io.h"
#include "cos_define.h"

COS_CPP_START

/**
  * @brief  sign cos headers 
**/
void cos_sign_headers(cos_pool_t *p,
                      const cos_string_t *signstr,
                      const cos_string_t *access_key_id,
                      const cos_string_t *access_key_secret,
                      cos_table_t *headers);

/**
  * @brief  get string to signature
**/
int cos_get_string_to_sign(cos_pool_t *p,
                           http_method_e method,
                           const cos_string_t *secret_id,
                           const cos_string_t *secret_key,
                           const cos_string_t *canon_res,
                           const cos_table_t *headers,
                           const cos_table_t *params,
                           const int64_t expire,
                           cos_string_t *signstr);

/**
  * @brief  get signed cos request headers
**/
int cos_get_signed_headers(cos_pool_t *p, const cos_string_t *access_key_id,
                           const cos_string_t *access_key_secret,
                           const cos_string_t* canon_res, cos_http_request_t *req);

/**
  * @brief  sign cos request
**/
int cos_sign_request(cos_http_request_t *req, const cos_config_t *config);

/**
  * @brief  generate cos request Signature
**/
int get_cos_request_signature(const cos_request_options_t *options, cos_http_request_t *req,
        const cos_string_t *expires, cos_string_t *signature);

/**
  * @brief  get cos signed url
**/
int cos_get_signed_url(const cos_request_options_t *options, cos_http_request_t *req,
        const cos_string_t *expires, cos_string_t *auth_url);

/**
  * @brief  get rtmp string to signature
**/
int cos_get_rtmp_string_to_sign(cos_pool_t *p, const cos_string_t *expires,
    const cos_string_t *canon_res, const cos_table_t *params,
    cos_string_t *signstr);

/**
  * @brief  generate cos rtmp request signature
**/
int get_cos_rtmp_request_signature(const cos_request_options_t *options, cos_http_request_t *req,
    const cos_string_t *expires, cos_string_t *signature);

/**
  * @brief  get cos rtmp signed url
**/
int cos_get_rtmp_signed_url(const cos_request_options_t *options, cos_http_request_t *req,
    const cos_string_t *expires, const cos_string_t *play_list_name, cos_table_t *params,
    cos_string_t *signed_url);

COS_CPP_END

#endif  // COS_C_SDK_V5_COS_C_SDK_COS_AUTH_H_
