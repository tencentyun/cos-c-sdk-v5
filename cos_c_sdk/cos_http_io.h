#ifndef COS_C_SDK_V5_COS_C_SDK_COS_HTTP_IO_H_
#define COS_C_SDK_V5_COS_C_SDK_COS_HTTP_IO_H_

#include "cos_transport.h"
#include "cos_define.h"


COS_CPP_START

cos_http_controller_t *cos_http_controller_create(cos_pool_t *p, int owner);

/* http io error message*/
static APR_INLINE const char *cos_http_controller_get_reason(cos_http_controller_t *ctl) {
    cos_http_controller_ex_t *ctle = (cos_http_controller_ex_t *)ctl;
    return ctle->reason;
}

CURL *cos_request_get();
void request_release(CURL *request);
void request_release2(cos_curl_http_transport_t* t);

int cos_http_io_initialize(const char *user_agent_info, int flag);
void cos_http_io_deinitialize();

int cos_http_send_request(cos_http_controller_t *ctl, cos_http_request_t *req, cos_http_response_t *resp);

void cos_set_default_request_options(cos_http_request_options_t *op);
void cos_set_default_transport_options(cos_http_transport_options_t *op);

cos_http_request_options_t *cos_http_request_options_create(cos_pool_t *p);

cos_http_request_t *cos_http_request_create(cos_pool_t *p);
cos_http_response_t *cos_http_response_create(cos_pool_t *p);

int cos_read_http_body_memory(cos_http_request_t *req, char *buffer, int len);
int cos_write_http_body_memory(cos_http_response_t *resp, const char *buffer, int len);

int cos_read_http_body_file(cos_http_request_t *req, char *buffer, int len);
int cos_write_http_body_file(cos_http_response_t *resp, const char *buffer, int len);
int cos_write_http_body_file_part(cos_http_response_t *resp, const char *buffer, int len);


typedef cos_http_transport_t *(*cos_http_transport_create_pt)(cos_pool_t *p);
typedef int (*cos_http_transport_perform_pt)(cos_http_transport_t *t);

extern cos_pool_t *cos_global_pool;
extern apr_file_t *cos_stderr_file;

extern cos_http_request_options_t *cos_default_http_request_options;
extern cos_http_transport_options_t *cos_default_http_transport_options;

extern cos_http_transport_create_pt cos_http_transport_create;
extern cos_http_transport_perform_pt cos_http_transport_perform;

COS_CPP_END

#endif  //  COS_C_SDK_V5_COS_C_SDK_COS_HTTP_IO_H_

