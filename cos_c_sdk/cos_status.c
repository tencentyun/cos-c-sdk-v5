#include "cos_log.h"
#include "cos_sys_define.h"
#include "cos_sys_util.h"
#include "cos_status.h"

const char COS_XML_PARSE_ERROR_CODE[] = "ParseXmlError";
const char COS_OPEN_FILE_ERROR_CODE[] = "OpenFileFail";
const char COS_WRITE_FILE_ERROR_CODE[] = "WriteFileFail";
const char COS_RENAME_FILE_ERROR_CODE[] = "RenameFileFail";
const char COS_HTTP_IO_ERROR_CODE[] = "HttpIoError";
const char COS_UNKNOWN_ERROR_CODE[] = "UnknownError";
const char COS_CLIENT_ERROR_CODE[] = "ClientError";
const char COS_UTF8_ENCODE_ERROR_CODE[] = "Utf8EncodeFail";
const char COS_URL_ENCODE_ERROR_CODE[] = "UrlEncodeFail";
const char COS_INCONSISTENT_ERROR_CODE[] = "InconsistentError";
const char COS_CREATE_QUEUE_ERROR_CODE[] = "CreateQueueFail";
const char COS_CREATE_THREAD_POOL_ERROR_CODE[] = "CreateThreadPoolFail";
const char COS_LACK_OF_CONTENT_LEN_ERROR_CODE[] = "LackOfContentLength";
const char COS_SERVER_ERROR_CODE[] = "ServerError";
const char COS_INTERNAL_ERROR_CODE[] = "InternalError";
const char COS_SLOW_DOWN_ERROR_CODE[] = "SlowDown";
const char COS_SERVICE_UNAVAILABLE_ERROR_CODE[] = "ServiceUnavailable";


cos_status_t *cos_status_create(cos_pool_t *p) {
    return (cos_status_t *)cos_pcalloc(p, sizeof(cos_status_t));
}

cos_status_t *cos_status_dup(cos_pool_t *p, cos_status_t *src) {
    cos_status_t *dst = cos_status_create(p);
    dst->code = src->code;
    dst->error_code = apr_pstrdup(p, src->error_code);
    dst->error_msg = apr_pstrdup(p, src->error_msg);
    dst->req_id = apr_pstrdup(p, src->req_id);
    return dst;
}

int cos_should_retry(cos_status_t *s) {
    int cos_error_code = 0;

    if (s == NULL || s->code / 100 == 2) {
        return COS_FALSE;
    }

    if (s->code / 100 == 5) {
        return COS_TRUE;
    }

    if (s->error_code != NULL) {
        cos_error_code = atoi(s->error_code);
        if (cos_error_code == COSE_CONNECTION_FAILED || cos_error_code == COSE_REQUEST_TIMEOUT ||
            cos_error_code == COSE_FAILED_CONNECT || cos_error_code == COSE_SERVICE_ERROR) {
            return COS_TRUE;
        }
    }

    return COS_FALSE;
}

static mxml_node_t *cos_find_error_node(mxml_node_t *root) {
    const char *element;

    if (root == NULL || mxmlGetType(root) != MXML_ELEMENT) {
        return NULL;
    }

    element = mxmlGetElement(root);
    if (element != NULL && strcmp(element, "Error") == 0) {
        return root;
    }

    return mxmlFindElement(root, root, "Error", NULL, NULL, MXML_DESCEND);
}

static void cos_status_fill_error_from_xml(cos_pool_t *p, mxml_node_t *root,
                                           mxml_node_t *error_node, cos_status_t *s) {
    mxml_node_t *n;
    const char *content;

    n = mxmlFindElement(error_node, root, "Code", NULL, NULL, MXML_DESCEND);
    if (n != NULL && (content = mxmlGetOpaque(n)) != NULL) {
        s->error_code = apr_pstrdup(p, content);
    }

    n = mxmlFindElement(error_node, root, "Message", NULL, NULL, MXML_DESCEND);
    if (n != NULL && (content = mxmlGetOpaque(n)) != NULL) {
        s->error_msg = apr_pstrdup(p, content);
    }
}

cos_status_t *cos_status_parse_from_body(cos_pool_t *p, cos_list_t *bc, int code, int need_check_2xx_body, cos_status_t *s){
    mxml_node_t *root = NULL, *error_node = NULL;

    if (s == NULL) {
        s = cos_status_create(p);
    }
    s->code = code;

    // cases:
    // 1. 2xx and no need to check body, return directly
    // 2. not 2xx, parse body error: 
    //    a. empty or xml parse error: return unknown error
    //    b. no error in body, return error
    //    c. error exists in body, return parsed error
    // 3. 2xx and need to check body
    //    a. empty or xml parse error: return unknown error
    //    b. no error in body, return directly
    //    c. error exists in body, return parsed error

    // case 1: 
    if (cos_http_is_ok(code) && !need_check_2xx_body) {
        return s;
    }

    // case 2.a, case 3.a
    if (cos_list_empty(bc) || cos_parse_xml_body(bc, &root) != COSE_OK) {
        s->error_code = (char *)COS_UNKNOWN_ERROR_CODE;
        return s;
    }

    error_node = cos_find_error_node(root);
    
    if (!cos_http_is_ok(code)) {
        // case 2.b, case 2.c
        if (error_node == NULL) {
            s->error_code = (char *)COS_UNKNOWN_ERROR_CODE;
        } else {
            cos_status_fill_error_from_xml(p, root, error_node, s);
            if (s->error_code == NULL) {
                s->error_code = (char *)COS_UNKNOWN_ERROR_CODE;
            }
        }
    } else if (error_node != NULL) {
        // case 3.c
        cos_status_fill_error_from_xml(p, root, error_node, s);
        if (s->error_code == NULL) {
            s->error_code = (char *)COS_UNKNOWN_ERROR_CODE;
        }
        s->code = COSE_SERVICE_ERROR;
    }
    
    mxmlDelete(root);
    return s;
}
