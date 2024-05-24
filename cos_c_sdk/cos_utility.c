#include "cos_string.h"
#include "cos_sys_util.h"
#include "cos_log.h"
#include "cos_status.h"
#include "cos_auth.h"
#include "cos_utility.h"

#ifndef WIN32
#include<sys/socket.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#endif

static char *default_content_type = "application/octet-stream";

static cos_content_type_t file_type[] = {
    {"html", "text/html"},
    {"htm", "text/html"},
    {"shtml", "text/html"},
    {"css", "text/css"},
    {"xml", "text/xml"},
    {"gif", "image/gif"},
    {"jpeg", "image/jpeg"},
    {"jpg", "image/jpeg"},
    {"js", "application/x-javascript"},
    {"atom", "application/atom+xml"},
    {"rss", "application/rss+xml"},
    {"mml", "text/mathml"},
    {"txt", "text/plain"},
    {"jad", "text/vnd.sun.j2me.app-descriptor"},
    {"wml", "text/vnd.wap.wml"},
    {"htc", "text/x-component"},
    {"png", "image/png"},
    {"tif", "image/tiff"},
    {"tiff", "image/tiff"},
    {"wbmp", "image/vnd.wap.wbmp"},
    {"ico", "image/x-icon"},
    {"jng", "image/x-jng"},
    {"bmp", "image/x-ms-bmp"},
    {"svg", "image/svg+xml"},
    {"svgz", "image/svg+xml"},
    {"webp", "image/webp"},
    {"jar", "application/java-archive"},
    {"war", "application/java-archive"},
    {"ear", "application/java-archive"},
    {"hqx", "application/mac-binhex40"},
    {"doc ", "application/msword"},
    {"pdf", "application/pdf"},
    {"ps", "application/postscript"},
    {"eps", "application/postscript"},
    {"ai", "application/postscript"},
    {"rtf", "application/rtf"},
    {"xls", "application/vnd.ms-excel"},
    {"ppt", "application/vnd.ms-powerpoint"},
    {"wmlc", "application/vnd.wap.wmlc"},
    {"kml", "application/vnd.google-earth.kml+xml"},
    {"kmz", "application/vnd.google-earth.kmz"},
    {"7z", "application/x-7z-compressed"},
    {"cco", "application/x-cocoa"},
    {"jardiff", "application/x-java-archive-diff"},
    {"jnlp", "application/x-java-jnlp-file"},
    {"run", "application/x-makeself"},
    {"pl", "application/x-perl"},
    {"pm", "application/x-perl"},
    {"prc", "application/x-pilot"},
    {"pdb", "application/x-pilot"},
    {"rar", "application/x-rar-compressed"},
    {"rpm", "application/x-redhat-package-manager"},
    {"sea", "application/x-sea"},
    {"swf", "application/x-shockwave-flash"},
    {"sit", "application/x-stuffit"},
    {"tcl", "application/x-tcl"},
    {"tk", "application/x-tcl"},
    {"der", "application/x-x509-ca-cert"},
    {"pem", "application/x-x509-ca-cert"},
    {"crt", "application/x-x509-ca-cert"},
    {"xpi", "application/x-xpinstall"},
    {"xhtml", "application/xhtml+xml"},
    {"zip", "application/zip"},
    {"wgz", "application/x-nokia-widget"},
    {"bin", "application/octet-stream"},
    {"exe", "application/octet-stream"},
    {"dll", "application/octet-stream"},
    {"deb", "application/octet-stream"},
    {"dmg", "application/octet-stream"},
    {"eot", "application/octet-stream"},
    {"iso", "application/octet-stream"},
    {"img", "application/octet-stream"},
    {"msi", "application/octet-stream"},
    {"msp", "application/octet-stream"},
    {"msm", "application/octet-stream"},
    {"mid", "audio/midi"},
    {"midi", "audio/midi"},
    {"kar", "audio/midi"},
    {"mp3", "audio/mpeg"},
    {"ogg", "audio/ogg"},
    {"m4a", "audio/x-m4a"},
    {"ra", "audio/x-realaudio"},
    {"3gpp", "video/3gpp"},
    {"3gp", "video/3gpp"},
    {"mp4", "video/mp4"},
    {"mpeg", "video/mpeg"},
    {"mpg", "video/mpeg"},
    {"mov", "video/quicktime"},
    {"webm", "video/webm"},
    {"flv", "video/x-flv"},
    {"m4v", "video/x-m4v"},
    {"mng", "video/x-mng"},
    {"asx", "video/x-ms-asf"},
    {"asf", "video/x-ms-asf"},
    {"wmv", "video/x-ms-wmv"},
    {"avi", "video/x-msvideo"},
    {"ts", "video/MP2T"},
    {"m3u8", "application/x-mpegURL"},
    {"apk", "application/vnd.android.package-archive"},
    {NULL, NULL}
};

static char *cos_invaild_params_error_msg[] = {
    "endpoint is null or empty, please check it",
    "appid is null or empty, please check it",
    "bucket is null or empty, please check it",
    "ak is start with space or end with space, please check it",
    "sk is start with space or end with space, please check it",
};

static uintptr_t ignore_bucket_check_ptr = -1;

static int is_ak_or_sk_valid(cos_string_t *str)
{
    char *data;
    int len;

    if (!cos_is_null_string(str)) {
        data = str->data;
        len = str->len;

        if (isspace(data[0]) || isspace(data[len - 1])) {
            return COS_FALSE;
        }
    }

    return COS_TRUE;
}

#ifdef MOCK_IS_SHOULD_RETRY
int is_should_retry(const cos_status_t *s, const char *str){
    return get_test_retry_change_domin_config();
}
#else
int is_should_retry(const cos_status_t *s, const char *str){
    if(s->code && s->error_code && is_default_domain(str) && get_retry_change_domin()){
        if((s->code == -996 && (!strcmp(s->error_code, "HttpIoError"))) || ((s->code/100 != 2) && (s->req_id==NULL || s->req_id==""))){
            return 1;
        }
    }
    return 0;
}
#endif

int is_should_retry_endpoint(const cos_status_t *s, const char *str){
    if(s->code && s->error_code && is_default_endpoint(str) && get_retry_change_domin()){
        if((s->code == -996 && (!strcmp(s->error_code, "HttpIoError"))) || ((s->code/100 != 2) && (s->req_id==NULL || s->req_id==""))){
            return 1;
        }
    }
    return 0;
}

char ** split(const char * s, char delim, int * returnSize) {
    int n = strlen(s);
    char ** ans = (char **)malloc(sizeof(char *) * n);
    int pos = 0;
    int curr = 0;
    int len = 0;
    
    while (pos < n) {
        while (pos < n && s[pos] == delim) {
            ++pos;
        }
        curr = pos;
        while (pos < n && s[pos] != delim) {
            ++pos;
        }
        if (curr < n) {
            ans[len] = (char *)malloc(sizeof(char) * (pos - curr + 1)); 
            strncpy(ans[len], s + curr, pos - curr);
            ans[len][pos - curr] = '\0';
            ++len;
        }
    }
    *returnSize = len;
    return ans;
}

int object_key_simplify_check(const char * path){
    if (!get_object_key_simplify_check()){
        return 1;
    }
    int namesSize = 0;
    int n = strlen(path);
    char ** names = split(path, '/', &namesSize);
    char ** stack = (char **)malloc(sizeof(char *) * namesSize);
    int stackSize = 0;
    int i = 0;
    for (i = 0; i < namesSize; ++i) {
        if (!strcmp(names[i], "..")) {
            if (stackSize > 0) {
                --stackSize;
            } 
        } else if (strcmp(names[i], ".")){
            stack[stackSize] = names[i];
            ++stackSize;
        }
    }

    char * ans = (char *)malloc(sizeof(char) * (n + 1));
    int curr = 0;
    if (stackSize == 0) {
        ans[curr] = '/';
        ++curr;
    } else {
        for (i = 0; i < stackSize; ++i) {
            ans[curr] = '/';
            ++curr;
            strcpy(ans + curr, stack[i]);
            curr += strlen(stack[i]);
        }
    }
    ans[curr] = '\0';
    for (i = 0; i < namesSize; ++i) {
        free(names[i]);
    }
    free(names);
    free(stack);
    if (strlen(ans) == 1 && ans[0] == '/'){
        free(ans);
        return 0;
    }
    free(ans);
    return 1;
}

int is_default_endpoint(const char *str){
    if (str == NULL) {
        return 0;
    }

    int len = strlen(str);
    int i = 0;

    // 匹配 \cos\.
    if (i >= len || strncmp(str + i, "cos.", 4) != 0) {
        return 0;
    }
    i += 4;

    // 匹配 ([\w-]+)-([\w-]+)
    int flag = 0;
    while (i < len && (isalnum(str[i]) || str[i] == '-'))
    {
        if(str[i] == '-') flag = 1;
        i++;
    }

    if (i >= len || str[i] != '.' || !flag) {
        return 0;
    }

    if (i >= len || strncmp(str + i, ".myqcloud.com", 13) != 0) {
        return 0;
    }
    i += 13;

    return i == len;
}
int is_default_domain(const char *str){
    if (str == NULL) {
        return 0;
    }

    int len = strlen(str);
    int i = 0;

    // 匹配 (^([\w-]+)-([\w-]+)
    while (i < len && (isalnum(str[i]) || str[i] == '-')) {
        i++;
    }

    if (i == 0 || i >= len || str[i] != '.') {
        return 0;
    }

    // 匹配 \.cos\.
    if (i >= len || strncmp(str + i, ".cos.", 5) != 0) {
        return 0;
    }
    i += 5;

    // 匹配 ([\w-]+)-([\w-]+)
    int flag = 0;
    while (i < len && (isalnum(str[i]) || str[i] == '-'))
    {
        if(str[i] == '-') flag = 1;
        i++;
    }

    if (i >= len || str[i] != '.' || !flag) {
        return 0;
    }

    if (i >= len || strncmp(str + i, ".myqcloud.com", 13) != 0) {
        return 0;
    }
    i += 13;

    return i == len;
}


// void change_host_suffix(char *endpoint){
//     const char *to_replace = "myqcloud.com";
//     char *pos = strstr(endpoint, to_replace);
//     if (pos) {
//         sprintf(pos, "tencentcos.cn");
//     }
// }

void change_host_suffix(char **endpoint) {
    const char *old_suffix = "myqcloud.com";
    const char *new_suffix = "tencentcos.cn";

    size_t old_len = strlen(old_suffix);
    size_t new_len = strlen(new_suffix);

    if (strncmp(*endpoint + strlen(*endpoint) - old_len, old_suffix, old_len) == 0) {
        size_t new_size = strlen(*endpoint) - old_len + new_len + 1;
        char *new_endpoint = (char *)malloc(new_size);
        if (new_endpoint == NULL) {
            return;
        }

        strncpy(new_endpoint, *endpoint, strlen(*endpoint) - old_len);
        strncpy(new_endpoint + strlen(*endpoint) - old_len, new_suffix, new_len);
        new_endpoint[new_size - 1] = '\0';
        *endpoint = new_endpoint;
    }
}
void change_endpoint_suffix(cos_string_t *endpoint) {
    const char *old_suffix = "myqcloud.com";
    const char *new_suffix = "tencentcos.cn";

    size_t old_len = strlen(old_suffix);
    size_t new_len = strlen(new_suffix);

    if (strncmp(endpoint->data + strlen(endpoint->data) - old_len, old_suffix, old_len) == 0) {
        size_t new_size = strlen(endpoint->data) - old_len + new_len + 1;
        char *new_endpoint = (char *)malloc(new_size);
        if (new_endpoint == NULL) {
            return;
        }

        strncpy(new_endpoint, endpoint->data, strlen(endpoint->data) - old_len);
        strncpy(new_endpoint + strlen(endpoint->data) - old_len, new_suffix, new_len);
        new_endpoint[new_size - 1] = '\0';
        endpoint->data = new_endpoint;
        endpoint->len = strlen(new_endpoint);
    }
}

void clear_change_endpoint_suffix(cos_string_t *endpoint , char * host){
    free(endpoint->data);
    endpoint->data = host;
    endpoint->len = strlen(endpoint->data);
}

static int is_config_params_vaild(const cos_request_options_t *options,
                                  const cos_string_t *bucket,
                                  char **error_msg)
{
    if (cos_is_null_string(&options->config->endpoint)) {
        *error_msg = cos_invaild_params_error_msg[0];
        cos_error_log("config params invaild, msg: %s", *error_msg);
        return COS_FALSE;
    }
    if ((uintptr_t)bucket != ignore_bucket_check_ptr && cos_is_null_string(bucket)) {
        *error_msg = cos_invaild_params_error_msg[2];
        cos_error_log("config params invaild, msg: %s", *error_msg);
        return COS_FALSE;
    }
    if (!is_ak_or_sk_valid(&options->config->access_key_id)) {
        *error_msg = cos_invaild_params_error_msg[3];
        cos_error_log("config params invaild, msg: %s", *error_msg);
        return COS_FALSE;
    }
    if (!is_ak_or_sk_valid(&options->config->access_key_secret)) {
        *error_msg = cos_invaild_params_error_msg[4];
        cos_error_log("config params invaild, msg: %s", *error_msg);
        return COS_FALSE;
    }

    return COS_TRUE;
}

int starts_with(const cos_string_t *str, const char *prefix) {
    uint32_t i;
    if(NULL != str && prefix && str->len > 0 && strlen(prefix)) {
        for(i = 0; str->data[i] != '\0' && prefix[i] != '\0'; i++) {
            if(prefix[i] != str->data[i]) return 0;
        }
        return 1;
    }
    return 0;
}

static void generate_proto(const cos_request_options_t *options, 
                           cos_http_request_t *req) 
{
    const char *proto;
    proto = starts_with(&options->config->endpoint, COS_HTTP_PREFIX) ? 
            COS_HTTP_PREFIX : "";
    proto = starts_with(&options->config->endpoint, COS_HTTPS_PREFIX) ? 
            COS_HTTPS_PREFIX : proto;
    req->proto = apr_psprintf(options->pool, "%.*s", (int)strlen(proto), proto);
}
#if 0
static void generate_rtmp_proto(const cos_request_options_t *options,
                           cos_http_request_t *req)
{
    const char *proto = COS_RTMP_PREFIX;
    req->proto = apr_psprintf(options->pool, "%.*s", (int)strlen(proto), proto);
}
#endif

int is_valid_ip(const char *str)
{
    if (INADDR_NONE == inet_addr(str) || INADDR_ANY == inet_addr(str)) {
        return 0;
    }
    return 1;
}

cos_config_t *cos_config_create(cos_pool_t *p)
{
    return (cos_config_t *)cos_pcalloc(p, sizeof(cos_config_t));
}
#if 0
void cos_config_resolve(cos_pool_t *pool, cos_config_t *config, cos_http_controller_t *ctl)
{
    if(!cos_is_null_string(&config->proxy_host)) {
        // proxy host:port
        if (config->proxy_port == 0) {
            ctl->options->proxy_host = apr_psprintf(pool, "%.*s", config->proxy_host.len, config->proxy_host.data);
        } else {
            ctl->options->proxy_host = apr_psprintf(pool, "%.*s:%d", config->proxy_host.len, config->proxy_host.data, 
                config->proxy_port);
        }
        // authorize user:passwd
        if (!cos_is_null_string(&config->proxy_user) && !cos_is_null_string(&config->proxy_passwd)) {
            ctl->options->proxy_auth = apr_psprintf(pool, "%.*s:%.*s", config->proxy_user.len, 
                config->proxy_user.data, config->proxy_passwd.len, config->proxy_passwd.data);
        }
    }
}
#endif
cos_request_options_t *cos_request_options_create(cos_pool_t *p)
{
    int s;
    cos_request_options_t *options;

    if(p == NULL) {
        if ((s = cos_pool_create(&p, NULL)) != APR_SUCCESS) {
            cos_fatal_log("cos_pool_create failure.");
            return NULL;
        }
    }

    options = (cos_request_options_t *)cos_pcalloc(p, sizeof(cos_request_options_t));
    options->pool = p;

    return options;
}

void cos_set_request_route(cos_http_controller_t *ctl, char *host_ip, int host_port)
{
    ctl->options->host_ip = apr_pstrdup(ctl->pool, host_ip);
    ctl->options->host_port = host_port;
}

int cos_get_service_uri(const cos_request_options_t *options,
                         const int all_region,
                         cos_http_request_t *req,
                         char **error_msg)
{
    int32_t proto_len;
    cos_string_t raw_endpoint;

    // check params
    if (!is_config_params_vaild(options, (cos_string_t *)ignore_bucket_check_ptr, error_msg)) {
        return COS_FALSE;
    }

    generate_proto(options, req);
    if (all_region == 1) {
        req->host = apr_psprintf(options->pool, "%s", "service.cos.myqcloud.com");
    } else {
        proto_len = strlen(req->proto);
        raw_endpoint.len = options->config->endpoint.len - proto_len;
        raw_endpoint.data = options->config->endpoint.data + proto_len;
        req->host = apr_psprintf(options->pool, "%.*s", raw_endpoint.len, raw_endpoint.data);
    }

    req->resource = apr_psprintf(options->pool, "%s", "");
    req->uri = apr_psprintf(options->pool, "%s", "");

    return COS_TRUE;
}

static int cos_get_media_buckets_uri(const cos_request_options_t *options,
                               cos_http_request_t *req,
                               char **error_msg)
{
    static const char *media_bucket_uri = "mediabucket";
    int32_t proto_len;
    cos_string_t raw_endpoint;

    // check params
    if (!is_config_params_vaild(options, (cos_string_t *)ignore_bucket_check_ptr, error_msg)) {
        return COS_FALSE;
    }

    generate_proto(options, req);
    proto_len = strlen(req->proto);
    raw_endpoint.len = options->config->endpoint.len - proto_len;
    raw_endpoint.data = options->config->endpoint.data + proto_len;
    req->host = apr_psprintf(options->pool, "%.*s", raw_endpoint.len, raw_endpoint.data);

    req->resource = apr_psprintf(options->pool, "%s", media_bucket_uri);
    req->uri = apr_psprintf(options->pool, "%s", media_bucket_uri);

    return COS_TRUE;
}

int cos_get_object_uri(const cos_request_options_t *options,
                        const cos_string_t *bucket,
                        const cos_string_t *object,
                        cos_http_request_t *req,
                        char **error_msg)
{
    int32_t proto_len;
    const char *raw_endpoint_str;
    cos_string_t raw_endpoint;
    int32_t bucket_has_appid = 0;

    // check params
    if (!is_config_params_vaild(options, bucket, error_msg)) {
        return COS_FALSE;
    }

    generate_proto(options, req);

    proto_len = strlen(req->proto);
    raw_endpoint_str = cos_pstrdup(options->pool, &options->config->endpoint) + proto_len;
    raw_endpoint.len = options->config->endpoint.len - proto_len;
    raw_endpoint.data = options->config->endpoint.data + proto_len;
   
    req->resource = apr_psprintf(options->pool, "%.*s", 
                                 object->len, object->data);
    if (options->config->is_cname || 
        is_valid_ip(raw_endpoint_str))
    {
        req->host = apr_psprintf(options->pool, "%.*s", 
                                raw_endpoint.len, raw_endpoint.data);
    } else {
        if (options->config->appid.len == 0 || strcmp(options->config->appid.data, "") == 0) {
            bucket_has_appid = 1;
        }
        else {
            if (cos_ends_with(bucket, &options->config->appid) && bucket->len > options->config->appid.len) {
                if (bucket->data[bucket->len - options->config->appid.len - 1] == '-') {
                    bucket_has_appid = 1;
                }
            }
        }
        if (bucket_has_appid) {
            req->host = apr_psprintf(options->pool, "%.*s.%.*s", 
                                     bucket->len, bucket->data,
                                     raw_endpoint.len, raw_endpoint.data);
        }
        else {
            req->host = apr_psprintf(options->pool, "%.*s-%.*s.%.*s", 
                                     bucket->len, bucket->data,
                                     options->config->appid.len, options->config->appid.data,
                                     raw_endpoint.len, raw_endpoint.data);
        }
    }
    req->uri = apr_psprintf(options->pool, "%.*s",
                            object->len, object->data);
    
    return COS_TRUE;
}

const char *cos_gen_object_url(const cos_request_options_t *options,
                                const cos_string_t *bucket,
                                const cos_string_t *object)
{
    int32_t proto_len;
    const char *proto;
    const char *host;
    const char *uri;
    const char *raw_endpoint_str;
    char uristr[3*COS_MAX_URI_LEN+1];
    cos_string_t raw_endpoint;
    int32_t bucket_has_appid = 0;

    proto = starts_with(&options->config->endpoint, COS_HTTP_PREFIX) ?
        COS_HTTP_PREFIX : "";
    proto = starts_with(&options->config->endpoint, COS_HTTPS_PREFIX) ?
        COS_HTTPS_PREFIX : proto;

    proto_len = strlen(proto);
    raw_endpoint_str = cos_pstrdup(options->pool, &options->config->endpoint) + proto_len;
    raw_endpoint.len = options->config->endpoint.len - proto_len;
    raw_endpoint.data = options->config->endpoint.data + proto_len;

    if (options->config->is_cname || 
            is_valid_ip(raw_endpoint_str))
    {
        host = apr_psprintf(options->pool, "%.*s", 
                raw_endpoint.len, raw_endpoint.data);
    } else {
        if (options->config->appid.len == 0 || strcmp(options->config->appid.data, "") == 0) {
            bucket_has_appid = 1;
        }
        else {
            if (cos_ends_with(bucket, &options->config->appid) && bucket->len > options->config->appid.len) {
                if (bucket->data[bucket->len - options->config->appid.len - 1] == '-') {
                    bucket_has_appid = 1;
                }
            }
        }
        if (bucket_has_appid) {
            host = apr_psprintf(options->pool, "%.*s.%.*s", 
                    bucket->len, bucket->data,
                    raw_endpoint.len, raw_endpoint.data);
        }
        else {
            host = apr_psprintf(options->pool, "%.*s-%.*s.%.*s", 
                    bucket->len, bucket->data,
                    options->config->appid.len, options->config->appid.data,
                    raw_endpoint.len, raw_endpoint.data);
        }
    }
    uri = apr_psprintf(options->pool, "%.*s", object->len, object->data);
    if (cos_url_encode(uristr, uri, COS_MAX_URI_LEN) != COSE_OK) {
        return "";
    }
    proto = strlen(proto) != 0 ? proto : COS_HTTP_PREFIX;
    return apr_psprintf(options->pool, "%s%s/%s", proto, host, uristr);
}

int cos_get_bucket_uri(const cos_request_options_t *options, 
                        const cos_string_t *bucket,
                        cos_http_request_t *req,
                        char **error_msg)
{
    int32_t proto_len;
    const char *raw_endpoint_str;
    cos_string_t raw_endpoint;
    int32_t bucket_has_appid = 0;

    // check params
    if (!is_config_params_vaild(options, bucket, error_msg)) {
        return COS_FALSE;
    }

    generate_proto(options, req);

    proto_len = strlen(req->proto);
    raw_endpoint_str = cos_pstrdup(options->pool, &options->config->endpoint) + proto_len;
    raw_endpoint.len = options->config->endpoint.len - proto_len;
    raw_endpoint.data = options->config->endpoint.data + proto_len;

    req->resource = apr_psprintf(options->pool, "%s", "");
    
    if (options->config->is_cname || 
        is_valid_ip(raw_endpoint_str))
    {
        req->host = apr_psprintf(options->pool, "%.*s", 
                                raw_endpoint.len, raw_endpoint.data);
    } else {
        if (options->config->appid.len == 0 || strcmp(options->config->appid.data, "") == 0) {
            bucket_has_appid = 1;
        }
        else {
            if (cos_ends_with(bucket, &options->config->appid) && bucket->len > options->config->appid.len) {
                if (bucket->data[bucket->len - options->config->appid.len - 1] == '-') {
                    bucket_has_appid = 1;
                }
            }
        }
        if (bucket_has_appid) {
            req->host = apr_psprintf(options->pool, "%.*s.%.*s", 
                                     bucket->len, bucket->data,
                                     raw_endpoint.len, raw_endpoint.data);
        }
        else {
            req->host = apr_psprintf(options->pool, "%.*s-%.*s.%.*s", 
                                     bucket->len, bucket->data,
                                     options->config->appid.len, options->config->appid.data,
                                     raw_endpoint.len, raw_endpoint.data);
        }
    }
    req->uri = apr_psprintf(options->pool, "%s", "");

    return COS_TRUE;
}

#if 0
void cos_get_rtmp_uri(const cos_request_options_t *options,
                      const cos_string_t *bucket,
                      const cos_string_t *live_channel_id,
                      cos_http_request_t *req)
{
    int32_t proto_len = 0;
    const char *raw_endpoint_str = NULL;
    cos_string_t raw_endpoint;

    generate_rtmp_proto(options, req);

    proto_len = strlen(req->proto);

    req->resource = apr_psprintf(options->pool, "%.*s/%.*s", bucket->len, bucket->data,
        live_channel_id->len, live_channel_id->data);

    raw_endpoint_str = cos_pstrdup(options->pool,
            &options->config->endpoint) + proto_len;
    raw_endpoint.len = options->config->endpoint.len - proto_len;
    raw_endpoint.data = options->config->endpoint.data + proto_len;

    if (options->config->is_cname) {
        req->host = apr_psprintf(options->pool, "%.*s",
                raw_endpoint.len, raw_endpoint.data);
        req->uri = apr_psprintf(options->pool, "live/%.*s",
            live_channel_id->len, live_channel_id->data);
    } else if (is_valid_ip(raw_endpoint_str)) {
        req->host = apr_psprintf(options->pool, "%.*s",
                raw_endpoint.len, raw_endpoint.data);
        req->uri = apr_psprintf(options->pool, "%.*s/live/%.*s",
                                bucket->len, bucket->data,
                                live_channel_id->len, live_channel_id->data);
    } else {
        req->host = apr_psprintf(options->pool, "%.*s.%.*s",
                bucket->len, bucket->data,
                raw_endpoint.len, raw_endpoint.data);
        req->uri = apr_psprintf(options->pool, "live/%.*s",
            live_channel_id->len, live_channel_id->data);
    }
}
#endif

void cos_write_request_body_from_buffer(cos_list_t *buffer, 
                                        cos_http_request_t *req)
{
    cos_list_movelist(buffer, &req->body);
    req->body_len = cos_buf_list_len(&req->body);
}

int cos_write_request_body_from_file(cos_pool_t *p, 
                                     const cos_string_t *filename, 
                                     cos_http_request_t *req)
{
    int res = COSE_OK;
    cos_file_buf_t *fb = cos_create_file_buf(p);
    res = cos_open_file_for_all_read(p, filename->data, fb);
    if (res != COSE_OK) {
        cos_error_log("Open read file fail, filename:%s\n", filename->data);
        return res;
    }

    req->body_len = fb->file_last;
    req->file_path = filename->data;
    req->file_buf = fb;
    req->type = BODY_IN_FILE;
    req->read_body = cos_read_http_body_file;

    return res;
}

int cos_write_request_body_from_upload_file(cos_pool_t *p, 
                                            cos_upload_file_t *upload_file, 
                                            cos_http_request_t *req)
{
    int res = COSE_OK;
    cos_file_buf_t *fb = cos_create_file_buf(p);
    res = cos_open_file_for_range_read(p, upload_file->filename.data, 
            upload_file->file_pos, upload_file->file_last, fb);
    if (res != COSE_OK) {
        cos_error_log("Open read file fail, filename:%s\n", 
                      upload_file->filename.data);
        return res;
    }

    req->body_len = fb->file_last - fb->file_pos;
    req->file_path = upload_file->filename.data;
    req->file_buf = fb;
    req->type = BODY_IN_FILE;
    req->read_body = cos_read_http_body_file;

    return res;
}

void cos_fill_read_response_body(cos_http_response_t *resp, 
                                 cos_list_t *buffer)
{
    if (NULL != buffer) {
        cos_list_movelist(&resp->body, buffer);
    }
}

int cos_init_read_response_body_to_file(cos_pool_t *p, 
                                        const cos_string_t *filename, 
                                        cos_http_response_t *resp)
{
    int res = COSE_OK;
    cos_file_buf_t *fb = cos_create_file_buf(p);
    res = cos_open_file_for_write(p, filename->data, fb);
    if (res != COSE_OK) {
        cos_error_log("Open write file fail, filename:%s\n", filename->data);
        return res;
    }
    resp->file_path = filename->data;
    resp->file_buf = fb;
    resp->write_body = cos_write_http_body_file;
    resp->type = BODY_IN_FILE;

    return res;
}

int cos_init_read_response_body_to_file_part(cos_pool_t *p, 
                                        cos_upload_file_t *download_file,
                                        cos_http_response_t *resp)
{
    int res = COSE_OK;
    cos_file_buf_t *fb = cos_create_file_buf(p);
    res = cos_open_file_for_range_write(p, download_file->filename.data, download_file->file_pos, download_file->file_last, fb);
    if (res != COSE_OK) {
        cos_error_log("Open write file fail, filename:%s\n", download_file->filename.data);
        return res;
    }
    resp->file_path = download_file->filename.data;
    resp->file_buf = fb;
    resp->write_body = cos_write_http_body_file_part;
    resp->type = BODY_IN_FILE;

    return res;
}


void cos_fill_read_response_header(cos_http_response_t *resp, 
                                   cos_table_t **headers)
{
    if (NULL != headers && NULL != resp) {        
        *headers = resp->headers;
    }
}

void *cos_create_api_result_content(cos_pool_t *p, size_t size)
{
    void *result_content = cos_palloc(p, size);
    if (NULL == result_content) {
        return NULL;
    }
    
    cos_list_init((cos_list_t *)result_content);

    return result_content;
}

cos_acl_grantee_content_t *cos_create_acl_list_content(cos_pool_t *p)
{
    cos_acl_grantee_content_t *content = NULL;
    content = (cos_acl_grantee_content_t *)cos_create_api_result_content(p, sizeof(cos_acl_grantee_content_t));
    cos_str_set(&content->type, "");
    cos_str_set(&content->id, "");
    cos_str_set(&content->name, "");
    cos_str_set(&content->permission, "");
    return content;
}

cos_get_service_content_t *cos_create_get_service_content(cos_pool_t *p)
{
    cos_get_service_content_t *content = NULL;
    content = (cos_get_service_content_t*)cos_create_api_result_content(p, sizeof(cos_get_service_content_t));
    cos_str_set(&content->bucket_name, "");
    cos_str_set(&content->location, "");
    cos_str_set(&content->creation_date, "");
    return content;
}

cos_list_object_content_t *cos_create_list_object_content(cos_pool_t *p)
{
    return (cos_list_object_content_t *)cos_create_api_result_content(
            p, sizeof(cos_list_object_content_t));
}

cos_list_object_common_prefix_t *cos_create_list_object_common_prefix(cos_pool_t *p)
{
    return (cos_list_object_common_prefix_t *)cos_create_api_result_content(
            p, sizeof(cos_list_object_common_prefix_t));
}

cos_list_multipart_upload_content_t *cos_create_list_multipart_upload_content(cos_pool_t *p)
{
    return (cos_list_multipart_upload_content_t*)cos_create_api_result_content(
            p, sizeof(cos_list_multipart_upload_content_t));
}

cos_list_part_content_t *cos_create_list_part_content(cos_pool_t *p)
{
    cos_list_part_content_t *list_part_content = NULL;
    list_part_content = (cos_list_part_content_t*)cos_create_api_result_content(p,
        sizeof(cos_list_part_content_t));

    return list_part_content;
}

cos_complete_part_content_t *cos_create_complete_part_content(cos_pool_t *p)
{
    cos_complete_part_content_t *complete_part_content = NULL;
    complete_part_content = (cos_complete_part_content_t*)cos_create_api_result_content(
            p, sizeof(cos_complete_part_content_t));

    return complete_part_content;
}

cos_get_service_params_t *cos_create_get_service_params(cos_pool_t *p)
{
    cos_get_service_params_t *params = NULL;
    params = (cos_get_service_params_t *)cos_pcalloc(p, sizeof(cos_get_service_params_t));
    params->all_region = 1;
    cos_list_init(&params->bucket_list);
    cos_str_set(&params->owner_id, "");
    cos_str_set(&params->owner_display_name, "");
    return params;
}

cos_acl_params_t *cos_create_acl_params(cos_pool_t *p)
{
    cos_acl_params_t *params = NULL;
    params = (cos_acl_params_t *)cos_pcalloc(p, sizeof(cos_acl_params_t));
    cos_list_init(&params->grantee_list);
    cos_str_set(&params->owner_id, "");
    cos_str_set(&params->owner_name, "");
    return params;
}

cos_copy_object_params_t *cos_create_copy_object_params(cos_pool_t *p)
{
    cos_copy_object_params_t *params = NULL;
    params = (cos_copy_object_params_t *)cos_pcalloc(p, sizeof(cos_copy_object_params_t));
    cos_str_set(&params->etag, "");
    cos_str_set(&params->last_modify, "");
    return params;
}

cos_list_object_params_t *cos_create_list_object_params(cos_pool_t *p)
{
    cos_list_object_params_t * params;
    params = (cos_list_object_params_t *)cos_pcalloc(
            p, sizeof(cos_list_object_params_t));
    cos_list_init(&params->object_list);
    cos_list_init(&params->common_prefix_list);
    cos_str_set(&params->prefix, "");
    cos_str_set(&params->marker, "");
    cos_str_set(&params->delimiter, "");
    params->truncated = 1;
    params->max_ret = COS_PER_RET_NUM;
    return params;
}

cos_list_upload_part_params_t *cos_create_list_upload_part_params(cos_pool_t *p)
{
    cos_list_upload_part_params_t *params;
    params = (cos_list_upload_part_params_t *)cos_pcalloc(
            p, sizeof(cos_list_upload_part_params_t));
    cos_list_init(&params->part_list);
    cos_str_set(&params->part_number_marker, "");
    params->max_ret = COS_PER_RET_NUM;
    params->truncated = 1;
    return params;
}

cos_list_multipart_upload_params_t *cos_create_list_multipart_upload_params(cos_pool_t *p)
{
    cos_list_multipart_upload_params_t *params;
    params = (cos_list_multipart_upload_params_t *)cos_pcalloc(
            p, sizeof(cos_list_multipart_upload_params_t));
    cos_list_init(&params->upload_list);
    cos_str_set(&params->prefix, "");
    cos_str_set(&params->key_marker, "");
    cos_str_set(&params->upload_id_marker, "");
    cos_str_set(&params->delimiter, "");
    params->truncated = 1;
    params->max_ret = COS_PER_RET_NUM;
    return params;
}

cos_upload_part_copy_params_t *cos_create_upload_part_copy_params(cos_pool_t *p)
{
    cos_upload_part_copy_params_t *copy_param;
    copy_param = (cos_upload_part_copy_params_t *)cos_pcalloc(p, sizeof(cos_upload_part_copy_params_t));
    cos_str_set(&copy_param->copy_source, "");
    cos_str_set(&copy_param->dest_bucket, "");
    cos_str_set(&copy_param->dest_object, "");
    cos_str_set(&copy_param->upload_id, "");
    copy_param->part_num = 0;
    copy_param->range_start = -1;
    copy_param->range_end = -1;
    copy_param->rsp_content = cos_create_copy_object_params(p);
    return copy_param;
}

cos_lifecycle_rule_content_t *cos_create_lifecycle_rule_content(cos_pool_t *p)
{
    cos_lifecycle_rule_content_t *rule;
    rule = (cos_lifecycle_rule_content_t *)cos_pcalloc(
            p, sizeof(cos_lifecycle_rule_content_t));
    cos_str_set(&rule->id, "");
    cos_str_set(&rule->prefix, "");
    cos_str_set(&rule->status, "");
    cos_str_set(&rule->expire.date, "");
    cos_str_set(&rule->transition.date, "");
    cos_str_set(&rule->transition.storage_class, "");
    rule->expire.days = INT_MAX;
    rule->transition.days = INT_MAX;
    rule->abort.days = INT_MAX;
    return rule;
}

cos_cors_rule_content_t *cos_create_cors_rule_content(cos_pool_t *p)
{
    cos_cors_rule_content_t *rule;
    rule = (cos_cors_rule_content_t *)cos_pcalloc(
            p, sizeof(cos_cors_rule_content_t));
    cos_str_set(&rule->id, "");
    cos_str_set(&rule->allowed_origin, "");
    cos_str_set(&rule->allowed_method, "");
    cos_str_set(&rule->allowed_header, "");
    cos_str_set(&rule->expose_header, "");
    rule->max_age_seconds = INT_MAX;
    return rule;
}

cos_versioning_content_t *cos_create_versioning_content(cos_pool_t *p)
{
    cos_versioning_content_t *versioning;
    versioning = (cos_versioning_content_t *)cos_pcalloc(p, sizeof(cos_versioning_content_t));
    cos_str_set(&versioning->status, "");
    return versioning;
}

cos_replication_params_t *cos_create_replication_params(cos_pool_t *p)
{
    cos_replication_params_t *params = NULL;
    params = (cos_replication_params_t *)cos_pcalloc(p, sizeof(cos_replication_params_t));
    cos_list_init(&params->rule_list);
    cos_str_set(&params->role, "");
    return params;
}

cos_replication_rule_content_t *cos_create_replication_rule_content(cos_pool_t *p)
{
    cos_replication_rule_content_t *rule;
    rule = (cos_replication_rule_content_t *)cos_pcalloc(p, sizeof(cos_replication_rule_content_t));
    cos_str_set(&rule->id, "");
    cos_str_set(&rule->status, "");
    cos_str_set(&rule->prefix, "");
    cos_str_set(&rule->dst_bucket, "");
    cos_str_set(&rule->storage_class, "");
    return rule;
}

cos_website_rule_content_t *cos_create_website_rule_content(cos_pool_t *p)
{
    cos_website_rule_content_t *content = NULL;
    content = (cos_website_rule_content_t*) cos_palloc(p, sizeof(cos_website_rule_content_t));
    cos_list_init(&content->node);
    cos_str_set(&content->condition_errcode, "");
    cos_str_set(&content->condition_prefix, "");
    cos_str_set(&content->redirect_protocol, "");
    cos_str_set(&content->redirect_replace_key, "");
    cos_str_set(&content->redirect_replace_key_prefix, "");
    return content;
}

cos_website_params_t *cos_create_website_params(cos_pool_t *p)
{
    cos_website_params_t *params = NULL;
    params = (cos_website_params_t*) cos_palloc(p, sizeof(cos_website_params_t));
    cos_list_init(&params->rule_list);
    cos_str_set(&params->index, "");
    cos_str_set(&params->redirect_protocol, "");
    cos_str_set(&params->error_document, "");
    return params;
}

cos_domain_params_t *cos_create_domain_params(cos_pool_t *p)
{
    cos_domain_params_t *params = NULL;
    params = (cos_domain_params_t*) cos_palloc(p, sizeof(cos_domain_params_t));
    cos_str_set(&params->status, "");
    cos_str_set(&params->name, "");
    cos_str_set(&params->type, "");
    cos_str_set(&params->forced_replacement, "");

    return params;
}

cos_logging_params_t *cos_create_logging_params(cos_pool_t *p) 
{
    cos_logging_params_t *params;
    params = (cos_logging_params_t*) cos_palloc(p, sizeof(cos_logging_params_t));
    cos_str_set(&params->target_bucket, "");
    cos_str_set(&params->target_prefix, "");

    return params;
}

cos_list_inventory_params_t *cos_create_list_inventory_params(cos_pool_t *p)
{
    cos_list_inventory_params_t *params = NULL;
    params = (cos_list_inventory_params_t*) cos_palloc(p, sizeof(cos_list_inventory_params_t));
    cos_list_init(&params->inventorys);
    cos_str_set(&params->continuation_token, "");
    cos_str_set(&params->next_continuation_token, "");
    params->is_truncated = 0;

    return params;
}

cos_inventory_params_t *cos_create_inventory_params(cos_pool_t *p)
{
    cos_inventory_params_t *params = NULL;
    params = (cos_inventory_params_t*) cos_palloc(p, sizeof(cos_inventory_params_t));
    cos_str_set(&params->id, "");
    cos_str_set(&params->is_enabled, "");
    cos_str_set(&params->frequency, "");
    cos_str_set(&params->filter_prefix, "");
    cos_str_set(&params->included_object_versions, "");

    cos_str_set(&params->destination.format, "");
    cos_str_set(&params->destination.account_id, "");
    cos_str_set(&params->destination.bucket, "");
    cos_str_set(&params->destination.prefix, "");
    params->destination.encryption = 0;

    cos_list_init(&params->fields);
    cos_list_init(&params->node);

    return params;
}

cos_inventory_optional_t *cos_create_inventory_optional(cos_pool_t *p)
{
    cos_inventory_optional_t *params = NULL;
    params = (cos_inventory_optional_t*) cos_palloc(p, sizeof(cos_inventory_optional_t));
    cos_str_set(&params->field, "");
    cos_list_init(&params->node);

    return params;
}

cos_tagging_params_t *cos_create_tagging_params(cos_pool_t *p)
{
    cos_tagging_params_t *params = NULL;
    params = (cos_tagging_params_t*) cos_palloc(p, sizeof(cos_tagging_params_t));
    cos_list_init(&params->node);
    return params;
}

cos_tagging_tag_t *cos_create_tagging_tag(cos_pool_t *p)
{
    cos_tagging_tag_t *params = NULL;
    params = (cos_tagging_tag_t*) cos_palloc(p, sizeof(cos_tagging_tag_t));
    cos_list_init(&params->node);
    cos_str_set(&params->key, "");
    cos_str_set(&params->value, "");
    return params;
}

cos_referer_params_t *cos_create_referer_params(cos_pool_t *p)
{
    cos_referer_params_t *params = NULL;
    params = (cos_referer_params_t*) cos_pcalloc(p, sizeof(cos_referer_params_t));
    cos_list_init(&params->domain_list);
    return params;
}

cos_referer_domain_t *cos_create_referer_domain(cos_pool_t *p)
{
    cos_referer_domain_t *params = NULL;
    params = (cos_referer_domain_t*) cos_pcalloc(p, sizeof(cos_referer_domain_t));
    return params;
}

cos_intelligenttiering_params_t *cos_create_intelligenttiering_params(cos_pool_t *p)
{
    cos_intelligenttiering_params_t *params = NULL;
    params = (cos_intelligenttiering_params_t*) cos_palloc(p, sizeof(cos_intelligenttiering_params_t));
    cos_str_set(&params->status, "");
    params->days = 0;
    return params;
}

cos_object_restore_params_t *cos_create_object_restore_params(cos_pool_t *p)
{
    cos_object_restore_params_t *params;
    params = (cos_object_restore_params_t *)cos_pcalloc(
            p, sizeof(cos_object_restore_params_t));
    cos_str_set(&params->tier, "");
    params->days = INT_MAX;
    return params;
}

cos_upload_file_t *cos_create_upload_file(cos_pool_t *p)
{
    return (cos_upload_file_t *)cos_pcalloc(p, sizeof(cos_upload_file_t));
}

cos_object_key_t *cos_create_cos_object_key(cos_pool_t *p)
{
    return (cos_object_key_t *)cos_pcalloc(p, sizeof(cos_object_key_t));
}

ci_qrcode_info_t *ci_create_qrcode_info(cos_pool_t *p)
{
    ci_qrcode_info_t *res = (ci_qrcode_info_t *)cos_palloc(p, sizeof(ci_qrcode_info_t));
    cos_list_init(&res->node);
    return res;
}

ci_operation_result_t *ci_create_operation_result(cos_pool_t *p)
{
    ci_operation_result_t *res = (ci_operation_result_t *)cos_palloc(p, sizeof(ci_operation_result_t));
    cos_list_init(&res->object.qrcode_info);
    return res;
}

ci_qrcode_result_t *ci_create_qrcode_result(cos_pool_t *p)
{
    ci_qrcode_result_t*res = (ci_qrcode_result_t *)cos_palloc(p, sizeof(ci_qrcode_result_t));
    cos_list_init(&res->qrcode_info);
    return res;
}

#if 0
cos_live_channel_publish_url_t *cos_create_live_channel_publish_url(cos_pool_t *p)
{
    return (cos_live_channel_publish_url_t *)cos_pcalloc(p, sizeof(cos_live_channel_publish_url_t));
}

cos_live_channel_play_url_t *cos_create_live_channel_play_url(cos_pool_t *p)
{
    return (cos_live_channel_play_url_t *)cos_pcalloc(p, sizeof(cos_live_channel_play_url_t));
}

cos_live_channel_content_t *cos_create_list_live_channel_content(cos_pool_t *p)
{
    cos_live_channel_content_t *list_live_channel_content = NULL;
    list_live_channel_content = (cos_live_channel_content_t*)cos_create_api_result_content(p,
        sizeof(cos_live_channel_content_t));
    cos_list_init(&list_live_channel_content->publish_url_list);
    cos_list_init(&list_live_channel_content->play_url_list);
    return list_live_channel_content;
}

cos_live_record_content_t *cos_create_live_record_content(cos_pool_t *p)
{
    cos_live_record_content_t *live_record_content = NULL;
    live_record_content = (cos_live_record_content_t*)cos_create_api_result_content(p,
        sizeof(cos_live_record_content_t));
    return live_record_content;
}

cos_live_channel_configuration_t *cos_create_live_channel_configuration_content(cos_pool_t *p)
{
    cos_live_channel_configuration_t *config;
    config = (cos_live_channel_configuration_t *)cos_pcalloc(
            p, sizeof(cos_live_channel_configuration_t));

    cos_str_set(&config->name, "");
    cos_str_set(&config->description, "");
    cos_str_set(&config->status, LIVE_CHANNEL_STATUS_ENABLED);
    cos_str_set(&config->target.type, LIVE_CHANNEL_DEFAULT_TYPE);
    cos_str_set(&config->target.play_list_name, LIVE_CHANNEL_DEFAULT_PLAYLIST);
    config->target.frag_duration = LIVE_CHANNEL_DEFAULT_FRAG_DURATION;
    config->target.frag_count = LIVE_CHANNEL_DEFAULT_FRAG_COUNT;

    return config;
}
#endif

cos_checkpoint_t *cos_create_checkpoint_content(cos_pool_t *p) 
{
    cos_checkpoint_t *cp;
    cp = (cos_checkpoint_t *)cos_pcalloc(p, sizeof(cos_checkpoint_t));
    cp->parts = (cos_checkpoint_part_t *)cos_pcalloc(p, sizeof(cos_checkpoint_part_t) * COS_MAX_PART_NUM);
    cos_str_set(&cp->md5, "");
    cos_str_set(&cp->file_path, "");
    cos_str_set(&cp->file_md5, "");
    cos_str_set(&cp->object_name, "");
    cos_str_set(&cp->object_last_modified, "");
    cos_str_set(&cp->object_etag, "");
    cos_str_set(&cp->upload_id, "");
    return cp;
}

cos_checkpoint_t *cos_create_checkpoint_content_with_partnum(cos_pool_t *p, int part_num) 
{
    cos_checkpoint_t *cp;
    cp = (cos_checkpoint_t *)cos_pcalloc(p, sizeof(cos_checkpoint_t));
    cp->parts = (cos_checkpoint_part_t *)cos_pcalloc(p, sizeof(cos_checkpoint_part_t) * cos_max(part_num, COS_MAX_PART_NUM));
    cos_str_set(&cp->md5, "");
    cos_str_set(&cp->file_path, "");
    cos_str_set(&cp->file_md5, "");
    cos_str_set(&cp->object_name, "");
    cos_str_set(&cp->object_last_modified, "");
    cos_str_set(&cp->object_etag, "");
    cos_str_set(&cp->upload_id, "");
    return cp;
}

cos_resumable_clt_params_t *cos_create_resumable_clt_params_content(cos_pool_t *p, int64_t part_size, int32_t thread_num,
                                                                    int enable_checkpoint, const char *checkpoint_path)
{
    cos_resumable_clt_params_t *clt;
    clt = (cos_resumable_clt_params_t *)cos_pcalloc(p, sizeof(cos_resumable_clt_params_t));
    clt->part_size = part_size;
    clt->thread_num = thread_num;
    clt->enable_checkpoint = enable_checkpoint;
    if (enable_checkpoint && NULL != checkpoint_path) {
        cos_str_set(&clt->checkpoint_path, checkpoint_path);
    }
    return clt;
}

#if 0
cos_list_live_channel_params_t *cos_create_list_live_channel_params(cos_pool_t *p)
{
    cos_list_live_channel_params_t *params;
    params = (cos_list_live_channel_params_t *)cos_pcalloc(
            p, sizeof(cos_list_live_channel_params_t));
    cos_list_init(&params->live_channel_list);
    cos_str_set(&params->prefix, "");
    cos_str_set(&params->marker, "");
    params->truncated = 1;
    params->max_keys = COS_PER_RET_NUM;
    return params;
}
#endif

void cos_set_multipart_content_type(cos_table_t *headers)
{
    const char *content_type;
    content_type = (char*)(apr_table_get(headers, COS_CONTENT_TYPE));
    content_type = content_type == NULL ? COS_MULTIPART_CONTENT_TYPE : content_type;
    apr_table_set(headers, COS_CONTENT_TYPE, content_type);
}

const char *get_cos_acl_str(cos_acl_e cos_acl)
{
    switch (cos_acl) {
        case COS_ACL_PRIVATE:
            return  "private";
        case COS_ACL_PUBLIC_READ:
            return "public-read";
        case COS_ACL_PUBLIC_READ_WRITE:
            return "public-read-write";
        case COS_ACL_DEFAULT:
            return  "default";
        default:
            return NULL;
    }
}

void cos_init_request(const cos_request_options_t *options, 
                      http_method_e method,
                      cos_http_request_t **req, 
                      cos_table_t *params, 
                      cos_table_t *headers, 
                      cos_http_response_t **resp)
{
    *req = cos_http_request_create(options->pool);
    *resp = cos_http_response_create(options->pool);
    (*req)->method = method;
    init_sts_token_header();
    (*req)->headers = headers;
    (*req)->query_params = params;
}

int cos_init_service_request(const cos_request_options_t *options,
                              http_method_e method,
                              cos_http_request_t **req,
                              cos_table_t *params,
                              cos_table_t *headers,
                              const int all_region,
                              cos_http_response_t **resp,
                              char **error_msg)
{
    cos_init_request(options, method, req, params, headers, resp);
    return cos_get_service_uri(options, all_region, *req, error_msg);
}

int cos_init_media_buckets_request(const cos_request_options_t *options,
                              http_method_e method,
                              cos_http_request_t **req,
                              cos_table_t *params,
                              cos_table_t *headers,
                              cos_http_response_t **resp,
                              char **error_msg)
{
    cos_init_request(options, method, req, params, headers, resp);
    return cos_get_media_buckets_uri(options, *req, error_msg);
}

int cos_init_bucket_request(const cos_request_options_t *options, 
                             const cos_string_t *bucket,
                             http_method_e method, 
                             cos_http_request_t **req, 
                             cos_table_t *params, 
                             cos_table_t *headers,
                             cos_http_response_t **resp,
                             char **error_msg)
{
    cos_init_request(options, method, req, params, headers, resp);
    return cos_get_bucket_uri(options, bucket, *req, error_msg);
}

int cos_init_object_request(const cos_request_options_t *options, 
                             const cos_string_t *bucket,
                             const cos_string_t *object, 
                             http_method_e method, 
                             cos_http_request_t **req, 
                             cos_table_t *params, 
                             cos_table_t *headers,
                             cos_progress_callback cb,
                             uint64_t init_crc,
                             cos_http_response_t **resp,
                             char **error_msg)
{
    cos_init_request(options, method, req, params, headers, resp);
    if (HTTP_GET == method) {
        (*resp)->progress_callback = cb;
    } else if (HTTP_PUT == method || HTTP_POST == method) {
        (*req)->progress_callback = cb;
        (*req)->crc64 = init_crc;
    }

    return cos_get_object_uri(options, bucket, object, *req, error_msg);
}

#if 0
void cos_init_live_channel_request(const cos_request_options_t *options, 
                                   const cos_string_t *bucket,
                                   const cos_string_t *live_channel,
                                   http_method_e method,
                                   cos_http_request_t **req,
                                   cos_table_t *params,
                                   cos_table_t *headers,
                                   cos_http_response_t **resp)
{
    cos_init_request(options, method, req, params, headers, resp);
    cos_get_object_uri(options, bucket, live_channel, *req);
}

void cos_init_signed_url_request(const cos_request_options_t *options, 
                                 const cos_string_t *signed_url,
                                 http_method_e method, 
                                 cos_http_request_t **req, 
                                 cos_table_t *params, 
                                 cos_table_t *headers, 
                                 cos_http_response_t **resp)
{
    *req = cos_http_request_create(options->pool);
    *resp = cos_http_response_create(options->pool);
    (*req)->method = method;
    (*req)->headers = headers;
    (*req)->query_params = params;
    (*req)->signed_url = signed_url->data;
}
#endif

cos_status_t *cos_send_request(cos_http_controller_t *ctl, 
                               cos_http_request_t *req,
                               cos_http_response_t *resp)
{
    cos_status_t *s;
    const char *reason;
    int res = COSE_OK;

    s = cos_status_create(ctl->pool);
    res = cos_http_send_request(ctl, req, resp);

    if (res != COSE_OK) {
        reason = cos_http_controller_get_reason(ctl);
        cos_status_set(s, res, COS_HTTP_IO_ERROR_CODE, reason);
    } else if (!cos_http_is_ok(resp->status)) {
        s = cos_status_parse_from_body(ctl->pool, &resp->body, resp->status, s);
    } else {
        s->code = resp->status;
    }

    s->req_id = (char*)(apr_table_get(resp->headers, "x-cos-request-id"));
    if (s->req_id == NULL) {
        s->req_id = (char*)(apr_table_get(resp->headers, "x-img-request-id"));
        if (s->req_id == NULL) {
            s->req_id = "";
        }
    }

    return s;
}

void reset_list_pos(cos_list_t *list) {
    cos_buf_t *b;
    cos_list_for_each_entry(cos_buf_t, b, list, node) {
        b->pos = b->start;
    }
}

cos_status_t *cos_process_request(const cos_request_options_t *options,
                                  cos_http_request_t *req, 
                                  cos_http_response_t *resp,
                                  const int retry)
{
    int res = COSE_OK;
    cos_status_t *s;

    req->clear_body = 0;
    s = cos_status_create(options->pool);
    res = cos_sign_request(req, options->config);
    if (res != COSE_OK) { 
        cos_status_set(s, res, COS_CLIENT_ERROR_CODE, NULL);
        return s;
    }
    s = cos_send_request(options->ctl, req, resp);

    if (retry && is_should_retry(s, req->host)){
        if (apr_table_get(req->headers, "Host") != NULL)
        {
            apr_table_unset(req->headers, "Host");
        }
        if (apr_table_get(req->headers, "Authorization") != NULL) {
            apr_table_unset(req->headers, "Authorization");
        }
        char *host = req->host;
        change_host_suffix(&req->host);
        reset_list_pos(&req->body);
        req->crc64 = 0;
        res = cos_sign_request(req, options->config);
        if (res != COSE_OK) {
            cos_status_set(s, res, COS_CLIENT_ERROR_CODE, NULL);
            return s;
        }
        if (req->file_path != NULL) {
            cos_string_t file;
            cos_str_set(&file, req->file_path);
            res = cos_write_request_body_from_file(options->pool, &file, req);
            if (res != COSE_OK) {
                cos_file_error_status_set(s, res);
                return s;
            }
        }
        if (req->file_path != NULL) {
            cos_string_t file;
            cos_str_set(&file, req->file_path);
            res = cos_write_request_body_from_file(options->pool, &file, req);
            if (res != COSE_OK) {
                cos_file_error_status_set(s, res);
                return s;
            }
        }

        ((cos_http_controller_ex_t *)options->ctl)->error_code = COSE_OK;
        resp->status = 0;
        req->consumed_bytes = 0;

        s = cos_send_request(options->ctl, req, resp);
        //clear body
        if (req->clear_body){
            cos_buf_t *b;
            cos_buf_t *n;
            cos_list_for_each_entry_safe(cos_buf_t, b, n, &req->body, node) {
                cos_list_del(&b->node);
            }
        }
        free(req->host);
        req->host = host;
    }
    return s;
}

cos_status_t *cos_process_signed_request(const cos_request_options_t *options,
                                         cos_http_request_t *req, 
                                         cos_http_response_t *resp)
{
    return cos_send_request(options->ctl, req, resp);
}

void cos_get_part_size(int64_t filesize, int64_t *part_size)
{
    *part_size = (1024*1024 > *part_size) ? 1024*1024 : *part_size;
    if (filesize > (*part_size) * COS_MAX_PART_NUM) {
        *part_size = (filesize + COS_MAX_PART_NUM - 
                      filesize % COS_MAX_PART_NUM) / COS_MAX_PART_NUM;

        cos_warn_log("Part number larger than max limit, "
                     "part size Changed to:%" APR_INT64_T_FMT "\n",
                     *part_size);
    } 
}

int part_sort_cmp(const void *a, const void *b)
{
    return (((cos_upload_part_t*)a)->part_num -
            ((cos_upload_part_t*)b)->part_num > 0 ? 1 : -1);
}

char *get_content_type_by_suffix(const char *suffix)
{
    cos_content_type_t *content_type;

    for (content_type = file_type; content_type->suffix; ++content_type) {
        if (strcasecmp(content_type->suffix, suffix) == 0)
        {
            return content_type->type;
        }
    }
    return default_content_type;
}

char *get_content_type(const char *name)
{
    char *begin;
    char *content_type = NULL;
    begin = strrchr(name, '.');
    if (begin) {
        content_type = get_content_type_by_suffix(begin + 1);
    }
    return content_type;
}

void set_content_type(const char* file_name,
                      const char* key,
                      cos_table_t *headers)
{
    char *user_content_type = NULL;
    char *content_type = NULL;
    const char *mime_key = NULL;

    mime_key = file_name == NULL ? key : file_name;

    user_content_type = (char*)apr_table_get(headers, COS_CONTENT_TYPE);
    if (NULL == user_content_type && mime_key != NULL) {
        content_type = get_content_type(mime_key);
        if (content_type) {
            apr_table_set(headers, COS_CONTENT_TYPE, content_type);
        } else {
            apr_table_set(headers, COS_CONTENT_TYPE, default_content_type);
        }
    }
}

cos_table_t* cos_table_create_if_null(const cos_request_options_t *options, 
                                      cos_table_t *table, 
                                      int table_size) 
{
    if (table == NULL) {
        table = cos_table_make(options->pool, table_size);
    }
    return table;
}

int is_enable_crc(const cos_request_options_t *options) 
{
    return options->ctl->options->enable_crc;
}

int is_enable_md5(const cos_request_options_t *options) 
{
    return options->ctl->options->enable_md5;
}

int has_crc_in_response(const cos_http_response_t *resp) 
{
    if (NULL != apr_table_get(resp->headers, COS_HASH_CRC64_ECMA)) {
        return COS_TRUE;
    }

    return COS_FALSE;
}

int has_range_or_process_in_request(const cos_http_request_t *req) 
{
    if (NULL != apr_table_get(req->headers, "Range") || 
        NULL != apr_table_get(req->query_params, COS_PROCESS)) {
        return COS_TRUE;
    }

    return COS_FALSE;
}

static int check_crc(uint64_t crc, const apr_table_t *headers) 
{
    char * srv_crc = (char*)(apr_table_get(headers, COS_HASH_CRC64_ECMA));
    if (NULL != srv_crc && crc != cos_atoui64(srv_crc)) {
        return COSE_CRC_INCONSISTENT_ERROR;
    }
    return COSE_OK;
}

int cos_check_crc_consistent(uint64_t crc, const apr_table_t *resp_headers, cos_status_t *s) 
{
    int res = check_crc(crc, resp_headers);
    if (res != COSE_OK) {
        cos_inconsistent_error_status_set(s, res);
    }
    return res;
}

int cos_check_len_consistent(cos_list_t *buffer, const apr_table_t *resp_headers, cos_status_t *s)
{
    if (resp_headers != NULL && buffer != NULL) {
        int64_t len = cos_buf_list_len(buffer);
        char *content_length = (char*)(apr_table_get(resp_headers, COS_CONTENT_LENGTH));
        if (content_length != NULL && len != cos_atoi64(content_length)) {
            cos_inconsistent_error_status_set(s, COSE_CRC_INCONSISTENT_ERROR);
            return COSE_CRC_INCONSISTENT_ERROR;
        }
    }
    return COSE_OK;
}

int cos_get_temporary_file_name(cos_pool_t *p, const cos_string_t *filename, cos_string_t *temp_file_name)
{
    int len = filename->len + 1;
    char *temp_file_name_ptr = NULL;

    len += strlen(COS_TEMP_FILE_SUFFIX);
    temp_file_name_ptr = cos_pcalloc(p, len);

    apr_snprintf(temp_file_name_ptr, len, "%.*s%s", filename->len, filename->data, COS_TEMP_FILE_SUFFIX);
    cos_str_set(temp_file_name, temp_file_name_ptr);

    return len;
}

int cos_temp_file_rename(cos_status_t *s, const char *from_path, const char *to_path, apr_pool_t *pool)
{
    int res = -1;

    if (s != NULL) {
        if (cos_status_is_ok(s)) {
            res = apr_file_rename(from_path, to_path, pool);
        } else {
            res = apr_file_remove(from_path, pool);
        }
    }

    return res;
}

int cos_add_content_md5_from_buffer(const cos_request_options_t *options,
                                    cos_list_t *buffer,
                                    cos_table_t *headers)
{
    char *b64_value = NULL;
    int b64_buf_len = (20 + 1) * 4 / 3;
    int b64_len;
    unsigned char md5_data[APR_MD5_DIGESTSIZE + 1];
    apr_md5_ctx_t context;
    cos_buf_t *content;
    
    /* do not add content-md5 if the option is disabled */
    if (!is_enable_md5(options)) {
        return 0;
    }

    /* use user-specified content-md5 */
    if (NULL != apr_table_get(headers, COS_CONTENT_MD5)) {
        return 0;
    }

    /* calc md5 digest */
    if (0 != apr_md5_init(&context)) {
        return COSE_INTERNAL_ERROR;
    }
    cos_list_for_each_entry(cos_buf_t, content, buffer, node) {
        if (0 != apr_md5_update(&context, content->pos, (apr_size_t)cos_buf_size(content))) {
            return COSE_INTERNAL_ERROR;
        }
    }
    if (0 != apr_md5_final(md5_data, &context)) {
        return COSE_INTERNAL_ERROR;
    }
    md5_data[APR_MD5_DIGESTSIZE] = '\0';

    /* add content-md5 header */
    b64_value = cos_pcalloc(options->pool, b64_buf_len);
    b64_len = cos_base64_encode(md5_data, 16, b64_value);
    b64_value[b64_len] = '\0';
    apr_table_addn(headers, COS_CONTENT_MD5, b64_value);
    
    return 0;
}

int cos_add_content_md5_from_file(const cos_request_options_t *options,
                                  const cos_string_t *filename,
                                  cos_table_t *headers)
{
    char *b64_value = NULL;
    int b64_buf_len = (20 + 1) * 4 / 3;
    int b64_len;
    unsigned char md5_data[APR_MD5_DIGESTSIZE + 1];
    apr_md5_ctx_t context;
    apr_file_t *thefile;
    apr_finfo_t finfo;
    int s;
    char buff[64 * 1024];
    apr_size_t nbytes;
    apr_size_t bytes_left;
    
    /* do not add content-md5 if the option is disabled */
    if (!is_enable_md5(options)) {
        return 0;
    }

    /* use user-specified content-md5 */
    if (NULL != apr_table_get(headers, COS_CONTENT_MD5)) {
        return 0;
    }

    /* open input file */
    if ((s = apr_file_open(&thefile, filename->data, APR_READ, APR_UREAD | APR_GREAD, options->pool)) != APR_SUCCESS) {
        return COSE_OPEN_FILE_ERROR;
    }
    if ((s = apr_file_info_get(&finfo, APR_FINFO_NORM, thefile)) != APR_SUCCESS) {
        apr_file_close(thefile);
        return COSE_FILE_INFO_ERROR;
    }
    bytes_left = finfo.size;

    /* calc md5 digest */
    if (0 != apr_md5_init(&context)) {
        apr_file_close(thefile);
        return COSE_INTERNAL_ERROR;
    }
    while (bytes_left) {
        nbytes = cos_min(sizeof(buff), bytes_left);
        if ((s = apr_file_read(thefile, buff, &nbytes)) != APR_SUCCESS) {
            apr_file_close(thefile);
            return COSE_FILE_READ_ERROR;
        }
        if (0 != apr_md5_update(&context, buff, nbytes)) {
            apr_file_close(thefile);
            return COSE_INTERNAL_ERROR;
        }
        bytes_left -= nbytes;
    }
    if (0 != apr_md5_final(md5_data, &context)) {
        apr_file_close(thefile);
        return COSE_INTERNAL_ERROR;
    }
    md5_data[APR_MD5_DIGESTSIZE] = '\0';

    /* add content-md5 header */
    b64_value = cos_pcalloc(options->pool, b64_buf_len);
    b64_len = cos_base64_encode(md5_data, 16, b64_value);
    b64_value[b64_len] = '\0';
    apr_table_addn(headers, COS_CONTENT_MD5, b64_value);

    apr_file_close(thefile);
    
    return 0;
}

int cos_add_content_md5_from_file_range(const cos_request_options_t *options,
                                  cos_upload_file_t *upload_file,
                                  cos_table_t *headers)
{
    char *b64_value = NULL;
    int b64_buf_len = (20 + 1) * 4 / 3;
    int b64_len;
    unsigned char md5_data[APR_MD5_DIGESTSIZE + 1];
    apr_md5_ctx_t context;
    apr_file_t *thefile;
    apr_finfo_t finfo;
    int s;
    char buff[64 * 1024];
    apr_size_t nbytes;
    apr_size_t bytes_left;
    apr_off_t offset;
    apr_off_t file_last;
    
    /* do not add content-md5 if the option is disabled */
    if (!is_enable_md5(options)) {
        return 0;
    }

    /* use user-specified content-md5 */
    if (NULL != apr_table_get(headers, COS_CONTENT_MD5)) {
        return 0;
    }

    /* open input file */
    if ((s = apr_file_open(&thefile, upload_file->filename.data, APR_READ, APR_UREAD | APR_GREAD, options->pool)) != APR_SUCCESS) {
        return COSE_OPEN_FILE_ERROR;
    }
    if ((s = apr_file_info_get(&finfo, APR_FINFO_NORM, thefile)) != APR_SUCCESS) {
        apr_file_close(thefile);
        return COSE_FILE_INFO_ERROR;
    }
    offset = upload_file->file_pos;
    if ((s = apr_file_seek(thefile, APR_SET, &offset)) != APR_SUCCESS) {
        apr_file_close(thefile);
        return COSE_FILE_INFO_ERROR;
    }
    file_last = cos_min(finfo.size, upload_file->file_last);
    if (offset >= file_last) {
        apr_file_close(thefile);
        return COSE_FILE_INFO_ERROR;
    }
    bytes_left = file_last - offset;

    /* calc md5 digest */
    if (0 != apr_md5_init(&context)) {
        apr_file_close(thefile);
        return COSE_INTERNAL_ERROR;
    }
    while (bytes_left) {
        nbytes = cos_min(sizeof(buff), bytes_left);
        if ((s = apr_file_read(thefile, buff, &nbytes)) != APR_SUCCESS) {
            apr_file_close(thefile);
            return COSE_FILE_READ_ERROR;
        }
        if (0 != apr_md5_update(&context, buff, nbytes)) {
            apr_file_close(thefile);
            return COSE_INTERNAL_ERROR;
        }
        bytes_left -= nbytes;
    }
    if (0 != apr_md5_final(md5_data, &context)) {
        apr_file_close(thefile);
        return COSE_INTERNAL_ERROR;
    }
    md5_data[APR_MD5_DIGESTSIZE] = '\0';

    /* add content-md5 header */
    b64_value = cos_pcalloc(options->pool, b64_buf_len);
    b64_len = cos_base64_encode(md5_data, 16, b64_value);
    b64_value[b64_len] = '\0';
    apr_table_addn(headers, COS_CONTENT_MD5, b64_value);

    apr_file_close(thefile);
    
    return 0;
}

void cos_set_content_md5_enable(cos_http_controller_t *ctl, int enable)
{
    ctl->options->enable_md5 = enable;
}

ci_video_auditing_job_options_t* ci_video_auditing_job_options_create(cos_pool_t *p)
{
    return (ci_video_auditing_job_options_t *)cos_pcalloc(p, sizeof(ci_video_auditing_job_options_t)); 
}

ci_media_buckets_request_t* ci_media_buckets_request_create(cos_pool_t *p)
{
    return (ci_media_buckets_request_t *)cos_pcalloc(p, sizeof(ci_media_buckets_request_t)); 
}

ci_get_snapshot_request_t* ci_snapshot_request_create(cos_pool_t *p)
{
    return (ci_get_snapshot_request_t *)cos_pcalloc(p, sizeof(ci_get_snapshot_request_t)); 
}

