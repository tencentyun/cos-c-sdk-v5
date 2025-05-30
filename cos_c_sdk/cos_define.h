#ifndef COS_C_SDK_V5_COS_C_SDK_COS_DEFINE_H_
#define COS_C_SDK_V5_COS_C_SDK_COS_DEFINE_H_

#include "cos_string.h"
#include "cos_list.h"
#include "cos_transport.h"

#ifdef __cplusplus
#define COS_CPP_START extern "C" {
#define COS_CPP_END }
#else
#define COS_CPP_START
#define COS_CPP_END
#endif

#define cos_xml_error_status_set(STATUS, RES) do {                   \
        cos_status_set(STATUS, RES, COS_XML_PARSE_ERROR_CODE, NULL); \
    } while(0)

#define cos_file_error_status_set(STATUS, RES) do {                   \
        cos_status_set(STATUS, RES, COS_OPEN_FILE_ERROR_CODE, NULL); \
    } while(0)

#define cos_inconsistent_error_status_set(STATUS, RES) do {                     \
        cos_status_set(STATUS, RES, COS_INCONSISTENT_ERROR_CODE, NULL); \
    } while(0)

extern const char COS_CANNONICALIZED_HEADER_ACL[];
extern const char COS_CANNONICALIZED_HEADER_SOURCE[];
extern const char COS_CANNONICALIZED_HEADER_PREFIX[];
extern const char COS_CANNONICALIZED_HEADER_DATE[];
extern const char COS_CANNONICALIZED_HEADER_COPY_SOURCE[];
extern const char COS_GRANT_READ[];
extern const char COS_GRANT_WRITE[];
extern const char COS_GRANT_FULL_CONTROL[];
extern const char COS_CONTENT_MD5[];
extern const char COS_CONTENT_TYPE[];
extern const char COS_CONTENT_LENGTH[];
extern const char COS_DATE[];
extern const char COS_AUTHORIZATION[];
extern const char COS_ACCESSKEYID[];
extern const char COS_EXPECT[];
extern const char COS_TRANSFER_ENCODING[];
extern const char COS_HOST[];
extern const char COS_EXPIRES[];
extern const char COS_SIGNATURE[];
extern const char COS_ACL[];
extern const char COS_ENCODING_TYPE[];
extern const char COS_PREFIX[];
extern const char COS_DELIMITER[];
extern const char COS_MARKER[];
extern const char COS_MAX_KEYS[];
extern const char COS_RESTORE[];
extern const char COS_UPLOADS[];
extern const char COS_UPLOAD_ID[];
extern const char COS_MAX_PARTS[];
extern const char COS_KEY_MARKER[];
extern const char COS_UPLOAD_ID_MARKER[];
extern const char COS_MAX_UPLOADS[];
extern const char COS_PARTNUMBER[];
extern const char COS_PART_NUMBER_MARKER[];
extern const char COS_APPEND[];
extern const char COS_POSITION[];
extern const char COS_MULTIPART_CONTENT_TYPE[];
extern const char COS_COPY_SOURCE[];
extern const char COS_COPY_SOURCE_RANGE[];
extern const char COS_SECURITY_TOKEN[];
extern const char COS_STS_SECURITY_TOKEN[];
extern const char COS_REPLACE_OBJECT_META[];
extern const char COS_OBJECT_TYPE[];
extern const char COS_NEXT_APPEND_POSITION[];
extern const char COS_HASH_CRC64_ECMA[];
extern const char COS_CALLBACK[];
extern const char COS_CALLBACK_VAR[];
extern const char COS_PROCESS[];
extern const char COS_LIFECYCLE[];
extern const char COS_CORS[];
extern const char COS_VERSIONING[];
extern const char COS_REPLICATION[];
extern const char COS_WEBSITE[];
extern const char COS_DOMAIN[];
extern const char COS_LOGGING[];
extern const char COS_INVENTORY[];
extern const char COS_TAGGING[];
extern const char COS_REFERER[];
extern const char COS_DELETE[];
extern const char COS_YES[];
extern const char COS_OBJECT_TYPE_NORMAL[];
extern const char COS_OBJECT_TYPE_APPENDABLE[];
extern const char COS_LIVE_CHANNEL[];
extern const char COS_LIVE_CHANNEL_STATUS[];
extern const char COS_COMP[];
extern const char COS_LIVE_CHANNEL_STAT[];
extern const char COS_LIVE_CHANNEL_HISTORY[];
extern const char COS_LIVE_CHANNEL_VOD[];
extern const char COS_LIVE_CHANNEL_START_TIME[];
extern const char COS_LIVE_CHANNEL_END_TIME[];
extern const char COS_PLAY_LIST_NAME[];
extern const char LIVE_CHANNEL_STATUS_DISABLED[];
extern const char LIVE_CHANNEL_STATUS_ENABLED[];
extern const char LIVE_CHANNEL_STATUS_IDLE[];
extern const char LIVE_CHANNEL_STATUS_LIVE[];
extern const char LIVE_CHANNEL_DEFAULT_TYPE[];
extern const char LIVE_CHANNEL_DEFAULT_PLAYLIST[];
extern const int  LIVE_CHANNEL_DEFAULT_FRAG_DURATION;
extern const int  LIVE_CHANNEL_DEFAULT_FRAG_COUNT;
extern const int COS_MAX_PART_NUM;
extern const int COS_PER_RET_NUM;
extern const int MAX_SUFFIX_LEN;
extern const char COS_CONTENT_SHA1[];
extern const char COS_RANGE[];
extern const char COS_INTELLIGENTTIERING[];
extern const char *SIGN_HEADER[];
extern const int SIGN_HEADER_NUM;
extern const char X_COS_HEADER[];
extern const char COS_VERSION_ID[];
extern const char X_CI_HEADER[];



typedef struct cos_lib_curl_initializer_s cos_lib_curl_initializer_t;

/**
 * cos_acl is an ACL that can be specified when an object is created or
 * updated.  Each canned ACL has a predefined value when expanded to a full
 * set of COS ACL Grants.
 * Private canned ACL gives the owner FULL_CONTROL and no other permissions
 *     are issued
 * Public Read canned ACL gives the owner FULL_CONTROL and all users Read
 *     permission 
 * Public Read Write canned ACL gives the owner FULL_CONTROL and all users
 *     Read and Write permission
 **/
typedef enum {
    COS_ACL_PRIVATE                  = 0,   /*< private */
    COS_ACL_PUBLIC_READ              = 1,   /*< public read */
    COS_ACL_PUBLIC_READ_WRITE        = 2,   /*< public read write */
    COS_ACL_DEFAULT                  = 3    /*< default */
} cos_acl_e;

typedef struct {
    cos_string_t endpoint;
    cos_string_t access_key_id;
    cos_string_t access_key_secret;
    cos_string_t appid;
    cos_string_t sts_token;
    int is_cname;
    cos_string_t proxy_host;
    int proxy_port;
    cos_string_t proxy_user;
    cos_string_t proxy_passwd;
    int retry_change_domin;
} cos_config_t;

typedef struct {
    cos_config_t *config;
    cos_http_controller_t *ctl; /*< cos http controller, more see cos_transport.h */
    cos_pool_t *pool;
} cos_request_options_t;

typedef struct {
    cos_list_t node;
    cos_string_t type;
    cos_string_t id;
    cos_string_t name;
    cos_string_t permission;
} cos_acl_grantee_content_t;

typedef struct {
    cos_string_t owner_id;
    cos_string_t owner_name;;
    cos_list_t grantee_list;
} cos_acl_params_t;

typedef struct {
    cos_string_t etag;
    cos_string_t last_modify;;
} cos_copy_object_params_t;

typedef struct {
    cos_list_t node;
    cos_string_t key;
    cos_string_t last_modified;
    cos_string_t etag;
    cos_string_t size;
    cos_string_t owner_id;
    cos_string_t owner_display_name;
    cos_string_t storage_class;
} cos_list_object_content_t;

typedef struct {
    cos_list_t node;
    cos_string_t prefix;
} cos_list_object_common_prefix_t;

typedef struct {
    cos_list_t node;
    cos_string_t key;
    cos_string_t upload_id;
    cos_string_t initiated;
} cos_list_multipart_upload_content_t;

typedef struct {
    cos_list_t node;
    cos_string_t part_number;
    cos_string_t size;
    cos_string_t etag;
    cos_string_t last_modified;
} cos_list_part_content_t;

typedef struct {
    cos_list_t node;
    cos_string_t part_number;
    cos_string_t etag;
} cos_complete_part_content_t;

typedef struct {
    int part_num;
    char *etag;
} cos_upload_part_t;

typedef struct {
    cos_list_t node;
    cos_string_t bucket_name;
    cos_string_t location;
    cos_string_t creation_date;
} cos_get_service_content_t;

typedef struct {
    int all_region;
    cos_string_t owner_id;
    cos_string_t owner_display_name;
    cos_list_t bucket_list;
} cos_get_service_params_t;

typedef struct {
    cos_string_t encoding_type;
    cos_string_t prefix;
    cos_string_t marker;
    cos_string_t delimiter;
    int max_ret;
    int truncated;
    cos_string_t next_marker;
    cos_list_t object_list;
    cos_list_t common_prefix_list;
} cos_list_object_params_t;

typedef struct {
    cos_string_t encoding_type;
    cos_string_t part_number_marker;
    int max_ret;
    int truncated;
    cos_string_t next_part_number_marker;
    cos_list_t part_list;
} cos_list_upload_part_params_t;

typedef struct {
    cos_string_t encoding_type;
    cos_string_t prefix;
    cos_string_t key_marker;
    cos_string_t upload_id_marker;
    cos_string_t delimiter;
    int max_ret;
    int truncated;
    cos_string_t next_key_marker;
    cos_string_t next_upload_id_marker;
    cos_list_t upload_list;
} cos_list_multipart_upload_params_t;

typedef struct {
    cos_string_t copy_source;
    cos_string_t dest_bucket;
    cos_string_t dest_object;
    cos_string_t upload_id;
    int part_num;
    int64_t range_start;
    int64_t range_end;
    cos_copy_object_params_t *rsp_content;
} cos_upload_part_copy_params_t;

typedef struct {
    cos_string_t filename;  /**< file range read filename */
    int64_t file_pos;   /**< file range read start position */
    int64_t file_last;  /**< file range read last position */
} cos_upload_file_t;

typedef struct {
    int days;
    cos_string_t date;
    cos_string_t storage_class;
} cos_lifecycle_expire_t;

typedef struct {
    int days;
    cos_string_t date;
    cos_string_t storage_class;
} cos_lifecycle_transition_t;

typedef struct {
    int days;
} cos_lifecycle_abort_t;

typedef struct {
    cos_list_t node;
    cos_string_t id;
    cos_string_t prefix;
    cos_string_t status;
    cos_lifecycle_expire_t expire;
    cos_lifecycle_transition_t transition;
    cos_lifecycle_abort_t abort;
} cos_lifecycle_rule_content_t;

typedef struct {
    cos_string_t status;
} cos_versioning_content_t;

typedef struct {
    cos_list_t node;
    cos_string_t id;
    cos_string_t allowed_origin;
    cos_string_t allowed_method;
    cos_string_t allowed_header;
    cos_string_t expose_header;
    int max_age_seconds;
} cos_cors_rule_content_t;

typedef struct {
    cos_string_t role;
    cos_list_t rule_list;
} cos_replication_params_t;

typedef struct {
    cos_list_t node;
    cos_string_t id;
    cos_string_t status;
    cos_string_t prefix;
    cos_string_t dst_bucket;
    cos_string_t storage_class;
} cos_replication_rule_content_t;

typedef struct {
    cos_list_t node;
    cos_string_t key;
} cos_object_key_t;

typedef struct {
    char *suffix;
    char *type;
} cos_content_type_t;

typedef struct {
    int64_t  part_size;  // bytes, default 1MB
    int32_t  thread_num;  // default 1
    int      enable_checkpoint; // default disable, false
    cos_string_t checkpoint_path;  // dafault ./filepath.ucp or ./filepath.dcp
} cos_resumable_clt_params_t;

typedef struct {
    int days;
    cos_string_t tier;
} cos_object_restore_params_t;


typedef struct {
    cos_string_t type;
    int32_t frag_duration;
    int32_t frag_count;
    cos_string_t play_list_name;
}cos_live_channel_target_t;

typedef struct {
    cos_string_t name;
    cos_string_t description;
    cos_string_t status;
    cos_live_channel_target_t target;
} cos_live_channel_configuration_t;

typedef struct {
    cos_list_t node;
    cos_string_t publish_url;
} cos_live_channel_publish_url_t;

typedef struct {
    cos_list_t node;
    cos_string_t play_url;
} cos_live_channel_play_url_t;

typedef struct {
    int32_t width;
    int32_t height;
    int32_t frame_rate;
    int32_t band_width;
    cos_string_t codec;
} cos_video_stat_t;

typedef struct {
    int32_t band_width;
    int32_t sample_rate;
    cos_string_t codec;
} cos_audio_stat_t;

typedef struct {
    cos_string_t pushflow_status;
    cos_string_t connected_time;
    cos_string_t remote_addr;
    cos_video_stat_t video_stat;
    cos_audio_stat_t audio_stat;
} cos_live_channel_stat_t;

typedef struct {
    cos_list_t node;
    cos_string_t name;
    cos_string_t description;
    cos_string_t status;
    cos_string_t last_modified;
    cos_list_t publish_url_list;
    cos_list_t play_url_list;
} cos_live_channel_content_t;

typedef struct {
    cos_string_t prefix;
    cos_string_t marker;
    int max_keys;
    int truncated;
    cos_string_t next_marker;
    cos_list_t live_channel_list;
} cos_list_live_channel_params_t;

typedef struct {
    cos_list_t node;
    cos_string_t start_time;
    cos_string_t end_time;
    cos_string_t remote_addr;
} cos_live_record_content_t;

typedef struct {
    cos_string_t index;
    cos_string_t redirect_protocol;
    cos_string_t error_document;
    cos_list_t rule_list;
} cos_website_params_t;

typedef struct {
    cos_list_t node;
    cos_string_t condition_errcode;
    cos_string_t condition_prefix;
    cos_string_t redirect_protocol;
    cos_string_t redirect_replace_key;
    cos_string_t redirect_replace_key_prefix;
} cos_website_rule_content_t;

typedef struct {
    cos_string_t status;
    cos_string_t name;
    cos_string_t type;
    cos_string_t forced_replacement;
} cos_domain_params_t;

typedef struct {
    cos_string_t target_bucket;
    cos_string_t target_prefix;
} cos_logging_params_t;

typedef struct {
    cos_string_t format;
    cos_string_t account_id;
    cos_string_t bucket;
    cos_string_t prefix;
    int encryption;
} cos_inventory_destination_t;

typedef struct {
    cos_list_t node;
    cos_string_t field;
} cos_inventory_optional_t;

typedef struct {
    cos_list_t node;
    cos_string_t id;
    cos_string_t is_enabled;
    cos_string_t frequency;
    cos_string_t filter_prefix;
    cos_string_t included_object_versions;
    cos_inventory_destination_t destination;
    cos_list_t fields;
} cos_inventory_params_t;

typedef struct {
    cos_list_t inventorys;
    int is_truncated;
    cos_string_t continuation_token;
    cos_string_t next_continuation_token;
} cos_list_inventory_params_t;

typedef struct {
    cos_list_t node;
    cos_string_t key;
    cos_string_t value;
} cos_tagging_tag_t;

typedef struct {
    cos_list_t node;
} cos_tagging_params_t;

typedef struct {
    cos_list_t node;
    cos_string_t domain;
} cos_referer_domain_t;

typedef struct {
    cos_string_t status;                // "Enabled" or "Disabled"
    cos_string_t referer_type;          // "Black-List" or "White-List"
    // list type: cos_referer_domain_t
    cos_list_t domain_list;
    cos_string_t empty_refer_config;    // "Allow" or "Deny"(default)
} cos_referer_params_t;

typedef struct {
    cos_string_t status;
    int days;
} cos_intelligenttiering_params_t;

typedef struct {
    cos_string_t format;
    cos_string_t ave;
    int width;
    int height;
    int quality;
    int orientation;
} ci_image_info_t;

typedef struct {
    cos_string_t key;
    cos_string_t location;
    cos_string_t etag;
    ci_image_info_t image_info;
} ci_operation_origin_info_t;

typedef struct {
    cos_list_t node;
    cos_string_t code_url;
    cos_string_t point[4];
} ci_qrcode_info_t;

typedef struct {
    cos_list_t qrcode_info;  
    cos_string_t key;
    cos_string_t location;
    cos_string_t format;
    cos_string_t etag;
    int width;
    int height;
    int size;
    int quality;
    int code_status;
} ci_operation_object_result_t;

typedef struct {
    ci_operation_origin_info_t origin;
    ci_operation_object_result_t object;
} ci_operation_result_t;

typedef struct {
    int code_status;
    cos_list_t qrcode_info;
    cos_string_t result_image;
} ci_qrcode_result_t;

typedef struct {
    cos_string_t mode;
    int count;
    float time_interval;
} ci_video_auditing_job_snapshot_t;

typedef struct {
    cos_string_t detect_type;
    ci_video_auditing_job_snapshot_t snapshot;
    cos_string_t callback;
    cos_string_t callback_version;
    cos_string_t biz_type;
    int detect_content;
} ci_video_auditing_job_conf_t;

typedef struct {
    cos_string_t input_object;
    ci_video_auditing_job_conf_t job_conf;
} ci_video_auditing_job_options_t;

typedef struct {
    cos_string_t job_id;
    cos_string_t state;
    cos_string_t creation_time;
} ci_video_auditing_jobs_detail_t;

typedef struct {
    ci_video_auditing_jobs_detail_t jobs_detail;
} ci_video_auditing_job_result_t;

typedef struct {
    int hit_flag;
    int count;
} ci_auditing_video_info_t;

typedef struct {
    int hit_flag;
    int score;
    cos_string_t label;
    cos_string_t sub_lable;
} ci_auditing_snapshot_info_t;

typedef struct {
    int hit_flag;
    int score;
    cos_string_t key_words;
} ci_auditing_audio_info_t;

typedef struct {
    cos_list_t node;
    cos_string_t url;
    int snapshot_time;
    cos_string_t text;
    
    ci_auditing_snapshot_info_t porn_info;
    ci_auditing_snapshot_info_t terrorism_info;
    ci_auditing_snapshot_info_t politics_info;
    ci_auditing_snapshot_info_t ads_info;
} ci_auditing_snapshot_result_t;

typedef struct {
    cos_list_t node;
    cos_string_t url;
    cos_string_t text;
    int offset_time;
    int duration;

    ci_auditing_audio_info_t porn_info;
    ci_auditing_audio_info_t terrorism_info;
    ci_auditing_audio_info_t politics_info;
    ci_auditing_audio_info_t ads_info;
} ci_auditing_audio_section_result_t;

typedef struct {
    cos_string_t code;
    cos_string_t message;
    cos_string_t job_id;
    cos_string_t state;
    cos_string_t creation_time;
    cos_string_t object;
    cos_string_t snapshot_count;
    int result;

    ci_auditing_video_info_t porn_info;
    ci_auditing_video_info_t terrorism_info;
    ci_auditing_video_info_t politics_info;
    ci_auditing_video_info_t ads_info;

    // list type: ci_auditing_snapshot_result_t
    cos_list_t snapshot_info_list;
    // list type: ci_auditing_audio_section_result_t
    cos_list_t audio_section_info_list;
} ci_get_auditing_jobs_detail_t;

typedef struct {
    ci_get_auditing_jobs_detail_t jobs_detail;
    cos_string_t nonexist_job_ids;
} ci_auditing_job_result_t;

/**
  * @brief  ci_describe_media_buckets() func params
**/
typedef struct {
    cos_string_t regions;
    cos_string_t bucket_names;
    cos_string_t bucket_name;
    cos_string_t page_number;
    cos_string_t page_size;
} ci_media_buckets_request_t;

typedef struct {
    cos_list_t node;
    cos_string_t bucket_id;
    cos_string_t name;
    cos_string_t region;
    cos_string_t create_time;
} ci_media_bucket_list_t;

typedef struct {
    int total_count;
    int page_number;
    int page_size;
    // list type: ci_media_bucket_list_t
    cos_list_t media_bucket_list;
} ci_media_buckets_result_t;

/**
  * @brief  ci_get_snapshot_to_buffer() / ci_get_snapshot_to_file() func params
**/
typedef struct {
    float time;
    int width;
    int height;
    cos_string_t format;   // jpg(default)/png
    cos_string_t rotate;   // auto(default)/off
    cos_string_t mode;     // keyframe/exactframe(default)
} ci_get_snapshot_request_t;

/**
  * @brief  ci_get_media_info() func params
**/
typedef struct {
    int index;
    cos_string_t codec_name;
    cos_string_t codec_long_name;
    cos_string_t codec_time_base;
    cos_string_t codec_tag_string;
    cos_string_t codec_tag;
    cos_string_t profile;
    int height;
    int width;
    int has_b_frame;
    int ref_frames;
    cos_string_t sar;
    cos_string_t dar;
    cos_string_t pix_format;
    cos_string_t field_order;
    int level;
    int fps;
    cos_string_t avg_fps;
    cos_string_t timebase;
    float start_time;
    float duration;
    float bit_rate;
    int num_frames;
    cos_string_t language;
} ci_media_video_t;

typedef struct {
    int index;
    cos_string_t codec_name;
    cos_string_t codec_long_name;
    cos_string_t codec_time_base;
    cos_string_t codec_tag_string;
    cos_string_t codec_tag;
    cos_string_t sample_fmt;
    int sample_rate;
    int channel;
    cos_string_t channel_layout;
    cos_string_t timebase;
    float start_time;
    float duration;
    float bit_rate;
    cos_string_t language;
} ci_media_audio_t;

typedef struct {
    int index;
    cos_string_t language;
} ci_media_subtitle_t;

typedef struct {
    ci_media_video_t video;
    ci_media_audio_t audio;
    ci_media_subtitle_t subtitle;
} ci_media_stream_info_t;

typedef struct {
    int num_stream;
    int num_program;
    cos_string_t format_name;
    cos_string_t format_long_name;
    float start_time;
    float duration;
    int bit_rate;
    int size;
} ci_media_stream_format_t;

typedef struct {
    ci_media_stream_info_t stream;
    ci_media_stream_format_t format;
} ci_media_info_result_t;

#define COS_AUTH_EXPIRE_DEFAULT 300

typedef enum {
    COS_BUCKET_NON_EXIST          = 0,   /*< bucket non-exist*/
    COS_BUCKET_EXIST              = 1,   /*< bucket exist*/
    COS_BUCKET_UNKNOWN_EXIST      = 2,   /*< unknown status, maybe the req of head has no auth or failed */
} cos_bucket_exist_status_e;

typedef enum {
    COS_OBJECT_NON_EXIST          = 0,   /*< object non-exist*/
    COS_OBJECT_EXIST              = 1,   /*< object exist*/
    COS_OBJECT_UNKNOWN_EXIST      = 2,   /*< unknown status, maybe the req of head has no auth or failed */
} cos_object_exist_status_e;

#endif  //  COS_C_SDK_V5_COS_C_SDK_COS_DEFINE_H_
