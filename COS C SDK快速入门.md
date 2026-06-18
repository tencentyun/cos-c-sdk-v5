## 开发准备
### 相关资源
对象存储的 XML C SDK 资源下载地址：[XML C SDK GitHub 下载](https://github.com/tencentyun/cos-c-sdk-v5)。
演示示例 Demo 下载地址：[XML C SDK Demo](https://github.com/tencentyun/cos-c-sdk-v5/blob/master/cos_c_sdk_test/cos_demo.c)。

### 开发环境
1. 安装 CMake 工具（建议 2.6.0 及以上版本），点击 [这里](http://www.cmake.org/download/) 下载，典型安装方式如下：
```bash
./configure
make
make install
```
2. 安装 libcurl（建议 7.32.0 及以上版本），点击 [这里](http://curl.haxx.se/download.html?spm=5176.doc32132.2.7.23MmBq) 下载，典型安装方式如下：
```bash
./configure
make
make install
```
3. 安装 apr（建议 1.5.2 及以上版本），点击 [这里](https://apr.apache.org/download.cgi?spm=5176.doc32132.2.9.23MmBq&file=download.cgi) 下载，典型安装方式如下：
```bash
./configure
make
make install
```
4. 安装 apr-util（建议 1.5.4 及以上版本），点击 [这里](https://apr.apache.org/download.cgi?spm=5176.doc32132.2.10.23MmBq&file=download.cgi) 下载，安装时需要指定— with-apr 选项，典型安装方式如下：
```bash
./configure --with-apr=/your/apr/install/path
make
make install
```
5. 安装 minixml（建议 2.8 及以上版本），点击 [这里](http://www.msweet.org/downloads.php?spm=5176.doc32132.2.11.23MmBq&L+Z3) 下载，典型安装方式如下：
```bash
./configure
make
sudo make install
```

### 安装 SDK
源码安装。从 [GitHub](https://github.com/tencentyun/cos-c-sdk-v5) 下载源码，典型编译命令如下：
```bash
cmake .
make
make install
```

## SDK 初始化
### 初始化 SDK 运行环境
```cpp
int main(int argc, char *argv[])
{
    /* 程序入口处调用 cos_http_io_initialize 方法，这个方法内部会做一些全局资源的初始化，涉及网络，内存等部分 */
    if (cos_http_io_initialize(NULL, 0) != COSE_OK) {
        exit(1);
    }
    
	/* 设置日志级别 */
    cos_log_set_level(COS_LOG_WARN);

    /* 调用 COS SDK 的接口上传或下载文件 */
    /* ... 用户逻辑代码，这里省略 */

    /* 程序结束前，调用 cos_http_io_deinitialize 方法释放之前分配的全局资源 */
    cos_http_io_deinitialize();
    return 0;
}
```

### 初始化请求选项
```cpp
    /* 等价于apr_pool_t，用于内存管理的内存池，实现代码在apr库中 */
    cos_pool_t *pool;
    cos_request_options_t *options;

    /* 重新创建一个新的内存池，第二个参数是NULL，表示没有继承自其它内存池 */
    cos_pool_create(&pool, NULL);

    /* 创建并初始化options，这个参数内部主要包括endpoint,access_key_id,acces_key_secret，is_cname, curl参数等全局配置信息
     * options的内存是由pool分配的，后续释放掉pool后，options的内存也相当于释放掉了，不再需要单独释放内存
     */ 
    options = cos_request_options_create(pool);
    options->config = cos_config_create(options->pool);

    /* cos_str_set是用char*类型的字符串初始化cos_string_t类型*/
    cos_str_set(&options->config->endpoint, "<用户的Endpoint>");              //Endpoint依据用户所在园区的COS服务域名填写
    cos_str_set(&options->config->access_key_id, "<用户的SecretId>");         //用户注册COS服务后所获得的SecretId
    cos_str_set(&options->config->access_key_secret, "<用户的SecretKey>");    //用户注册COS服务后所获得的SecretKey
    cos_str_set(&options->config->appid, "<用户的AppId>");                    //用户注册COS服务后所获得的AppId

    /* 可以通过设置sts_token来使用临时秘钥，当使用临时秘钥时access_key_id和access_key_secret均需要设置为对应临时秘钥所配套的SecretId和SecretKey */
    //cos_str_set(&options->config->sts_token, "MyTokenString");

    /* 是否使用了CNAME */
    options->config->is_cname = 0;

    /* 用于设置网络相关参数，比如超时时间等*/
    options->ctl = cos_http_controller_create(options->pool, 0);

    /* 用于设置上传请求是否自动添加Content-MD5头部，enable为COS_FALSE时上传请求将不自动添加Content-MD5头部，enable为COS_TRUE时上传请求将自动添加Content-MD5头部，如果不设置此项则默认将添加Content-MD5头部 */
    cos_set_content_md5_enable(options->ctl, COS_FALSE);
	
    /* 用于设置请求路由地址和端口，一般情况下无需设置此参数，请求将按域名解析结果路由 */
    //cos_set_request_route(options->ctl, "1.2.3.4", 80);
```

##  SDK 一般使用流程
1. 初始化 SDK。
2. 设置请求选项参数。
关于 APPID、SecretId、SecretKey、Bucket 等名称的含义和获取方式请参考 [COS 术语信息](https://cloud.tencent.com/document/product/436/7751)。
  *  APPID 是申请腾讯云账户后，系统分配的账户标识之一。
  * access_key_id 与 access_key_secret 是账户 API 密钥。
  * endpoint 是 COS 访问域名信息，可以通过腾讯云[【COS 可用地域】](https://cloud.tencent.com/document/product/436/6224) 页面查看。
  例如，广州地区 endpoint 为 cos.ap-guangzhou.myqcloud.com。
3. 设置 API 接口必需的参数。
4. 调用 SDK API 发起请求并获得请求响应结果。

### 创建 Bucket
```cpp
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_acl_e cos_acl = COS_ACL_PRIVATE;
    cos_string_t bucket;
    cos_table_t *resp_headers = NULL;
    
    /* 重新创建一个新的内存池，第二个参数是NULL，表示没有继承自其它内存池 */
    cos_pool_create(&p, NULL);
    
    /* 创建并初始化options，这个参数内部主要包括endpoint,access_key_id,acces_key_secret，is_cname, curl参数等全局配置信息
     * options的内存是由pool分配的，后续释放掉pool后，options的内存也相当于释放掉了，不再需要单独释放内存
     */
    options = cos_request_options_create(p);
    options->config = cos_config_create(options->pool);
    init_test_config(options->config, is_cname);
    
    /* 设置appid，endpoint，access_key_id，acces_key_secret，is_cname, curl参数等配置信息 */
    cos_str_set(&options->config->endpoint, TEST_COS_ENDPOINT);
    cos_str_set(&options->config->access_key_id, TEST_ACCESS_KEY_ID);
    cos_str_set(&options->config->access_key_secret, TEST_ACCESS_KEY_SECRET);
    cos_str_set(&options->config->appid, TEST_APPID);
    options->config->is_cname = is_cname;
    options->ctl = cos_http_controller_create(options->pool, 0);
    /* bucket的命名规则为{name}-{appid} ，此处填写的存储桶名称必须为此格式 */
    cos_str_set(&bucket, TEST_BUCKET_NAME);

    /* 调用api创建bucket */
    s = cos_create_bucket(options, &bucket, cos_acl, &resp_headers);
    if (cos_status_is_ok(s)) {
        printf("create bucket succeeded\n");
    } else {
        printf("create bucket failed\n");
    }
    
    //destroy memory pool
    cos_pool_destroy(p); 
```

### 上传文件
```cpp
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t file;
    cos_table_t *resp_headers = NULL;
    
    /* 重新创建一个新的内存池，第二个参数是NULL，表示没有继承自其它内存池 */
    cos_pool_create(&p, NULL);
    
    /* 创建并初始化options，这个参数内部主要包括endpoint,access_key_id,acces_key_secret，is_cname, curl参数等全局配置信息
     * options的内存是由pool分配的，后续释放掉pool后，options的内存也相当于释放掉了，不再需要单独释放内存
     */
    options = cos_request_options_create(p);
    options->config = cos_config_create(options->pool);
    init_test_config(options->config, is_cname);

    /* 设置appid，endpoint，access_key_id，acces_key_secret，is_cname, curl参数等配置信息 */
    cos_str_set(&options->config->endpoint, TEST_COS_ENDPOINT);
    cos_str_set(&options->config->access_key_id, TEST_ACCESS_KEY_ID);
    cos_str_set(&options->config->access_key_secret, TEST_ACCESS_KEY_SECRET);
    cos_str_set(&options->config->appid, TEST_APPID);
    options->config->is_cname = is_cname;
    options->ctl = cos_http_controller_create(options->pool, 0);
    /* bucket的命名规则为{name}-{appid} ，此处填写的存储桶名称必须为此格式 */
    cos_str_set(&bucket, TEST_BUCKET_NAME);

    /* 调用api上传文件 */
    cos_str_set(&file, TEST_DOWNLOAD_NAME);
    cos_str_set(&object, TEST_OBJECT_NAME);
    s = cos_put_object_from_file(options, &bucket, &object, &file, NULL, &resp_headers);
    if (cos_status_is_ok(s)) {
        printf("put object succeeded\n");
    } else {
        printf("put object failed\n");
    }
    
    //destroy memory pool
    cos_pool_destroy(p); 
```

### 下载文件
```cpp
    cos_pool_t *p = NULL;
    int is_cname = 0;
    cos_status_t *s = NULL;
    cos_request_options_t *options = NULL;
    cos_string_t bucket;
    cos_string_t object;
    cos_string_t file;
    cos_table_t *resp_headers = NULL;
    
    /* 重新创建一个新的内存池，第二个参数是NULL，表示没有继承自其它内存池 */
    cos_pool_create(&p, NULL);
    
    /* 创建并初始化options，这个参数内部主要包括endpoint,access_key_id,acces_key_secret，is_cname, curl参数等全局配置信息
     * options的内存是由pool分配的，后续释放掉pool后，options的内存也相当于释放掉了，不再需要单独释放内存
     */
    options = cos_request_options_create(p);
    options->config = cos_config_create(options->pool);
    init_test_config(options->config, is_cname);

    /* 设置appid，endpoint，access_key_id，acces_key_secret，is_cname, curl参数等配置信息 */
    cos_str_set(&options->config->endpoint, TEST_COS_ENDPOINT);
    cos_str_set(&options->config->access_key_id, TEST_ACCESS_KEY_ID);
    cos_str_set(&options->config->access_key_secret, TEST_ACCESS_KEY_SECRET);
    cos_str_set(&options->config->appid, TEST_APPID);
    options->config->is_cname = is_cname;
    options->ctl = cos_http_controller_create(options->pool, 0);
    /* bucket的命名规则为{name}-{appid} ，此处填写的存储桶名称必须为此格式 */
    cos_str_set(&bucket, TEST_BUCKET_NAME);

    /* 调用api下载文件 */
    cos_str_set(&file, TEST_DOWNLOAD_NAME);
    cos_str_set(&object, TEST_OBJECT_NAME);
    s = cos_get_object_to_file(options, &bucket, &object, NULL, NULL, &file, &resp_headers);
    if (cos_status_is_ok(s)) {
        printf("get object succeeded\n");
    } else {
        printf("get object failed\n");
    }
    
    //destroy memory pool
    cos_pool_destroy(p); 
```


## SDK 编译选项

SDK 的编译选项在仓库根目录的 `CMakeLists.txt` 中定义，可用于控制连接保活、连接复用时长以及重试时是否使用新连接等行为。

| 编译选项 | 默认值 | 说明 |
|---------|--------|------|
| `COS_ENABLE_TCP_KEEPALIVE` | `ON` | 是否启用 libcurl TCP keepalive。启用后会设置 `CURLOPT_TCP_KEEPALIVE`，并使用 `COS_TCP_KEEPIDLE` 和 `COS_TCP_KEEPINTVL` 控制探测时间。该选项依赖 libcurl 7.25.0 及以上版本。 |
| `COS_TCP_KEEPIDLE` | `30` | TCP keepalive 空闲探测时间，单位为秒，仅在 `COS_ENABLE_TCP_KEEPALIVE=ON` 时生效。 |
| `COS_TCP_KEEPINTVL` | `30` | TCP keepalive 探测间隔，单位为秒，仅在 `COS_ENABLE_TCP_KEEPALIVE=ON` 时生效。 |
| `COS_ENABLE_MAXAGE_CONN` | `ON` | 是否限制可复用连接的最大存活时间。启用后 SDK 会清理超过 `COS_MAXAGE_CONN` 的缓存连接，并在 libcurl 7.65.0 及以上版本设置 `CURLOPT_MAXAGE_CONN`。 |
| `COS_MAXAGE_CONN` | `90` | 可复用连接的最大存活时间，单位为秒，仅在 `COS_ENABLE_MAXAGE_CONN=ON` 时生效。 |
| `COS_ENABLE_RETRY_FRESH_CONNECT` | `ON` | 重试请求时是否强制使用新连接。启用后，部分重试场景会重新初始化 curl 连接，并在 libcurl 支持时设置 `CURLOPT_FRESH_CONNECT` 和 `CURLOPT_FORBID_REUSE`。 |

布尔开关使用 `option()` 定义，时间类参数使用 `CACHE STRING` 定义，均可以在执行 `cmake` 时通过 `-D` 参数覆盖默认值，例如：

```bash
mkdir -p build
cd build
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DCOS_ENABLE_TCP_KEEPALIVE=ON \
    -DCOS_TCP_KEEPIDLE=60 \
    -DCOS_TCP_KEEPINTVL=30 \
    -DCOS_ENABLE_MAXAGE_CONN=ON \
    -DCOS_MAXAGE_CONN=120 \
    -DCOS_ENABLE_RETRY_FRESH_CONNECT=ON
make
sudo make install
```


布尔开关使用 `ON` 或 `OFF`，时间类参数单位均为秒。若已在同一个构建目录执行过 `cmake`，旧值可能保存在 `CMakeCache.txt` 中；修改默认值后，建议重新执行 `cmake` 并通过 `-D` 明确覆盖，或清理构建目录后重新生成。



## SDK 使用注意事项

### 多线程场景

需要注意的是，COS C SDK 内存池使用了 apr 库的 apr_pool，apr_pool 大多数操作都不是线程安全的。

```c
/* apr_pools.h
* Note that most operations on pools are not thread-safe: a single pool
* should only be accessed by a single thread at any given time. The one
* exception to this rule is creating a subpool of a given pool: one or more
* threads can safely create subpools at the same time that another thread
* accesses the parent pool.
/
```

在多线程场景下，建议遵循以下原则：

- 一个 pool 同一时间只归一个线程使用；
- 可以创建多个 pool，每个线程使用一个 pool；
- 需要时，可以创建子 pool，用于临时使用，使用完毕后销毁，需注意子 pool 会随着父 pool 的销毁而销毁；
- 父 pool 中只读数据可以被多个线程引用，但必须保证父 pool 生命周期覆盖所有线程。


此外，每次请求所需的 `cos_request_options_t *optins` 结构的全部三个字段：`config`, `ctl`, `pool` 均应该独立创建，不要共用。