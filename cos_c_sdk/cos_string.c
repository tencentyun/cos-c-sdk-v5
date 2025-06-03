#include "cos_string.h"

typedef int (*cos_is_char_pt)(char c);

static void cos_strip_str_func(cos_string_t *str, cos_is_char_pt func);

char *cos_pstrdup(cos_pool_t *p, const cos_string_t *s) {
    return apr_pstrndup(p, s->data, s->len);
}

static void cos_strip_str_func(cos_string_t *str, cos_is_char_pt func) {
    char *data = str->data;
    int len = str->len;
    int offset = 0;

    if (len == 0) return;

    while (len > 0 && func(data[len - 1])) {
        --len;
    }

    for (; offset < len && func(data[offset]); ++offset) {
        // empty;
    }

    str->data = data + offset;
    str->len = len - offset;
}

void cos_unquote_str(cos_string_t *str) {
    cos_strip_str_func(str, cos_is_quote);
}

void cos_strip_space(cos_string_t *str) {
    cos_strip_str_func(str, cos_is_space);
}

void cos_trip_space_and_cntrl(cos_string_t *str) {
    cos_strip_str_func(str, cos_is_space_or_cntrl);
}

int cos_ends_with(const cos_string_t *str, const cos_string_t *suffix) {
    if (!str || !suffix) {
        return 0;
    }

    return (str->len >= suffix->len) && strncmp(str->data + str->len - suffix->len, suffix->data, suffix->len) == 0;
}
