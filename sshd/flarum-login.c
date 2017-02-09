#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#include "flarum-login.h"

#define TOKEN_LENGTH 128
#define POST_FILED_SIZE 8192

typedef struct {
    char *content;
    size_t buff_size;
} string_t;

void init_string(string_t *s) {
    s->buff_size = 0;
    s->content = (char *) malloc(s->buff_size + 1);
    s->content[s->buff_size] = '\0';
}

size_t fetchResponse(void *contents, size_t size, size_t nmemb, string_t *s) {
    size_t newLength = size * nmemb;
    size_t oldLength = s->buff_size;
    s->content = (char *) realloc(s->content, oldLength + newLength + 1);
    memcpy(s->content + s->buff_size, contents, newLength);
    s->content[oldLength + newLength] = '\0';
    return size * nmemb;
}

char *tryLogin_WebApi(const char *user, const char *pass) {
    static int hasInit = 0;

    if (!hasInit) {
        curl_global_init(CURL_GLOBAL_ALL);
        hasInit = 1;
    }

    CURL *curl;
    if ((curl = curl_easy_init()) == NULL) {
        return NULL;
    }

    char *token = (char *) malloc(TOKEN_LENGTH);


    struct curl_slist *headers = NULL;
    string_t response;
    init_string(&response);
    char data_fields[POST_FILED_SIZE];
    sprintf(data_fields, "{\"identification\":\"%s\",\"password\":\"%s\"}", user, pass);
    headers = curl_slist_append(headers, "Content-Type: application/json; charset=UTF-8");
    curl_easy_setopt(curl, CURLOPT_URL, "https://www.cnvintage.org/login");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data_fields);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(data_fields));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fetchResponse);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode __attribute__((unused)) res = curl_easy_perform(curl);

    puts(response.content);
    if (strstr(response.content, "permission_denied")) {
        return NULL;
    }

    free(response.content);

    return token;
}
