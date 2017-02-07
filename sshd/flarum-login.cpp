#include <iostream>
#include <curl/curl.h>
/*
#include <mysql_connection.h>

#include <cppconn/driver.h>
#include <cppconn/exception.h>
#include <cppconn/resultset.h>
#include <cppconn/statement.h>
*/
#include "flarum-login.h"

size_t fetchResponse(void *contents, size_t size, size_t nmemb, std::string *s) {
    size_t newLength = size*nmemb;
    size_t oldLength = s->size();
    s->resize(oldLength + newLength);

    std::copy((char*)contents,(char*)contents+newLength,s->begin()+oldLength);
    return size*nmemb;
}

bool tryLogin_WebApi(std::string user, std::string pass, std::string &token) {
    static bool hasInit = false;

    token = "";

    if (!hasInit) {
        curl_global_init(CURL_GLOBAL_ALL);
    }

    CURL *curl;
    if ((curl = curl_easy_init()) == nullptr) {
        std::cerr << "curl_easy_init() failed." << std::endl;
        return false;
    }

    struct curl_slist *headers = nullptr;
    std::string response;

    std::string dataFields = "{\"identification\":\"" + user + "\",\"password\":\"" + pass + "\"}";
    headers = curl_slist_append(headers, "Content-Type: application/json; charset=UTF-8");
    curl_easy_setopt(curl, CURLOPT_URL, "http://ntzyz-solaris.lan/login");
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, dataFields.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, dataFields.length());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, fetchResponse);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);

    if (response.find("permission_denied") != std::string::npos) {
        return false;
    }

    std::cout << response << response.find("permission_denied") << std::endl;
    return true;
}

bool tryLogin_Direct(std::string user, std::string pass) {
    // TODO
    return false;
}