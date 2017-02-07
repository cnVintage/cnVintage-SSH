#pragma once

#include <string>

bool tryLogin_WebApi(std::string user, std::string pass, std::string &token);
bool tryLogin_Direct(std::string user, std::string pass);
