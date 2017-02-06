#pragma once

#include <string>
#include <sstream>

void helpHandler(const char *cmdline, std::stringstream& arguments, std::string &cwd);
void lsHandler  (const char *cmdline, std::stringstream& arguments, std::string &cwd);
void cdHandler  (const char *cmdline, std::stringstream& arguments, std::string &cwd);
void pwdHandler (const char *cmdline, std::stringstream& arguments, std::string &cwd);

