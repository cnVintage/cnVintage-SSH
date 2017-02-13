#pragma once

#include <string>
#include <sstream>
#include "mtools.h"

void helpHandler(const char *cmdline, std::stringstream& arguments, folder &cwd);
void lsHandler  (const char *cmdline, std::stringstream& arguments, folder &cwd);
void cdHandler  (const char *cmdline, std::stringstream& arguments, folder &cwd);
void pwdHandler (const char *cmdline, std::stringstream& arguments, folder &cwd);
void treeHandler(const char *cmdline, std::stringstream& arguments, folder &cwd);
