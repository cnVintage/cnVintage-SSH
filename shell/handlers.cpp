#include <iostream>

#include "handlers.h"

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

void helpHandler(const char *cmdline, std::stringstream& arguments, std::string &cwd) {
    using namespace std;
    cout << "Commands list:" << endl
            << "  help     - Print this help message." << endl
            << "  ls       - List directory contents." << endl
            << "  cd       - Change current directory." << endl
            << "  cat      - Concatenate files and print on the standard output." << endl
            << "  pwd      - Print current directory." << endl
            << "  whoami   - Print effective userid." << endl
            << "  exit     - Exit cnVintage." << endl;
}

/**
 *  Fake filesystem:
 *  /
 *  +- discussions
 *  |  +- all
 *  |  +- by-tag
 *  |
 *  +- users
 */
void lsHandler(const char *cmdline, std::stringstream& arguments, std::string &cwd) {
    using namespace std;

    // FIXME: rewrite this stupid code.
    if (cwd == "/") {
        cout << ANSI_COLOR_BLUE << "discussions\tusers" << ANSI_COLOR_RESET << endl;
    } else if (cwd == "/discussions") {
        cout << ANSI_COLOR_BLUE << "all\tby-tag" << ANSI_COLOR_RESET << endl;
    } else if (cwd == "/discussions/all") {
        cout << ANSI_COLOR_RED << "ERROR: not implemented" << ANSI_COLOR_RESET << endl;
    } else if (cwd == "/discussions/by-tag") {
        cout << ANSI_COLOR_RED << "ERROR: not implemented" << ANSI_COLOR_RESET << endl;
    } else if (cwd == "/users") {
        cout << ANSI_COLOR_RED << "ERROR: not implemented" << ANSI_COLOR_RESET << endl;
    }
}


void cdHandler(const char *cmdline, std::stringstream& arguments, std::string &cwd) {
    using namespace std;
    
    // FIXME: rewrite this stupid code.
    string dest;
    arguments >> dest;
    if (dest[0] == '/') {
        cwd = dest;
    } else if (dest == ".") {
        return;
    } else if (dest == "..") {
        string parent = cwd.substr(0, cwd.find_last_of('/'));
        cwd = parent;
        if (cwd == "") {
            cwd = "/";
        }
    }
}

void pwdHandler(const char *cmdline, std::stringstream& arguments, std::string &cwd) {
    using namespace std;
    cout << cwd << endl;
}