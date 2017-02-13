#include <iostream>
#include <vector>

#include "handlers.h"
#include "mtools.h"

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

void helpHandler(const char *cmdline, std::stringstream& arguments, folder &cwd) {
    using namespace std;
    cout << "Commands list:" << endl
        << "  help     - Print this help message." << endl
        << "  ls       - List directory contents." << endl
        << "  tree     - List directory contents recursively." << endl
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

void lsHandler(const char *cmdline, std::stringstream& arguments, folder &cwd) {
    using namespace std;

    cout << ANSI_COLOR_BLUE;
    for(folder *optfolder : cwd.folders)
    {
        cout << optfolder->name << "\t";
    }
    cout << ANSI_COLOR_RESET;
    
    cout << ANSI_COLOR_CYAN;
    for(string opts : cwd.files)
    {
        cout << opts << "\t";
    }
    cout << ANSI_COLOR_RESET << endl;
}


void cdHandler(const char *cmdline, std::stringstream& arguments, folder &cwd) {
    using namespace std;

    string dest;
    arguments >> dest;
    
    if (moveToPath(dest, cwd))
        cout << ANSI_COLOR_RED 
             << "No such file or directory"
             << ANSI_COLOR_RESET
             << endl;
}

void pwdHandler(const char *cmdline, std::stringstream& arguments, folder &cwd) {
    using namespace std;
    cout << cwd.getPath() << endl;
}

void treeHandler(const char *cmdline, std::stringstream& arguments, folder &cwd) {
    using namespace std;

    folder tempcwd = cwd;
    string dest;
    arguments >> dest;

    if (dest!="" && moveToPath(dest, tempcwd))
        cout << ANSI_COLOR_RED
             << "No such file or directory"
             << ANSI_COLOR_RESET
             << endl;

    showChild(tempcwd, string(""));
}
