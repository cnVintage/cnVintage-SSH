#include <iostream>
#include <string>
#include <sstream>

// #include <mysql_connection.h>
// #include <cppconn/driver.h>
// #include <cppconn/exception.h>
// #include <cppconn/resultset.h>
// #include <cppconn/statement.h>

#include <readline/readline.h>
#include <readline/history.h>

#include <signal.h>

#include "handlers.h"

const char *motd = "Welcome to:\n"
                   "          __     ___       _                   \n"
                   "   ___ _ _\\ \\   / (_)_ __ | |_ __ _  __ _  ___ \n"
                   "  / __| '_ \\ \\ / /| | '_ \\| __/ _` |/ _` |/ _ \\\n"
                   " | (__| | | \\ V / | | | | | || (_| | (_| |  __/\n"
                   "  \\___|_| |_|\\_/  |_|_| |_|\\__\\__,_|\\__, |\\___|\n"
                   "                                    |___/      \n"
                   "Type help to to get support on commands and navigation.\n";

static void CtrlC(int sig) {
    printf("\n");
    rl_on_new_line();
    rl_replace_line("", 0);
    rl_redisplay();
}

void executeCommands(const char *input, std::string &cwd) {
    using namespace std;
    stringstream ss(input);
    string baseCommand;
    ss >> baseCommand;

    if (baseCommand == string("help")) {
        helpHandler(input, ss, cwd);
    } else if (baseCommand == string("ls")) {
        lsHandler(input, ss, cwd);
    } else if (baseCommand == string("cd")) {
        cdHandler(input, ss, cwd);
    } else if (baseCommand == string("pwd")) {
        pwdHandler(input, ss, cwd);
    } else {
        cout << "cnVintage: command not found: " << baseCommand << endl;
    }
}

int main(int argc, char **argv) {
    if (argc == 1) {
        std::cerr << "INVALID LOGIN" << std::endl;
        return 1;
    }
    else {
        std::cout << "Access token: " << argv[1] << std::endl;
    }


    if (signal(SIGINT, CtrlC) == SIG_ERR) {
        return 1;
    }

    char *buf = nullptr;
    std::string cwd = "/";

    std::cout << motd << std::endl;
    while ((buf = readline("cnVintage% ")) != nullptr) {
        if (*buf)
            add_history(buf);
        executeCommands(buf, cwd);
    }

    free(buf);

    return 0;
}