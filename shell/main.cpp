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
#include "mtools.h"

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

int executeCommands(const char *input, folder &cwd) {
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
	} else if (baseCommand == string("tree")) {
		treeHandler(input, ss, cwd);
    } else if (baseCommand == string("exit")){
		cout << "Bye" << endl;
		return -1;
	} else {
		cout << "cnVintage: command not found: " << baseCommand << endl;
	}

	return 0;
}

folder* initFileSystem() {
	using namespace std;
	folder *root = new folder("/");
	folder *discussions = new folder("discussions");
	folder *users = new folder("users");
	folder *all = new folder("all");
	folder *by_tag = new folder("by-tag");
	discussions->addClip(*all);
	discussions->addClip(*by_tag);
	root->addClip(*discussions);
	root->addClip(*users);

	return root;
}

int main(int argc, char **argv) {
	using namespace std;

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
	folder *fileSystem = initFileSystem();
	folder cwd = *fileSystem;
    
	cout << motd << endl;
    while ((buf = readline("cnVintage% ")) != nullptr) {
        if (*buf)
            add_history(buf);
		if (executeCommands(buf, cwd) == -1)
			break;
    }

    free(buf);
	fileSystem->dispose();
    
    return 0;
}
