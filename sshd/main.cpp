#include <string>
#include <iostream>

#include "server.h"
#include "flarum-login.h"

int main(int __attribute__((unused)) argc, char ** __attribute__((unused)) argv) {
	SshServer server(std::string("0.0.0.0"), std::string("2022"));
	server.authMethod = [] (std::string user, std::string pass) {
		std::string token = "";
		return tryLogin_WebApi(user, pass, token);
	};
	server.start();
	return 0;
}
