#pragma once
#include <iostream>
#include <functional>
#include <string>
#include <chrono>
#include <thread>

#include <pty.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <stdio.h>
#include <utmp.h>
#include <poll.h>

#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>

const uint32_t buffer_size = 1048576;

struct channel_data_struct {
	pid_t pid;
	socket_t pty_master;
	socket_t pty_slave;
	socket_t child_stdin;
	socket_t child_stdout;
	socket_t child_stderr;
	ssh_event event;
	struct winsize *winsize;
};

struct session_data_struct {
	ssh_channel channel;
	int auth_attempts;
	int authenticated;
	void *server_instance;
	char access_token[50];
};

class SshServer {
private:
	std::string serverAddr;
	std::string serverPort;
	ssh_bind bind;
	ssh_session session;
	ssh_event event;
	struct sigaction sa;

	void setBind();
	void setSigaction();
	void removeSigaction();
	void handleSession(ssh_event event, ssh_session session);
	static void sigchldHandler(int __attribute__((unused)) signo);
	static int onPtyRequest(ssh_session __attribute__((unused)) session, ssh_channel __attribute__((unused)) channel, const char * __attribute__((unused)) term, int cols, int rows, int py, int px, void *userdata);
	static int onPtyResize(ssh_session __attribute__((unused)) session, ssh_channel __attribute__((unused)) channel, int cols, int rows, int py, int px, void *userdata);
	static int onShellRequest(ssh_session __attribute__((unused)) session, ssh_channel __attribute__((unused)) channel, void *userdata);
	static int onExecRequest(ssh_session __attribute__((unused)) session, ssh_channel __attribute__((unused)) channel, const char *command, void *userdata);
	static int onData(ssh_session __attribute__((unused)) session, ssh_channel __attribute__((unused)) channel, void *data, uint32_t len, int __attribute__((unused)) is_stderr, void *userdata);
	static int onSubsystemRequest(ssh_session __attribute__((unused)) session, ssh_channel __attribute__((unused)) channel, const char * __attribute__((unused)) subsystem, void * __attribute__((unused)) userdata);
	static int execPty(const char *mode, const char *command, struct channel_data_struct *cdata);
	static int execNoPty(const char *command, struct channel_data_struct *cdata);
	static int onAuthPasswd(ssh_session __attribute__((unused)) session, const char *user, const char *pass, void *userdata);
	static ssh_channel onChannelOpen(ssh_session session, void *userdata);
	static int process_stderr(socket_t fd, int revents, void *userdata);
	static int process_stdout(socket_t fd, int revents, void *userdata);
public:
	std::function<bool(std::string, std::string)> authMethod;
	SshServer(std::string addr, std::string port);
	void start();
};