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
	/* pid of the child process the channel will spawn. */
	pid_t pid;
	/* For PTY allocation */
	socket_t pty_master;
	socket_t pty_slave;
	/* For communication with the child process. */
	socket_t child_stdin;
	socket_t child_stdout;
	/* Only used for subsystem and exec requests. */
	socket_t child_stderr;
	/* Event which is used to poll the above descriptors. */
	ssh_event event;
	/* Terminal size struct. */
	struct winsize *winsize;
};

struct session_data_struct {
	/* Pointer to the channel the session will allocate. */
	ssh_channel channel;
	int auth_attempts;
	int authenticated;
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
	static void sigchldHandler(int __attribute__((unused)) signo) {
		while (waitpid(-1, nullptr, WNOHANG) > 0)
			std::this_thread::sleep_for(std::chrono::milliseconds(10));
	}
	static void handleSession(ssh_event event, ssh_session session) {
		struct winsize wsize = {
		ws_row: 0,
				ws_col : 0,
			ws_xpixel : 0,
			ws_ypixel : 0
		};
		struct channel_data_struct cdata = {
		pid: 0,
			 pty_master : -1,
			pty_slave : -1,
			child_stdin : -1,
			child_stdout : -1,
			child_stderr : -1,
			event : nullptr,
			winsize : &wsize
		};
		struct session_data_struct sdata = {
		channel: nullptr,
				 auth_attempts : 0,
			authenticated : 0
		};
		struct ssh_channel_callbacks_struct channel_cb;
		channel_cb.userdata = &cdata;
		channel_cb.channel_pty_request_function = SshServer::onPtyRequest;
		channel_cb.channel_pty_window_change_function = SshServer::onPtyResize;
		channel_cb.channel_shell_request_function = SshServer::onShellRequest;
		channel_cb.channel_exec_request_function = SshServer::onExecRequest;
		channel_cb.channel_data_function = SshServer::onData;
		channel_cb.channel_subsystem_request_function = SshServer::OnSubsystemRequest;

		struct ssh_server_callbacks_struct server_cb;
		server_cb.userdata = &sdata;
		server_cb.auth_password_function = SshServer::auth_password;
		server_cb.channel_open_request_session_function = SshServer::channel_open;

		ssh_callbacks_init(&server_cb);
		ssh_callbacks_init(&channel_cb);

		ssh_set_server_callbacks(session, &server_cb);

		if (ssh_handle_key_exchange(session) != SSH_OK) {
			fprintf(stderr, "%s\n", ssh_get_error(session));
			return;
		}

		ssh_set_auth_methods(session, SSH_AUTH_METHOD_PASSWORD);
		ssh_event_add_session(event, session);

		int n = 0, rc;
		while (sdata.authenticated == 0 || sdata.channel == NULL) {
			/* If the user has used up all attempts, or if he hasn't been able to
			* authenticate in 10 seconds (n * 100ms), disconnect. */
			if (sdata.auth_attempts >= 3 || n >= 100) {
				return;
			}

			if (ssh_event_dopoll(event, 100) == SSH_ERROR) {
				std::cerr << ssh_get_error(session) << std::endl;
				return;
			}
			n++;
		}

		ssh_set_channel_callbacks(sdata.channel, &channel_cb);

		do {
			/* Poll the main event which takes care of the session, the channel and
			* even our child process's stdout/stderr (once it's started). */
			if (ssh_event_dopoll(event, -1) == SSH_ERROR) {
				ssh_channel_close(sdata.channel);
			}

			/* If child process's stdout/stderr has been registered with the event,
			* or the child process hasn't started yet, continue. */
			if (cdata.event != NULL || cdata.pid == 0) {
				continue;
			}
			/* Executed only once, once the child process starts. */
			cdata.event = event;
			/* If stdout valid, add stdout to be monitored by the poll event. */
			if (cdata.child_stdout != -1) {
				if (ssh_event_add_fd(event, cdata.child_stdout, POLLIN, process_stdout,
					sdata.channel) != SSH_OK) {
					fprintf(stderr, "Failed to register stdout to poll context\n");
					ssh_channel_close(sdata.channel);
				}
			}

			/* If stderr valid, add stderr to be monitored by the poll event. */
			if (cdata.child_stderr != -1) {
				if (ssh_event_add_fd(event, cdata.child_stderr, POLLIN, process_stderr,
					sdata.channel) != SSH_OK) {
					fprintf(stderr, "Failed to register stderr to poll context\n");
					ssh_channel_close(sdata.channel);
				}
			}
		} while (ssh_channel_is_open(sdata.channel) &&
			(cdata.pid == 0 || waitpid(cdata.pid, &rc, WNOHANG) == 0));

		close(cdata.pty_master);
		close(cdata.child_stdin);
		close(cdata.child_stdout);
		close(cdata.child_stderr);

		/* Remove the descriptors from the polling context, since they are now
		* closed, they will always trigger during the poll calls. */
		ssh_event_remove_fd(event, cdata.child_stdout);
		ssh_event_remove_fd(event, cdata.child_stderr);

		/* If the child process exited. */
		if (kill(cdata.pid, 0) < 0 && WIFEXITED(rc)) {
			rc = WEXITSTATUS(rc);
			ssh_channel_request_send_exit_status(sdata.channel, rc);
			/* If client terminated the channel or the process did not exit nicely,
			* but only if something has been forked. */
		}
		else if (cdata.pid > 0) {
			kill(cdata.pid, SIGKILL);
		}

		ssh_channel_send_eof(sdata.channel);
		ssh_channel_close(sdata.channel);

		/* Wait up to 5 seconds for the client to terminate the session. */
		for (n = 0; n < 50 && (ssh_get_status(session) & (SSH_CLOSED | SSH_CLOSED_ERROR)) == 0; n++) {
			ssh_event_dopoll(event, 100);
		}
	}

	static int onPtyRequest(ssh_session __attribute__((unused)) session, ssh_channel __attribute__((unused)) channel, const char * __attribute__((unused)) term, int cols, int rows, int py, int px, void *userdata) {
		struct channel_data_struct *cdata = (struct channel_data_struct *)userdata;

		cdata->winsize->ws_row = rows;
		cdata->winsize->ws_col = cols;
		cdata->winsize->ws_xpixel = px;
		cdata->winsize->ws_ypixel = py;

		if (openpty(&cdata->pty_master, &cdata->pty_slave, nullptr, nullptr, cdata->winsize) != 0) {
			std::cerr << "Failed to open pty" << std::endl;
			return SSH_ERROR;
		}
		return SSH_OK;
	}

	static int onPtyResize(ssh_session __attribute__((unused)) session, ssh_channel __attribute__((unused)) channel, int cols, int rows, int py, int px, void *userdata) {
		struct channel_data_struct *cdata = (struct channel_data_struct *)userdata;
		cdata->winsize->ws_row = rows;
		cdata->winsize->ws_col = cols;
		cdata->winsize->ws_xpixel = px;
		cdata->winsize->ws_ypixel = py;

		if (cdata->pty_master != -1) {
			return ioctl(cdata->pty_master, TIOCSWINSZ, cdata->winsize);
		}

		return SSH_ERROR;
	}
	static int onShellRequest(ssh_session session, ssh_channel channel, void *userdata) {
		struct channel_data_struct *cdata = (struct channel_data_struct *) userdata;

		(void)session;
		(void)channel;

		if (cdata->pid > 0) {
			return SSH_ERROR;
		}

		if (cdata->pty_master != -1 && cdata->pty_slave != -1) {
			return SshServer::execPty("", NULL, cdata);
		}
		/* Client requested a shell without a pty, let's pretend we allow that */
		return SSH_OK;
	}
	static int onExecRequest(ssh_session session, ssh_channel channel, const char *command, void *userdata) {
		struct channel_data_struct *cdata = (struct channel_data_struct *) userdata;

		(void)session;
		(void)channel;

		if (cdata->pid > 0) {
			return SSH_ERROR;
		}

		if (cdata->pty_master != -1 && cdata->pty_slave != -1) {
			return SshServer::execPty("-c", command, cdata);
		}
		return exec_nopty(command, cdata);
	}
	static int onData(ssh_session session, ssh_channel channel, void *data, uint32_t len, int is_stderr, void *userdata) {
		struct channel_data_struct *cdata = (struct channel_data_struct *) userdata;

		(void)session;
		(void)channel;
		(void)is_stderr;

		if (len == 0 || cdata->pid < 1 || kill(cdata->pid, 0) < 0) {
			return 0;
		}

		return write(cdata->child_stdin, (char *)data, len);
	}
	static int OnSubsystemRequest(ssh_session session, ssh_channel channel, const char *subsystem, void *userdata) {
		return SSH_ERROR;
	}
	static int execPty(const char *mode, const char *command, struct channel_data_struct *cdata) {
		switch (cdata->pid = fork()) {
		case -1:
			close(cdata->pty_master);
			close(cdata->pty_slave);
			fprintf(stderr, "Failed to fork\n");
			return SSH_ERROR;
		case 0:
			close(cdata->pty_master);
			if (login_tty(cdata->pty_slave) != 0) {
				exit(1);
			}
			execl(SHELL, SHELL, NULL);
			exit(0);
		default:
			close(cdata->pty_slave);
			/* pty fd is bi-directional */
			cdata->child_stdout = cdata->child_stdin = cdata->pty_master;
		}
		return SSH_OK;
	}
	static int exec_nopty(const char *command, struct channel_data_struct *cdata) {
		int in[2], out[2], err[2];

		/* Do the plumbing to be able to talk with the child process. */
		if (pipe(in) != 0) {
			goto stdin_failed;
		}
		if (pipe(out) != 0) {
			goto stdout_failed;
		}
		if (pipe(err) != 0) {
			goto stderr_failed;
		}

		switch (cdata->pid = fork()) {
		case -1:
			goto fork_failed;
		case 0:
			/* Finish the plumbing in the child process. */
			close(in[1]);
			close(out[0]);
			close(err[0]);
			dup2(in[0], STDIN_FILENO);
			dup2(out[1], STDOUT_FILENO);
			dup2(err[1], STDERR_FILENO);
			close(in[0]);
			close(out[1]);
			close(err[1]);
			/* exec the requested command. */
			execl("/bin/sh", "sh", "-c", command, NULL);
			exit(0);
		}

		close(in[0]);
		close(out[1]);
		close(err[1]);

		cdata->child_stdin = in[1];
		cdata->child_stdout = out[0];
		cdata->child_stderr = err[0];

		return SSH_OK;

	fork_failed:
		close(err[0]);
		close(err[1]);
	stderr_failed:
		close(out[0]);
		close(out[1]);
	stdout_failed:
		close(in[0]);
		close(in[1]);
	stdin_failed:
		return SSH_ERROR;
	}
	static int auth_password(ssh_session session, const char *user, const char *pass, void *userdata) {
		struct session_data_struct *sdata = (struct session_data_struct *) userdata;

		(void)session;

		if (1) {
			sdata->authenticated = 1;
			return SSH_AUTH_SUCCESS;
		}

		sdata->auth_attempts++;
		return SSH_AUTH_DENIED;
	}
	static ssh_channel channel_open(ssh_session session, void *userdata) {
		struct session_data_struct *sdata = (struct session_data_struct *) userdata;

		sdata->channel = ssh_channel_new(session);
		return sdata->channel;
	}
	static int process_stderr(socket_t fd, int revents, void *userdata) {
		char buf[buffer_size];
		int n = -1;
		ssh_channel channel = (ssh_channel)userdata;

		if (channel != NULL && (revents & POLLIN) != 0) {
			n = read(fd, buf, buffer_size);
			if (n > 0) {
				ssh_channel_write_stderr(channel, buf, n);
			}
		}

		return n;
	}
	static int process_stdout(socket_t fd, int revents, void *userdata) {
		char buf[buffer_size];
		int n = -1;
		ssh_channel channel = (ssh_channel)userdata;

		if (channel != NULL && (revents & POLLIN) != 0) {
			n = read(fd, buf, buffer_size);
			if (n > 0) {
				ssh_channel_write(channel, buf, n);
			}
		}

		return n;
	}
public:
	SshServer(std::string addr, std::string port);
	void start();
};

SshServer::SshServer(std::string addr, std::string port) {
	serverAddr = addr;
	serverPort = port;

	setSigaction();
	ssh_init();
	setBind();
}

void SshServer::setBind() {
	bind = ssh_bind_new();

	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_DSAKEY, KEYS_FOLDER "ssh_host_dsa_key");
	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_RSAKEY, KEYS_FOLDER "ssh_host_rsa_key");
	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDADDR, serverAddr.c_str());
	ssh_bind_options_set(bind, SSH_BIND_OPTIONS_BINDPORT_STR, serverPort.c_str());
}

void SshServer::setSigaction() {
	static bool initialized = false;
	if (initialized)
		return;

	sa.sa_handler = SshServer::sigchldHandler;
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
	if (sigaction(SIGCHLD, &sa, nullptr) != 0) {
		std::cerr << "Failed to register SIGCHLD handler" << std::endl;
		exit(1);
	}

	initialized = true;
}

void SshServer::removeSigaction() {
	sa.sa_handler = SIG_DFL;
	sigaction(SIGCHLD, &sa, nullptr);
}

void SshServer::start() {
	if (ssh_bind_listen(bind) < 0) {
		std::cerr << ssh_get_error(bind) << std::endl;
		exit(1);
	}

	for (;;) {
		if ((session = ssh_new()) == nullptr) {
			std::cerr << "Failed to allocate session" << std::endl;
			continue;
		}

		if (ssh_bind_accept(bind, session) == SSH_ERROR) {
			std::cerr << ssh_get_error(bind) << std::endl;
		}
		else {
			switch (fork()) {
			case 0:
				removeSigaction();
				ssh_bind_free(bind);
				if ((event = ssh_event_new()) == nullptr) {
					std::cerr << "Could not create polling context" << std::endl;
				}
				else {
					SshServer::handleSession(event, session);
					ssh_event_free(event);
				}
				ssh_disconnect(session);
				ssh_free(session);

				exit(0);
				break;
			case -1:
				std::cerr << "Failed to fork" << std::endl;
			default:
				break;
			}
		}

		ssh_disconnect(session);
		ssh_free(session);
	}
}

int main(int __attribute__((unused)) argc, char ** __attribute__((unused)) argv) {
	SshServer server(std::string("0.0.0.0"), std::string("2022"));
	server.start();
	return 0;
}
