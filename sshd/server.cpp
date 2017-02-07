#include "server.h"

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
					handleSession(event, session);
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

void SshServer::sigchldHandler(int __attribute__((unused)) signo) {
	while (waitpid(-1, nullptr, WNOHANG) > 0)
		std::this_thread::sleep_for(std::chrono::milliseconds(10));
}

void SshServer::handleSession(ssh_event event, ssh_session session) {
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
		authenticated : 0,
		server_instance : this
	};
	struct ssh_channel_callbacks_struct channel_cb;
	channel_cb.userdata = &cdata;
	channel_cb.channel_pty_request_function = SshServer::onPtyRequest;
	channel_cb.channel_pty_window_change_function = SshServer::onPtyResize;
	channel_cb.channel_shell_request_function = SshServer::onShellRequest;
	channel_cb.channel_exec_request_function = SshServer::onExecRequest;
	channel_cb.channel_data_function = SshServer::onData;
	channel_cb.channel_subsystem_request_function = SshServer::onSubsystemRequest;

	struct ssh_server_callbacks_struct server_cb;
	server_cb.userdata = &sdata;
	server_cb.auth_password_function = SshServer::onAuthPasswd;
	server_cb.channel_open_request_session_function = SshServer::onChannelOpen;

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
		if (ssh_event_dopoll(event, -1) == SSH_ERROR) {
			ssh_channel_close(sdata.channel);
		}

		if (cdata.event != NULL || cdata.pid == 0) {
			continue;
		}
		cdata.event = event;
		if (cdata.child_stdout != -1) {
			if (ssh_event_add_fd(event, cdata.child_stdout, POLLIN, process_stdout,
				sdata.channel) != SSH_OK) {
				fprintf(stderr, "Failed to register stdout to poll context\n");
				ssh_channel_close(sdata.channel);
			}
		}

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

	ssh_event_remove_fd(event, cdata.child_stdout);
	ssh_event_remove_fd(event, cdata.child_stderr);

	if (kill(cdata.pid, 0) < 0 && WIFEXITED(rc)) {
		rc = WEXITSTATUS(rc);
		ssh_channel_request_send_exit_status(sdata.channel, rc);
	}
	else if (cdata.pid > 0) {
		kill(cdata.pid, SIGKILL);
	}

	ssh_channel_send_eof(sdata.channel);
	ssh_channel_close(sdata.channel);

	for (n = 0; n < 50 && (ssh_get_status(session) & (SSH_CLOSED | SSH_CLOSED_ERROR)) == 0; n++) {
		ssh_event_dopoll(event, 100);
	}
}

int SshServer::onPtyRequest(ssh_session __attribute__((unused)) session, ssh_channel __attribute__((unused)) channel, const char * __attribute__((unused)) term, int cols, int rows, int py, int px, void *userdata) {
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

int SshServer::onPtyResize(ssh_session __attribute__((unused)) session, ssh_channel __attribute__((unused)) channel, int cols, int rows, int py, int px, void *userdata) {
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

int SshServer::onShellRequest(ssh_session __attribute__((unused)) session, ssh_channel __attribute__((unused)) channel, void *userdata) {
	struct channel_data_struct *cdata = (struct channel_data_struct *) userdata;

	if (cdata->pid > 0) {
		return SSH_ERROR;
	}

	if (cdata->pty_master != -1 && cdata->pty_slave != -1) {
		return SshServer::execPty("", NULL, cdata);
	}
	return SSH_OK;
}

int SshServer::onExecRequest(ssh_session __attribute__((unused)) session, ssh_channel __attribute__((unused)) channel, const char *command, void *userdata) {
	struct channel_data_struct *cdata = (struct channel_data_struct *) userdata;

	if (cdata->pid > 0) {
		return SSH_ERROR;
	}

	if (cdata->pty_master != -1 && cdata->pty_slave != -1) {
		return SshServer::execPty("-c", command, cdata);
	}
	return execNoPty(command, cdata);
}

int SshServer::onData(ssh_session __attribute__((unused)) session, ssh_channel __attribute__((unused)) channel, void *data, uint32_t len, int __attribute__((unused)) is_stderr, void *userdata) {
	struct channel_data_struct *cdata = (struct channel_data_struct *) userdata;

	if (len == 0 || cdata->pid < 1 || kill(cdata->pid, 0) < 0) {
		return 0;
	}

	return write(cdata->child_stdin, (char *)data, len);
}

int SshServer::onSubsystemRequest(ssh_session __attribute__((unused)) session, ssh_channel __attribute__((unused)) channel, const char * __attribute__((unused)) subsystem, void * __attribute__((unused)) userdata) {
	return SSH_ERROR;
}

// TODO: add unused attribute
int SshServer::execPty(const char *mode, const char *command, struct channel_data_struct *cdata) {
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
		cdata->child_stdout = cdata->child_stdin = cdata->pty_master;
	}
	return SSH_OK;
}

// TODO: add unused attribute
int SshServer::execNoPty(const char *command, struct channel_data_struct *cdata) {
	return SSH_ERROR;
}

int SshServer::onAuthPasswd(ssh_session __attribute__((unused)) session, const char *user, const char *pass, void *userdata) {
	struct session_data_struct *sdata = (struct session_data_struct *) userdata;
	SshServer *self = (SshServer *)sdata->server_instance;

	// for test
	if (self->authMethod(std::string(user), std::string(pass))) {
		sdata->authenticated = 1;
		return SSH_AUTH_SUCCESS;
	}

	sdata->auth_attempts++;
	return SSH_AUTH_DENIED;
}

ssh_channel SshServer::onChannelOpen(ssh_session session, void *userdata) {
	struct session_data_struct *sdata = (struct session_data_struct *) userdata;

	sdata->channel = ssh_channel_new(session);
	return sdata->channel;
}

int SshServer::process_stderr(socket_t fd, int revents, void *userdata) {
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

int SshServer::process_stdout(socket_t fd, int revents, void *userdata) {
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