Installation
============

### 1. Clone this repo
```bash
# TODO
```

### 2. Install dependency
```bash
sudo apt install build-essential libssh-dev libmysqlcppconn-dev libcurl4-openssl-dev
```

### 3. Compile source.
```bash
# TODO
```

### 4. Generate serever-side key pair.
```bash
#!/bin/bash

mkdir -p build && cd build
ssh-keygen -f ssh_host_rsa_key -N '' -t rsa
ssh-keygen -f ssh_host_dsa_key -N '' -t dsa
```

### 5. Create a service account for security.
```bash
# TODO
```

### 6. Create a systemd unit.
```bash
# TODO
```

### 7. Start the server.
```bash
# TODO
```