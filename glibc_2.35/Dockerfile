FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc libc6-dev make cmake pkg-config gdb git curl ca-certificates tmux neovim sudo \
        python3 python3-pip python3-dev \
    && pip3 install --no-cache-dir \
        "filebytes @ git+https://github.com/sashs/filebytes.git@ff7492d750140288e2c3ff25b8a648719be470ce" \
    && pip3 install --no-cache-dir pwntools ropper \
    && rm -rf /var/lib/apt/lists/*

RUN userdel -r ubuntu 2>/dev/null; groupadd -g 1000 user && useradd -m -s /bin/bash -u 1000 -g 1000 user \
    && echo 'user ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/user && chmod 0440 /etc/sudoers.d/user

RUN git clone --depth 1 https://github.com/pwndbg/pwndbg /opt/pwndbg \
    && cd /opt/pwndbg && ./setup.sh \
    && mkdir -p /etc/gdb \
    && echo "source /opt/pwndbg/gdbinit.py" > /etc/gdb/gdbinit \
    && chown -R user:user /opt/pwndbg

ENV LANG=C.UTF-8

WORKDIR /lab

COPY Makefile /lab/Makefile
COPY src/     /lab/src/
COPY pwn.conf /home/user/.pwn.conf
COPY gdbinit  /home/user/.gdbinit

RUN make -C /lab build \
    && chown -R user:user /lab \
    && chown user:user /home/user/.pwn.conf /home/user/.gdbinit
USER user

RUN mkdir -p /home/user/.local/share /home/user/.local/state /home/user/.cache

RUN for b in /lab/bin/*; do gdb --batch -ex quit "$b" >/dev/null 2>&1 || true; done

CMD ["bash"]
