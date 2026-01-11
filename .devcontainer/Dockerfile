FROM mcr.microsoft.com/devcontainers/base:ubuntu

# Install Node.js 20
RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
    && apt-get -y install --no-install-recommends curl ca-certificates \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get -y install --no-install-recommends nodejs

# Install pnpm
RUN npm install -g pnpm

# Install Python and pip
RUN apt-get -y install --no-install-recommends python3 python3-pip

# Install just
RUN curl --proto '=https' --tlsv1.2 -sSf https://just.systems/install.sh | bash -s -- --to /usr/local/bin

# Install mise
RUN curl https://mise.run | sh

# Install pre-commit
RUN pip3 install pre-commit

# Clean up
RUN apt-get autoremove -y && apt-get clean -y && rm -rf /var/lib/apt/lists/*
