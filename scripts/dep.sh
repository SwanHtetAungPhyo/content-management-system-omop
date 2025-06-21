#!/usr/bin/env bash

# AUTHOR: Swan Htet Aung Phyo'
# NOTE: I assume all of the member use the unix base operating system
set -e


REQUIRED_TOOLS=("go" "docker" "golangci-lint" "gofmt")


OS="$(uname -s)"
echo "Detected OS: $OS"


# We are working on the operating system level . So , we need to check the tool to download the dependency
command_os_checker(){
  command -v  "$1" >/dev/null 2>&1
}

go_installation(){
  echo "Installing Go ...."

  if [[ "$OS" == "linux" ]]; then
    curl -LO https://go.dev/dl/go1.24.3.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go1.24.3.linux-amd64.tar.gz
    rm go1.24.3.linux-amd64.tar.gz
    export PATH=$PATH:/usr/local/go/bin
  elif [ [ "$OS" == "darwin" ] ]; then
    if command_os_checker brew; then
      brew install go
    else
      echo "Please install home brew first"
      exit 1
    fi
  else
    echo "UnSupport OS for automatic GO.."
  fi
}

install_golangci_lint() {
  echo "Installing golangci-lint..."
  if [[ "$OS" == "Linux" ]]; then
    curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin v1.52.2
  elif [[ "$OS" == "Darwin" ]]; then
    if command_exists brew; then
      brew install golangci-lint
    else
      echo "Please install Homebrew first: https://brew.sh/"
      exit 1
    fi
  else
    echo "Unsupported OS for automatic golangci-lint install"
  fi
}

install_docker() {
  echo "Installing Docker..."
  if [[ "$OS" == "Linux" ]]; then
    sudo apt-get update
    sudo apt-get install -y docker.io
    sudo systemctl start docker
    sudo systemctl enable docker
  elif [[ "$OS" == "Darwin" ]]; then
    if command_exists brew; then
      brew install --cask docker
    else
      echo "Please install Homebrew first: https://brew.sh/"
      exit 1
    fi
  else
    echo "Unsupported OS for automatic Docker install"
  fi
}


for tool in "${REQUIRED_TOOLS[@]}"; do
  if ! command_exists "$tool"; then
    echo "⚠️  $tool not found, installing..."
    case $tool in
      go)
        install_go
        ;;
      docker)
        install_docker
        ;;
      golangci-lint)
        install_golangci_lint
        ;;
      gofmt)
        echo "gofmt comes with Go, so make sure Go is installed."
        ;;
      *)
        echo "No automatic install available for $tool, please install manually."
        ;;
    esac
  else
    echo "✔️ $tool is already installed."
  fi
done

echo "Installation Finished...."
