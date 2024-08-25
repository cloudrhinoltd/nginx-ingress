#!/bin/bash
set -ex

# Define project directory
PROJECT_DIR="ngx_waf_ingress_controller"
BUILD_DIR="$PROJECT_DIR/build"
SCRIPTS_DIR="$PROJECT_DIR/scripts"
SRC_DIR="$PROJECT_DIR/src"

# Create the directory structure
mkdir -p "$BUILD_DIR"
mkdir -p "$SCRIPTS_DIR"
mkdir -p "$SRC_DIR"

# Create a basic README.md file
cat << EOF > "$PROJECT_DIR/README.md"
# ngx_waf_ingress_controller

This project builds a custom NGINX ingress-controller that incorporates a custom NGINX build with a WAF module.

## Directory Structure
- \`build/\`: Directory where the final build artifacts will be placed.
- \`scripts/\`: Directory for build scripts and other utilities.
- \`src/\`: Source code for the ingress-controller (cloned from upstream).
EOF

# Create a placeholder LICENSE file (you should update this with your actual license)
cat << EOF > "$PROJECT_DIR/LICENSE"
Your License Information Here.
EOF

# Create the build script in the scripts directory
cat << 'EOF' > "$SCRIPTS_DIR/build.sh"
#!/bin/bash
set -ex

# Define variables
HOME_DIR=$(pwd)
NGINX_WAF_PROJECT_DIR="$HOME_DIR/../ngx_waf_protect"
NGINX_WAF_BUILD_SCRIPT="$NGINX_WAF_PROJECT_DIR/scripts/build.sh"
INGRESS_CONTROLLER_SRC_DIR="$HOME_DIR/src"
NGINX_EXEC="$NGINX_WAF_PROJECT_DIR/build/nginx"
BUILD_DIR="$HOME_DIR/build"

# Ensure directories exist
mkdir -p "$BUILD_DIR"

# Clone or update the ngx_waf_protect project
if [ ! -d "$NGINX_WAF_PROJECT_DIR" ]; then
    echo "Cloning ngx_waf_protect..."
    git clone <your-git-repo-url-for-ngx_waf_protect> "$NGINX_WAF_PROJECT_DIR"
else
    echo "Updating ngx_waf_protect..."
    cd "$NGINX_WAF_PROJECT_DIR"
    git pull origin main
fi

# Build the custom NGINX with WAF module
echo "Building custom NGINX with WAF module..."
cd "$NGINX_WAF_PROJECT_DIR"
bash "$NGINX_WAF_BUILD_SCRIPT"

# Download and extract the ingress-controller source
if [ ! -d "$INGRESS_CONTROLLER_SRC_DIR" ]; then
    git clone https://github.com/kubernetes/ingress-nginx.git "$INGRESS_CONTROLLER_SRC_DIR"
fi

cd "$INGRESS_CONTROLLER_SRC_DIR"

# Build the custom ingress-controller with your NGINX
make build NGINX_BIN="$NGINX_EXEC"

# Copy the built ingress-controller to the build directory
cp "$INGRESS_CONTROLLER_SRC_DIR/bin/nginx-ingress-controller" "$BUILD_DIR/"

# Output success message
echo "Custom ingress-controller built successfully and located at $BUILD_DIR."
EOF

# Make the build script executable
chmod +x "$SCRIPTS_DIR/build.sh"

# Output a message indicating success
echo "Project structure created successfully. You can find the build script at $SCRIPTS_DIR/build.sh."

