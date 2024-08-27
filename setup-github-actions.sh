#!/bin/bash

# Create the necessary directories
mkdir -p .github/workflows

# Create the GitHub Actions workflow file
cat << 'EOF' > .github/workflows/build-and-publish.yml
name: Build and Publish Docker Image

on:
  push:
    branches:
      - main
  pull_request:
    branches:
      - main

jobs:
  build-and-publish:
    runs-on: ubuntu-latest

    steps:
      - name: Checkout the code
        uses: actions/checkout@v3

      - name: Set up Docker Buildx
        uses: docker/setup-buildx-action@v2
        with:
          driver-opts: image=moby/buildkit:master

      - name: Set up QEMU
        uses: docker/setup-qemu-action@v2

      - name: Log in to GitHub Container Registry
        uses: docker/login-action@v2
        with:
          registry: ghcr.io
          username: ${{ github.actor }}
          password: ${{ secrets.GITHUB_TOKEN }}

      - name: Run build script
        run: |
          chmod +x ./scripts/build_with_controller_ssl3.sh
          ./scripts/build_with_controller_ssl3.sh

      - name: Build and push Docker image
        run: |
          docker buildx build -f Dockerfile --platform linux/amd64 --tag ghcr.io/cloudrhinoltd/nginx-ingress:1.0.0 --push .
EOF

# Make the workflow file executable (just in case)
chmod +x .github/workflows/build-and-publish.yml

# Add the workflow to git and commit
git add .github/workflows/build-and-publish.yml
git commit -m "Add GitHub Actions workflow to build and publish Docker image"
git push

echo "GitHub Actions workflow set up and pushed to the repository."
