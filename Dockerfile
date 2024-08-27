# Copyright (C) 2024 Cloud Rhino Pty Ltd
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# This Dockerfile contains parts under a dual-license:
# Only the 'enable_protocol_attack' and 'enable_general_rules' features are 
# covered by the Apache 2.0 License, other features require a commercial license.
#
# GitHub Repo: https://github.com/cloudrhinoltd/ngx-waf-protect
# Contact Email: cloudrhinoltd@gmail.com

# Step 1: Use the latest Ubuntu base image for runtime
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Step 2: Install necessary runtime dependencies including OpenSSL 3
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev \
    libpcre3 \
    zlib1g \
    libstdc++6 \
    dumb-init \
    wget \
    git \
    cmake \
    build-essential \
    libmaxminddb0 \
    libmaxminddb-dev \
    sudo \
    vim \
    net-tools \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && wget https://www.openssl.org/source/openssl-3.0.8.tar.gz -O /tmp/openssl.tar.gz \
    && tar -xzf /tmp/openssl.tar.gz -C /tmp \
    && cd /tmp/openssl-3.0.8 \
    && ./config --prefix=/usr/local/openssl --openssldir=/usr/local/openssl \
    && make -j$(nproc) \
    && make install \
    && rm -rf /tmp/openssl* \
    && ln -sf /usr/local/openssl/bin/openssl /usr/bin/openssl \
    && ldconfig

# Step 3: Set the working directory
WORKDIR /etc/nginx

# Step 4: Create the group with GID 82 and modify the www-data user
RUN groupadd -g 82 www-data-group && usermod -u 101 -g 82 www-data

# Step 5: Copy the Ingress NGINX controller binaries
COPY build/nginx-ingress-controller /usr/local/bin/nginx-ingress-controller
COPY build/wait-shutdown /usr/local/bin/wait-shutdown
COPY build/dbg /usr/local/bin/dbg

# Step 6: Ensure that the custom NGINX binary is used in place of the default
RUN ln -sf /usr/local/nginx/sbin/nginx /usr/bin/nginx && mkdir -p /etc/ingress-controller && chown -R www-data:www-data /etc/ingress-controller

# Step 7: Download, build, and install mimalloc
RUN mkdir -p /tmp/mimalloc && cd /tmp/mimalloc \
    && wget https://github.com/microsoft/mimalloc/archive/refs/tags/v2.0.6.tar.gz -O mimalloc.tar.gz \
    && tar -xzf mimalloc.tar.gz --strip-components=1 \
    && mkdir -p out/release && cd out/release \
    && cmake ../.. -DMI_INSTALL_TOP=/usr/local \
    && make && make install \
    && rm -rf /tmp/mimalloc && ldconfig \
    && mkdir -p /etc/ingress-controller/telemetry

# Step 8: Setup NGINX and required directories
COPY snippets/waf_location_snippet.conf /etc/nginx/snippets/
COPY ./src/ingress-nginx/rootfs/etc/nginx /etc/nginx
COPY ./telemetry /etc/ingress-controller/telemetry
COPY build/nginx /usr/local/nginx/sbin/nginx
COPY ./src/ingress-nginx/rootfs/etc/nginx /etc/nginx
COPY build/config/nginx.conf /etc/nginx/nginx.conf
COPY src/nginx-1.27.1/conf/mime.types /etc/nginx/mime.types
COPY build/geoip /etc/nginx/geoip
COPY src/luajit /etc/luajit
COPY src/luajit/share/lua/5.1/resty /etc/nginx/lua/resty

RUN mkdir -p /etc/ingress-controller/auth \
    && mkdir -p /etc/ingress-controller/ssl \
    && mkdir -p /etc/nginx/logs \
    && mkdir -p /etc/nginx/snippets \
    && mkdir -p /etc/nginx/temp \
    && chmod -R 755 /etc/ingress-controller \
    && chmod -R 755 /etc/nginx \
    && mkdir -p /etc/nginx/client_temp \
    && mkdir -p /etc/nginx/proxy_temp \
    && mkdir -p /etc/nginx/fastcgi_temp \
    && mkdir -p /etc/nginx/uwsgi_temp \
    && mkdir -p /etc/nginx/scgi_temp \
    && mkdir -p /var/log/nginx \
    && chown -R www-data:www-data /var/log/nginx \
    && chmod -R 755 /var/log/nginx \
    && mkdir -p /tmp/nginx \
    && chown -R www-data:www-data /tmp/nginx

RUN mkdir -p /etc/nginx/html \
    && echo "<html><body><h1>CLRH NGINX WAF Module Test</h1></body></html>" > "/etc/nginx/html/index.html"

# Step 9: Ensure the symlink for the controller and set correct ownership
RUN ln -s /usr/local/bin/nginx-ingress-controller /nginx-ingress-controller \
    && chown www-data:www-data /nginx-ingress-controller \
    && chown -R www-data:www-data /etc/nginx \
    && chown -R www-data:www-data /etc/ingress-controller 

# Step 10: Set the user to www-data (place this after system package installations)
USER www-data

ENV LD_LIBRARY_PATH="/etc/luajit/lib:$LD_LIBRARY_PATH"
ENV LUA_PATH="/etc/luajit/share/lua/5.1/?.lua;/etc/luajit/share/lua/5.1/?/init.lua"
ENV LUA_CPATH="/etc/luajit/lib/lua/5.1/?.so"

# Use sed to append the WAF include line to each location block
RUN sed -i '/location {/a\ \ \ \ \ \ \ \ # Include Cloud Rhino WAF configuration for this location\n\ \ \ \ \ \ \ \ include /etc/nginx/snippets/waf_location_snippet.conf;' /etc/nginx/template/nginx.tmpl

# Step 11: Expose the necessary ports (80 and 443)
EXPOSE 80 443

# Step 12: Set the entrypoint and command to match the standard image
ENTRYPOINT ["/usr/bin/dumb-init", "--"]
CMD ["/nginx-ingress-controller"]
