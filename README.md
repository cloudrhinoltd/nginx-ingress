
# ngx-waf-ingress-controller

`ngx-waf-ingress-controller` is a custom NGINX-based ingress controller with an integrated Web Application Firewall (WAF) for Kubernetes clusters. Built on the latest Ubuntu 24.04 base, this ingress controller provides enhanced security, modern features, and robust protection against a wide range of web-based threats. It is designed to meet the demands of secure and scalable Kubernetes environments.

## Status

This project is production-ready.

## Table of Contents

- [Synopsis](#synopsis)
- [Description](#description)
- [Directives](#directives)
  - [`enable_protocol_attack`](#enable_protocol_attack)
  - [`enable_sql_injection`](#enable_sql_injection)
  - [`enable_xss`](#enable_xss)
  - [`enable_rce_php_node`](#enable_rce_php_node)
  - [`enable_session_rules`](#enable_session_rules)
  - [`enable_general_rules`](#enable_general_rules)
- [Installation](#installation)
  - [Building as a Static Module](#building-as-a-static-module)
  - [Building as a Dynamic Module](#building-as-a-dynamic-module)
- [Enhanced Security with Latest Ubuntu 24.04 and SSL3 Libraries](#enhanced-security-with-latest-ubuntu-2404-and-ssl3-libraries)
- [Requirements](#requirements)
- [Building](#building)
- [Licensing and Copyright](#licensing-and-copyright)
- [Source Repository](#source-repository)
- [Author](#author)
- [See Also](#see-also)

## Synopsis

```nginx
http {
    server {
        listen 80;
        server_name localhost;

        location / {
            clrh_waf_handler;

            enable_protocol_attack on;
            enable_general_rules off;
            enable_sql_injection off;
            enable_xss off;
            enable_rce_php_node off;
            enable_session_rules off;
        }

        error_page 500 502 503 504 /50x.html;
        location = /50x.html {
            root html;
        }
    }
}
```

## Description

`ngx-waf-ingress-controller` is a powerful and flexible NGINX-based ingress controller designed to protect your Kubernetes clusters with an advanced Web Application Firewall (WAF). This controller not only manages traffic ingress but also defends against common web-based threats such as SQL Injection, Cross-Site Scripting (XSS), Remote Command Execution (RCE), and more.

### Key Features

- **Advanced Threat Protection:** Integrated WAF with customizable rules to protect against a variety of web-based attacks.
- **Modern Security:** Built on the latest Ubuntu 24.04 with the latest SSL3 libraries, ensuring up-to-date security features and compliance.
- **High Performance:** Optimized for performance in cloud-native environments with support for modern web technologies.
- **Scalable Architecture:** Easily scales to meet the demands of growing Kubernetes environments.

## Directives

### `enable_protocol_attack`
- **Syntax:** `enable_protocol_attack on | off;`
- **Default:** `off`
- **Context:** `http, server, location`
- **Description:** Enables or disables protocol attack protection.

### `enable_sql_injection`
- **Syntax:** `enable_sql_injection on | off;`
- **Default:** `off`
- **Context:** `http, server, location`
- **Description:** Enables or disables SQL injection protection.

### `enable_xss`
- **Syntax:** `enable_xss on | off;`
- **Default:** `off`
- **Context:** `http, server, location`
- **Description:** Enables or disables Cross-Site Scripting (XSS) protection.

### `enable_rce_php_node`
- **Syntax:** `enable_rce_php_node on | off;`
- **Default:** `off`
- **Context:** `http, server, location`
- **Description:** Enables or disables Remote Command Execution (RCE) protection for PHP and Node.js environments.

### `enable_session_rules`
- **Syntax:** `enable_session_rules on | off;`
- **Default:** `off`
- **Context:** `http, server, location`
- **Description:** Enables or disables session management rules.

### `enable_general_rules`
- **Syntax:** `enable_general_rules on | off;`
- **Default:** `on`
- **Context:** `http, server, location`
- **Description:** Enables or disables general security rules.

## License

This project is licensed under the Apache License 2.0. Note that the `ngx-waf-protect` module contains specific directives that are dual-licensed:

- **Apache License 2.0:** Applies to the following directives:
  - `enable_protocol_attack`
  - `enable_general_rules`
- **Enterprise License:** Required for the following directives:
  - `enable_sql_injection`
  - `enable_xss`
  - `enable_rce_php_node`
  - `enable_session_rules`

## Installation

### Building as a Static Module

To build `ngx-waf-ingress-controller` as part of a custom NGINX build:

1. Clone the repository:
   ```bash
   git clone https://github.com/cloudrhinoltd/ngx-waf-protect.git
   cd ngx-waf-protect
   ```

2. Download and extract the NGINX source code:
   ```bash
   wget 'http://nginx.org/download/nginx-1.27.1.tar.gz'
   tar -xzvf nginx-1.27.1.tar.gz
   cd nginx-1.27.1
   ```

3. Configure and build NGINX with the `ngx-waf-ingress-controller` module:
   ```bash
   ./configure --prefix=/opt/nginx                --with-http_ssl_module                --add-module=/path/to/ngx-waf-protect
   make -j$(nproc)
   make install
   ```

### Building as a Dynamic Module

Starting with NGINX 1.9.11, `ngx-waf-ingress-controller` can also be built as a dynamic module:

1. Follow steps 1 and 2 above.

2. Configure NGINX with `--add-dynamic-module`:
   ```bash
   ./configure --prefix=/opt/nginx                --with-http_ssl_module                --add-dynamic-module=/path/to/ngx-waf-protect
   make -j$(nproc)
   make install
   ```

3. Load the module in `nginx.conf`:
   ```nginx
   load_module /path/to/modules/ngx_waf_protect.so;
   ```

## Enhanced Security with Latest Ubuntu 24.04 and SSL3 Libraries

The NGINX Ingress Controller image is built on the latest Ubuntu 24.04 base, ensuring that it leverages the most up-to-date and secure operating system environment. This modern foundation is particularly beneficial for security-sensitive applications, as it includes the most recent security patches and performance improvements.

Furthermore, the image utilizes the latest SSL3 libraries, which are part of OpenSSL 3.0, offering enhanced security features and better protection against vulnerabilities compared to older versions. OpenSSL 3.0 introduces a more modular design, improved cryptographic algorithms, and stricter compliance with modern security standards, making it an excellent choice for environments where secure communication is paramount.

By adopting the latest Ubuntu release and SSL3 libraries, the NGINX Ingress Controller image is well-equipped to handle current and emerging security challenges, providing robust and reliable protection for your web applications.

## Requirements

To build `ngx-waf-ingress-controller`, you need the following:

- **C++ Compiler:** Ensure that gcc or clang is installed.
- **NGINX Source Code:** Download from nginx.org.
- **Build Tools:** `make`, `autoconf`, and `libtool`.
- **OpenSSL:** Required for SSL support in NGINX.
- **PCRE:** Required for regex support in NGINX.

## Building

To build `ngx-waf-ingress-controller`, use the provided build script:

```bash
./scripts/build.sh
```

This script will download and compile all necessary dependencies and build the custom NGINX with the `ngx-waf-ingress-controller` module integrated.

## Licensing and Copyright

```text
Copyright (C) 2024 Cloud Rhino Pty Ltd

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

This project contains parts under a dual-license:
Only the 'enable_protocol_attack' and 'enable_general_rules' features are
covered by the Apache 2.0 License, other features require a commercial license.

GitHub Repo: https://github.com/cloudrhinoltd/ngx-waf-protect
Contact Email: cloudrhinoltd@gmail.com
```

## Source Repository

Available on GitHub at [cloudrhinoltd/ngx-waf-protect](https://github.com/cloudrhinoltd/ngx-waf-protect).

## Author

Cloud Rhino Pty Ltd  
[cloudrhinoltd@gmail.com](mailto:cloudrhinoltd@gmail.com)

## See Also

- [NGINX](https://nginx.org/)
- [OpenSSL](https://www.openssl.org/)
