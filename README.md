# ubi-micro-dev
> Pre-built micro Red Hat UBI images for modern application development

[✨ **Start Here: View the Container Collection and Image Reports** ✨](https://ubi-micro-dev.github.io/ubi-micro-dev/)

---

**ubi-micro-dev** is a curated collection of **distroless**,
OCI-compliant container images based on Red Hat’s Universal Base Image
(UBI). These images are purpose-built to simplify secure, minimal
application hosting.

Red Hat’s official *micro UBI* base images are extremely lightweight,
omitting the package manager and most supporting tools. While this
minimalism is excellent for production security, it can make
installing essential runtimes (such as Java or Node.js) unnecessarily
complex.

**ubi-micro-dev** solves this by providing pre-configured,
application-ready images that include popular runtimes and libraries
out of the box—saving you time and reducing boilerplate in your build
process.

---

## ✅ Key Features
- Based on trusted **Red Hat UBI Micro** technology
- **Distroless**: no package manager, fewer attack surfaces
- Pre-installed **Java** and **Node.js** runtimes
- Fully **OCI-compatible**
- Designed for **secure, minimal deployments**

---

## 🎯 Who Is This For?
These images are ideal for:
- Java or Node.js developers deploying to Kubernetes
- Teams who want the smallest possible Red Hat–based images without the hassle of manual RPM installs
- CI/CD pipelines requiring predictable, minimal environments

---

## 🚀 Getting Started
You can pull the images directly and start building your containers without additional configuration.

These images come pre-configured with non-root user `ubi-micro-dev`,
and `WORKDIR` is set to `/home/ubi-micro-dev`.

If you really must install additional RPMS, run a multi-stage build and use the `ubi-micr-dev.sh` script to install packages.

```
FROM ghcr.io/ubi-micro-dev/ubi9-micro-dev-openjdk-21 AS source-image
FROM registry.access.redhat.com/ubi9 AS build-image

COPY --from=source-image /usr/bin/ubi-micro-dev.sh /usr/bin

# Install git (for example)
RUN ubi-micro-dev.sh git-core

FROM ghcr.io/ubi-micro-dev/ubi9-micro-dev-openjdk-21
COPY --from=build-image /tmp/ubi-micro-dev/rootfs/ /
```

---
