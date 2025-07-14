# ubi-micro-dev
> Pre-built micro Red Hat UBI images for modern application development

[✨ **Start Here: View the Container Collection and Image Reports** ✨](https://ubi-micro-dev.github.io/ubi-micro-dev/)

---

**ubi-micro-dev** is a curated collection of **distroless**,
OCI-compliant container images based on Red Hat’s Universal Base Image
(UBI) technology. These images are purpose-built to simplify secure,
minimal application hosting.

Red Hat’s official *UBI Micro* base images are extremely lightweight,
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
- Based entirely on trusted **Red Hat UBI** technology
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

## 🚀 Getting started
You can pull the images directly and start building your containers without additional configuration.

For example:

```
FROM ghcr.io/ubi-micro-dev/ubi9-micro-dev-openjdk-21:latest

ADD spring-petclinic-3.4.0-SNAPSHOT.jar .

CMD java -jar spring-petclinic-3.4.0-SNAPSHOT.jar
```

These images are rebuilt and scanned every 6 hours, and are only ever
published with a `latest` tag.  For reproducibility, pull these images
into your own registry and assign tags that are meaningful to you.

---
