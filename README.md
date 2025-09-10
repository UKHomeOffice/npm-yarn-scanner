# npm-yarn-scanner

## Overview

The `npm-yarn-scanner` is a tool designed to scan JavaScript projects managed by npm or Yarn for vulnerabilities that might be present on your machine.  It's reactive step in case you've heard about some vulnerabilities and you want to check if your local machine has been compromised

---

## Prerequisites

- **Node.js** (version 14+ recommended)
- **npm** or **Yarn**
- Git (to clone the repository)

---

## Clone the Repository

```bash
git clone https://github.com/UKHomeOffice/npm-yarn-scanner.git
cd npm-yarn-scanner
```
---
## Run

- Go to your parent directory where you have all your repos 
- Then run node with the full path name of where you have this repo

```bash
node npm-yarn-scanner/index.js
```

Alternatively, you can pass it a filepath and it'll scan all the subfolders and that folder for packages

```bash
node npm-yarn-scanner/index.js /Users/sulthan/dev-shizzle
```
