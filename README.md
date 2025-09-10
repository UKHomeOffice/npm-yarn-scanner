# npm-yarn-scanner

## Overview

The `npm-yarn-scanner` is a tool designed to scan JavaScript projects managed by npm or Yarn for vulnerabilities or license issues. This guide will walk you through:

1. Installing dependencies and preparing the environment
2. Running the scanner on your project
3. Adding a custom file for scanning
4. Specifying a custom path for scanning

---

## 1. Prerequisites

- **Node.js** (version 14+ recommended)
- **npm** or **Yarn**
- Git (to clone the repository)

---

## 2. Clone the Repository

```bash
git clone https://github.com/UKHomeOffice/npm-yarn-scanner.git
cd npm-yarn-scanner
```

---

## 3. Install Dependencies

Using **npm**:

```bash
npm install
```

Or using **Yarn**:

```bash
yarn install
```

---

## 4. Basic Usage: Scan the Default Project

By default, the scanner will look for a `package.json` in the root folder and scan the dependencies listed.

```bash
npm start
```

Or:

```bash
yarn start
```

---

## 5. Scanning a Specific File

You can instruct the scanner to scan a specific file, such as a custom `package.json` or a lockfile.

### Example: Scan a custom package.json file

Suppose you have a file called `alt-package.json` in your project directory.

```bash
npm start -- --file alt-package.json
```

Or with Yarn:

```bash
yarn start --file alt-package.json
```

**Note:**  
- The `--` before the arguments is necessary to pass arguments to the underlying script.
- Replace `alt-package.json` with your actual filename.

---

## 6. Scanning a Specific Path

If your project is located in a subdirectory (e.g., `apps/my-app/`), you can specify the path:

```bash
npm start -- --path apps/my-app
```

Or:

```bash
yarn start --path apps/my-app
```

You can combine both options if needed:

```bash
npm start -- --path apps/my-app --file package.json
```

This will scan `apps/my-app/package.json`.

---

## 7. Output

The scanner will provide a summary of findings, including any vulnerabilities or license issues detected.

---

## 8. Advanced Options

Check the CLI help for more options:

```bash
npm start -- --help
```

Or

```bash
yarn start --help
```

---

## 9. Troubleshooting

- **Ensure your Node.js version is compatible**
- **Check file paths and names are correct**
- **Make sure you have permissions to access the files**

---

## 10. Contribution

Feel free to fork the repo, create pull requests, or raise issues for bugs and feature requests.

---

## Example

Assume you want to scan `src/client/package.json`:

```bash
npm start -- --path src/client --file package.json
```

---

## References

- [npm documentation](https://docs.npmjs.com/)
- [Yarn documentation](https://yarnpkg.com/)
