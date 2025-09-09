const fs = require('fs');
const path = require('path');

// --- List known vulnerable versions (update as needed) ---
const vulnerabilities = {
  backslash: ['0.2.1'],
  'chalk-template': ['1.1.1'],
  'supports-hyperlinks': ['4.1.1'],
  'has-ansi': ['6.0.1'],
  'simple-swizzle': ['0.2.3'],
  'color-string': ['2.1.1'],
  'error-ex': ['1.3.3'],
  'color-name': ['2.0.1'],
  'is-arrayish': ['0.3.3'],
  'slice-ansi': ['7.1.1'],
  'color-convert': ['3.1.1'],
  'wrap-ansi': ['9.0.1'],
  'ansi-regex': ['6.2.1'],
  'supports-color': ['10.2.1'],
  'strip-ansi': ['7.1.1'],
  chalk: ['5.6.1'],
  debug: ['4.4.2'],
  'ansi-styles': ['6.2.2'],
};

// --- Helper: Check if a version is vulnerable ---
function isVulnerable(pkg, version) {
  if (!vulnerabilities[pkg]) return false;
  // Remove any leading ^, ~, >=, <=, etc.
  const cleanVersion = version.replace(/^[^\d]*/, '');
  return vulnerabilities[pkg].includes(cleanVersion);
}

// --- Helper: Extract package versions from node_modules ---
function getInstalledVersion(repoPath, pkg) {
  try {
    const pkgPath = path.join(repoPath, 'node_modules', pkg, 'package.json');
    if (fs.existsSync(pkgPath)) {
      const pkgJson = JSON.parse(fs.readFileSync(pkgPath, 'utf8'));
      return pkgJson.version;
    }
  } catch (e) {
    // Ignore errors for missing packages
  }
  return null;
}

// --- Helper: Extract package versions from lock files ---
function extractVersionsFromLock(lockFile) {
  const content = fs.readFileSync(lockFile, 'utf8');
  const result = {};
  Object.keys(vulnerabilities).forEach(pkg => {
    // Match lines like: "chalk@5.6.1": { ... "version": "5.6.1"
    const regex = new RegExp(`"${pkg}@[^"]+":\\s*\\{[^\\}]*"version": "([^"]+)"`, 'g');
    let match;
    while ((match = regex.exec(content)) !== null) {
      result[pkg] = match[1];
    }
  });
  return result;
}

// --- Main: Scan all subfolders ---
const parentDir = process.cwd();
const folders = fs.readdirSync(parentDir).filter(f => fs.statSync(path.join(parentDir, f)).isDirectory());

folders.forEach(folder => {
  const repoPath = path.join(parentDir, folder);
  let foundAny = false;
  let report = [];

  // Check package.json
  const pkgJsonPath = path.join(repoPath, 'package.json');
  if (fs.existsSync(pkgJsonPath)) {
    try {
      const json = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
      ['dependencies', 'devDependencies'].forEach(depType => {
        if (json[depType]) {
          Object.keys(vulnerabilities).forEach(pkg => {
            if (json[depType][pkg]) {
              const version = json[depType][pkg];
              report.push({
                source: 'package.json',
                package: pkg,
                version: version,
                vulnerable: isVulnerable(pkg, version)
              });
              foundAny = true;
            }
          });
        }
      });
    } catch (e) {
      console.error(`Error reading ${pkgJsonPath}:`, e);
    }
  }

  // Check lock files for actual installed versions
  ['yarn.lock', 'package-lock.json'].forEach(lockName => {
    const lockPath = path.join(repoPath, lockName);
    if (fs.existsSync(lockPath)) {
      const lockVersions = extractVersionsFromLock(lockPath);
      Object.entries(lockVersions).forEach(([pkg, version]) => {
        report.push({
          source: lockName,
          package: pkg,
          version: version,
          vulnerable: isVulnerable(pkg, version)
        });
        foundAny = true;
      });
    }
  });

  // Check node_modules for installed package versions
  Object.keys(vulnerabilities).forEach(pkg => {
    const installedVersion = getInstalledVersion(repoPath, pkg);
    if (installedVersion) {
      report.push({
        source: 'node_modules',
        package: pkg,
        version: installedVersion,
        vulnerable: isVulnerable(pkg, installedVersion)
      });
      foundAny = true;
    }
  });

  // Print results
  if (foundAny) {
    console.log(`--- ${folder} ---`);
    report.forEach(r => {
      console.log(`[${r.source}] ${r.package}@${r.version} : ${r.vulnerable ? '❌ VULNERABLE' : '✅ SAFE'}`);
    });
    console.log('');
  } else {
    console.log(`⚠️ ${folder}: No relevant packages found.`);
  }
});
