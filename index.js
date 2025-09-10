const fs = require('fs');
const path = require('path');
const defaultVulnerabilities = require('./vulnerabilities');

// --- Helper: Load custom vulnerabilities file if provided ---
function loadCustomVulnerabilities(filePath) {
  if (!filePath) return {};
  try {
    if (filePath.endsWith('.json')) {
      return JSON.parse(fs.readFileSync(filePath, 'utf8'));
    } else if (filePath.endsWith('.js')) {
      return require(path.resolve(filePath));
    }
  } catch (e) {
    console.error('Error loading custom vulnerabilities file:', e);
  }
  return {};
}

// --- Helper: Merge vulnerabilities ---
function mergeVulnerabilities(base, custom) {
  const merged = { ...base };
  Object.entries(custom).forEach(([pkg, versions]) => {
    if (!merged[pkg]) merged[pkg] = [];
    merged[pkg] = Array.from(new Set([...merged[pkg], ...versions]));
  });
  return merged;
}

// --- Helper: Check if a version is vulnerable ---
function isVulnerable(pkg, version, vulnerabilities) {
  if (!vulnerabilities[pkg]) return false;
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
  } catch (e) {}
  return null;
}

// --- Helper: Extract package versions from lock files ---
function extractVersionsFromLock(lockFile, vulnerabilities) {
  const content = fs.readFileSync(lockFile, 'utf8');
  const result = {};
  Object.keys(vulnerabilities).forEach(pkg => {
    const regex = new RegExp(`"${pkg}@[^"]+":\\s*\\{[^\\}]*"version": "([^"]+)"`, 'g');
    let match;
    while ((match = regex.exec(content)) !== null) {
      result[pkg] = match[1];
    }
  });
  return result;
}

// --- Main: Scan a specific folder or file ---
function scanTarget(targetPath, vulnerabilities) {
  let foundAny = false;
  let report = [];
  let repoPath = targetPath;
  if (fs.statSync(targetPath).isFile()) {
    repoPath = path.dirname(targetPath);
  }

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
                vulnerable: isVulnerable(pkg, version, vulnerabilities)
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
      const lockVersions = extractVersionsFromLock(lockPath, vulnerabilities);
      Object.entries(lockVersions).forEach(([pkg, version]) => {
        report.push({
          source: lockName,
          package: pkg,
          version: version,
          vulnerable: isVulnerable(pkg, version, vulnerabilities)
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
        vulnerable: isVulnerable(pkg, installedVersion, vulnerabilities)
      });
      foundAny = true;
    }
  });

  // Print results
  if (foundAny) {
    console.log(`--- ${path.basename(repoPath)} ---`);
    report.forEach(r => {
      console.log(`[${r.source}] ${r.package}@${r.version} : ${r.vulnerable ? '❌ VULNERABLE' : '✅ SAFE'}`);
    });
    console.log('');
  } else {
    console.log(`⚠️ ${path.basename(repoPath)}: No relevant packages found.`);
  }
}

// --- CLI: Accept a file/folder argument and optional vulnerabilities file ---
const argPath = process.argv[2];
const customVulnFile = process.argv[3];
const customVulns = loadCustomVulnerabilities(customVulnFile);
const vulnerabilities = mergeVulnerabilities(defaultVulnerabilities, customVulns);

if (argPath) {
  scanTarget(path.resolve(argPath), vulnerabilities);
} else {
  const parentDir = process.cwd();
  const folders = fs.readdirSync(parentDir).filter(f => fs.statSync(path.join(parentDir, f)).isDirectory());
  folders.forEach(folder => {
    scanTarget(path.join(parentDir, folder), vulnerabilities);
  });
}
