const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');

const BACKUP_DIR = path.join(__dirname, '.backups');
const MANIFEST_FILE = path.join(BACKUP_DIR, 'manifest.json');

function ensureBackupDir() {
    if (!fs.existsSync(BACKUP_DIR)) {
        fs.mkdirSync(BACKUP_DIR, { recursive: true });
    }
}

function loadManifest() {
    if (fs.existsSync(MANIFEST_FILE)) {
        return JSON.parse(fs.readFileSync(MANIFEST_FILE, 'utf-8'));
    }
    return { backups: [] };
}

function saveManifest(manifest) {
    fs.writeFileSync(MANIFEST_FILE, JSON.stringify(manifest, null, 2));
}

function hashFile(filePath) {
    const content = fs.readFileSync(filePath);
    return crypto.createHash('sha256').update(content).digest('hex');
}

function copyRecursive(src, dest) {
    const stat = fs.statSync(src);
    if (stat.isDirectory()) {
        fs.mkdirSync(dest, { recursive: true });
        for (const entry of fs.readdirSync(src)) {
            if (entry === '.backups') continue;
            copyRecursive(path.join(src, entry), path.join(dest, entry));
        }
    } else {
        fs.mkdirSync(path.dirname(dest), { recursive: true });
        fs.copyFileSync(src, dest);
    }
}

function getFileCount(dir) {
    let count = 0;
    const stat = fs.statSync(dir);
    if (!stat.isDirectory()) return 1;
    for (const entry of fs.readdirSync(dir)) {
        if (entry === '.backups') continue;
        const full = path.join(dir, entry);
        const s = fs.statSync(full);
        count += s.isDirectory() ? getFileCount(full) : 1;
    }
    return count;
}

function getTotalSize(target) {
    const stat = fs.statSync(target);
    if (!stat.isDirectory()) return stat.size;
    let size = 0;
    for (const entry of fs.readdirSync(target)) {
        if (entry === '.backups') continue;
        size += getTotalSize(path.join(target, entry));
    }
    return size;
}

function formatSize(bytes) {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

// --- Commands ---

function backup(targetPath, label) {
    ensureBackupDir();
    const resolved = path.resolve(targetPath);

    if (!fs.existsSync(resolved)) {
        console.error(`[-] Target not found: ${resolved}`);
        process.exit(1);
    }

    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const id = crypto.randomBytes(4).toString('hex');
    const backupName = `${timestamp}_${id}`;
    const backupPath = path.join(BACKUP_DIR, backupName);

    console.log(`[+] Backing up: ${resolved}`);
    copyRecursive(resolved, backupPath);

    const fileCount = getFileCount(resolved);
    const totalSize = getTotalSize(resolved);

    const manifest = loadManifest();
    const entry = {
        id: backupName,
        source: resolved,
        label: label || null,
        timestamp: new Date().toISOString(),
        fileCount,
        size: totalSize,
    };
    manifest.backups.push(entry);
    saveManifest(manifest);

    console.log(`[+] Backup created: ${backupName}`);
    console.log(`[+] Files: ${fileCount} | Size: ${formatSize(totalSize)}`);
    if (label) console.log(`[+] Label: ${label}`);
}

function list() {
    ensureBackupDir();
    const manifest = loadManifest();

    if (manifest.backups.length === 0) {
        console.log('[*] No backups found.');
        return;
    }

    console.log(`[+] ${manifest.backups.length} backup(s):\n`);
    console.log('  #  ID                                   Source                     Label        Files   Size');
    console.log('  ' + '-'.repeat(105));

    manifest.backups.forEach((b, i) => {
        const idx = String(i + 1).padStart(3);
        const src = b.source.length > 25 ? '...' + b.source.slice(-22) : b.source.padEnd(25);
        const label = (b.label || '-').padEnd(12);
        const files = String(b.fileCount).padStart(5);
        const size = formatSize(b.size).padStart(8);
        console.log(`  ${idx}  ${b.id}  ${src}  ${label}  ${files}  ${size}`);
    });
}

function restore(idOrIndex, destPath) {
    ensureBackupDir();
    const manifest = loadManifest();

    if (manifest.backups.length === 0) {
        console.error('[-] No backups found.');
        process.exit(1);
    }

    let entry;
    const asNum = parseInt(idOrIndex, 10);
    if (!isNaN(asNum) && asNum >= 1 && asNum <= manifest.backups.length) {
        entry = manifest.backups[asNum - 1];
    } else {
        entry = manifest.backups.find(b => b.id === idOrIndex || b.label === idOrIndex);
    }

    if (!entry) {
        console.error(`[-] Backup not found: ${idOrIndex}`);
        process.exit(1);
    }

    const backupPath = path.join(BACKUP_DIR, entry.id);
    if (!fs.existsSync(backupPath)) {
        console.error(`[-] Backup data missing for: ${entry.id}`);
        process.exit(1);
    }

    const target = destPath ? path.resolve(destPath) : entry.source;
    console.log(`[+] Restoring backup ${entry.id}`);
    console.log(`[+] To: ${target}`);

    copyRecursive(backupPath, target);
    console.log(`[+] Restore complete. Files: ${entry.fileCount} | Size: ${formatSize(entry.size)}`);
}

function remove(idOrIndex) {
    ensureBackupDir();
    const manifest = loadManifest();

    if (manifest.backups.length === 0) {
        console.error('[-] No backups found.');
        process.exit(1);
    }

    let idx;
    const asNum = parseInt(idOrIndex, 10);
    if (!isNaN(asNum) && asNum >= 1 && asNum <= manifest.backups.length) {
        idx = asNum - 1;
    } else {
        idx = manifest.backups.findIndex(b => b.id === idOrIndex || b.label === idOrIndex);
    }

    if (idx === -1) {
        console.error(`[-] Backup not found: ${idOrIndex}`);
        process.exit(1);
    }

    const entry = manifest.backups[idx];
    const backupPath = path.join(BACKUP_DIR, entry.id);

    if (fs.existsSync(backupPath)) {
        fs.rmSync(backupPath, { recursive: true, force: true });
    }

    manifest.backups.splice(idx, 1);
    saveManifest(manifest);
    console.log(`[+] Removed backup: ${entry.id}`);
}

function purge() {
    if (fs.existsSync(BACKUP_DIR)) {
        fs.rmSync(BACKUP_DIR, { recursive: true, force: true });
        console.log('[+] All backups purged.');
    } else {
        console.log('[*] Nothing to purge.');
    }
}

// --- CLI ---

const args = process.argv.slice(2);
const command = args[0];

switch (command) {
    case 'create':
        if (!args[1]) {
            console.error('Usage: node backup.cjs create <path> [label]');
            process.exit(1);
        }
        backup(args[1], args[2]);
        break;

    case 'list':
        list();
        break;

    case 'restore':
        if (!args[1]) {
            console.error('Usage: node backup.cjs restore <id|index|label> [dest_path]');
            process.exit(1);
        }
        restore(args[1], args[2]);
        break;

    case 'remove':
        if (!args[1]) {
            console.error('Usage: node backup.cjs remove <id|index|label>');
            process.exit(1);
        }
        remove(args[1]);
        break;

    case 'purge':
        purge();
        break;

    default:
        console.log(`CustomLoader Backup System

Usage: node backup.cjs <command> [options]

Commands:
  create <path> [label]              Create a backup of a file or directory
  list                               List all backups
  restore <id|index|label> [dest]    Restore a backup
  remove <id|index|label>            Remove a specific backup
  purge                              Remove all backups
`);
}
