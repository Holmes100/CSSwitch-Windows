// 跨平台版 clean-bundle-resources.sh：打包前清理 scripts/ 下的 Python 缓存。
// bash 版本保留供 unix CI 使用；本文件供 npm scripts（含 Windows）调用。
import { readdirSync, rmSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const scriptsDir = fileURLToPath(new URL("../scripts", import.meta.url));

function clean(directory) {
  let entries;
  try {
    entries = readdirSync(directory, { withFileTypes: true });
  } catch {
    return;
  }
  for (const entry of entries) {
    const full = join(directory, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "__pycache__") {
        rmSync(full, { recursive: true, force: true });
      } else {
        clean(full);
      }
    } else if (/\.py[co]$/.test(entry.name)) {
      rmSync(full, { force: true });
    }
  }
}

clean(scriptsDir);
