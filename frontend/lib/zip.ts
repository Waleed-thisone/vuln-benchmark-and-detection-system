/**
 * Lightweight, zero-dependency ZIP parser for C/C++ source code extraction in the browser.
 * Uses Web Standard DecompressionStream('deflate-raw') supported natively in all modern browsers.
 */

export interface ExtractedCodeFile {
  filename: string;
  code: string;
  size: number;
}

const CPP_EXTENSION_REGEX = /\.(c|cpp|cc|cxx|h|hpp|hxx)$/i;
const MAX_FILE_SIZE = 2 * 1024 * 1024; // 2 MB per file limit to prevent browser memory issues

/**
 * Checks whether a given filename or file object is a ZIP archive.
 */
export function isZipFile(file: File | string): boolean {
  if (typeof file === "string") {
    return file.toLowerCase().endsWith(".zip");
  }
  return (
    file.name.toLowerCase().endsWith(".zip") ||
    file.type === "application/zip" ||
    file.type === "application/x-zip-compressed"
  );
}

/**
 * Parses a ZIP ArrayBuffer and extracts only C/C++ source code files.
 */
export async function extractCppFilesFromZip(
  buffer: ArrayBuffer
): Promise<ExtractedCodeFile[]> {
  const data = new Uint8Array(buffer);
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);

  // 1. Locate End of Central Directory (EOCD) record (signature: 0x06054b50)
  let eocdOffset = -1;
  const minEocdSearch = Math.max(0, data.length - 65557);
  for (let i = data.length - 22; i >= minEocdSearch; i--) {
    if (view.getUint32(i, true) === 0x06054b50) {
      eocdOffset = i;
      break;
    }
  }

  if (eocdOffset === -1) {
    throw new Error(
      "Invalid or corrupted ZIP archive: End of Central Directory not found."
    );
  }

  const entryCount = view.getUint16(eocdOffset + 10, true);
  const cdOffset = view.getUint32(eocdOffset + 16, true);

  if (cdOffset >= data.length) {
    throw new Error("Invalid ZIP archive: Central directory offset is out of bounds.");
  }

  const results: ExtractedCodeFile[] = [];
  let p = cdOffset;

  // 2. Iterate through Central Directory records (signature: 0x02014b50)
  for (let i = 0; i < entryCount && p < data.length - 46; i++) {
    if (view.getUint32(p, true) !== 0x02014b50) {
      break;
    }

    const method = view.getUint16(p + 10, true);
    const compSize = view.getUint32(p + 20, true);
    const uncompSize = view.getUint32(p + 24, true);
    const nameLen = view.getUint16(p + 28, true);
    const extraLen = view.getUint16(p + 30, true);
    const commentLen = view.getUint16(p + 32, true);
    const localHeaderOffset = view.getUint32(p + 42, true);

    if (p + 46 + nameLen > data.length) break;

    const nameBytes = data.subarray(p + 46, p + 46 + nameLen);
    const filename = new TextDecoder("utf-8", { fatal: false }).decode(nameBytes);
    p += 46 + nameLen + extraLen + commentLen;

    // Filter out directories, macOS metadata, hidden dotfiles, and non-C/C++ files
    if (
      filename.endsWith("/") ||
      filename.includes("__MACOSX") ||
      filename.split("/").some((part) => part.startsWith(".")) ||
      !CPP_EXTENSION_REGEX.test(filename)
    ) {
      continue;
    }

    // Skip excessively large individual files (prevent UI hang)
    if (uncompSize > MAX_FILE_SIZE) {
      console.warn(`Skipping ${filename}: size (${uncompSize} bytes) exceeds limit.`);
      continue;
    }

    // 3. Jump to Local File Header (signature: 0x04034b50)
    if (
      localHeaderOffset + 30 > data.length ||
      view.getUint32(localHeaderOffset, true) !== 0x04034b50
    ) {
      continue;
    }

    const localNameLen = view.getUint16(localHeaderOffset + 26, true);
    const localExtraLen = view.getUint16(localHeaderOffset + 28, true);
    const dataOffset = localHeaderOffset + 30 + localNameLen + localExtraLen;

    if (dataOffset + compSize > data.length) {
      continue;
    }

    const compressedData = data.subarray(dataOffset, dataOffset + compSize);
    let text = "";

    try {
      if (method === 0) {
        // Stored (no compression)
        text = new TextDecoder("utf-8", { fatal: false }).decode(compressedData);
      } else if (method === 8) {
        // Deflated compression
        if (typeof DecompressionStream !== "undefined") {
          const ds = new DecompressionStream("deflate-raw");
          const writer = ds.writable.getWriter();
          writer.write(compressedData);
          writer.close();
          const ab = await new Response(ds.readable).arrayBuffer();
          text = new TextDecoder("utf-8", { fatal: false }).decode(ab);
        } else {
          console.warn("DecompressionStream is not supported in this environment.");
          continue;
        }
      } else {
        console.warn(`Unsupported compression method (${method}) for ${filename}`);
        continue;
      }
    } catch (decompErr) {
      console.warn(`Failed decompressing ${filename}:`, decompErr);
      continue;
    }

    if (text.trim().length > 0) {
      results.push({
        filename,
        code: text,
        size: uncompSize,
      });
    }
  }

  return results;
}

