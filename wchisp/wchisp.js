/*******************************************************************************
 *
 * WCH RISC-V Microcontroller Web Serial ISP
 * Copyright (c) 2025 Basil Hussain
 * 
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU Affero General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or (at your option) any
 * later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more
 * details.
 * 
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 * 
 * SPDX-License-Identifier: AGPL-3.0-or-later
 * 
 ******************************************************************************/

(() => {
  // modules/parsers/intelhex.js
  var IntelHexRecordType = class {
    static Data = new this("Data", 0);
    static EndOfFile = new this("End Of File", 1);
    static ExtSegmentAddr = new this("Extended Segment Address", 2);
    static StartSegmentAddr = new this("Start Segment Address", 3);
    static ExtLinearAddr = new this("Extended Linear Address", 4);
    static StartLinearAddr = new this("Start Linear Address", 5);
    #name;
    #value;
    constructor(name, value) {
      this.#name = name;
      this.#value = value;
    }
    get name() {
      return this.#name;
    }
    get value() {
      return this.#value;
    }
    static isValidType(value) {
      for (let t in this) {
        if (this[t].#value == value) return true;
      }
      return false;
    }
  };
  var IntelHexParser = class {
    static #calcRecordChecksum(bytes) {
      return ~bytes.reduce((sum, val) => sum = (sum + val) % 256, 0) + 1 & 255;
    }
    static parse(txt, maxSize = 1048576, minSize = 64, fillVal = 255) {
      const lines = txt.split(/\r\n|\r|\n/);
      const output = new ArrayBuffer(minSize, { maxByteLength: maxSize });
      let idx = 0, eof = false, addrBase = 0;
      const filler = new Uint8Array(output);
      filler.fill(fillVal);
      for (const line of lines) {
        ++idx;
        if (line.length == 0) continue;
        if (line.length < 11 || line[0] != ":") {
          throw new Error("Non-record or incomplete record on line " + idx);
        }
        const bytes = new Uint8Array(line.match(/[0-9a-f]{2}/gi).map((hex) => Number.parseInt(hex, 16)));
        const count = bytes.at(0);
        const addr = new DataView(bytes.buffer, 1, 2).getUint16(0);
        const type = bytes.at(3);
        const data = bytes.subarray(4, -1);
        const checksum = bytes.at(-1);
        if (count != data.length) {
          throw new Error("Byte count and length of data mismatch on line " + idx);
        }
        if (!IntelHexRecordType.isValidType(type)) {
          throw new Error("Invalid record type on line " + idx);
        }
        if (this.#calcRecordChecksum(bytes.subarray(0, -1)) != checksum) {
          throw new Error("Checksum mismatch on line " + idx);
        }
        switch (type) {
          case IntelHexRecordType.Data.value:
            if (addrBase + addr + count > output.byteLength) {
              const fillFrom = output.byteLength;
              try {
                output.resize(addrBase + addr + count);
              } catch (err) {
                if (err instanceof RangeError) {
                  err = new Error("Maximum size of " + output.maxByteLength.toLocaleString() + " bytes exceeded");
                }
                throw err;
              }
              filler.fill(fillVal, fillFrom);
            }
            new Uint8Array(output, addrBase + addr, count).set(data);
            break;
          case IntelHexRecordType.EndOfFile.value:
            eof = true;
            break;
          case IntelHexRecordType.ExtSegmentAddr.value:
            throw new Error("Extended Segment Address record type not supported");
            break;
          case IntelHexRecordType.StartSegmentAddr.value:
            throw new Error("Start Segment Address record type not supported");
            break;
          case IntelHexRecordType.ExtLinearAddr.value:
            addrBase = new DataView(bytes.buffer, 4, 2).getUint16(0) << 16;
            break;
          case IntelHexRecordType.StartLinearAddr.value:
            break;
        }
        if (eof) break;
      }
      if (!eof) throw new Error("Unexpected end of file (missing EOF record) on line " + idx);
      return new Uint8Array(output);
    }
    static get forText() {
      return true;
    }
    static get formatName() {
      return "Intel Hex";
    }
  };

  // modules/parsers/srecord.js
  var SRecordRecordType = class {
    static Header = new this("Header", 0);
    static Data16BitAddr = new this("Data (16-bit Address)", 1);
    static Data24BitAddr = new this("Data (24-bit Address)", 2);
    static Data32BitAddr = new this("Data (32-bit Address)", 3);
    static Reserved = new this("Reserved", 4);
    static RecordCount16Bit = new this("Record Count (16-bit)", 5);
    static RecordCount24Bit = new this("Record Count (24-bit)", 6);
    static StartAddr32Bit = new this("Start Address (32-bit)", 7);
    static StartAddr24Bit = new this("Start Address (24-bit)", 8);
    static StartAddr16Bit = new this("Start Address (16-bit)", 9);
    #name;
    #value;
    constructor(name, value) {
      this.#name = name;
      this.#value = value;
    }
    get name() {
      return this.#name;
    }
    get value() {
      return this.#value;
    }
    static isValidType(value) {
      for (let t in this) {
        if (this[t].#value == value) return true;
      }
      return false;
    }
  };
  var SRecordParser = class {
    static #calcRecordChecksum(bytes) {
      return 255 - bytes.reduce((sum, val) => sum = (sum + val) % 256, 0);
    }
    static parse(txt, maxSize = 1048576, minSize = 64, fillVal = 255) {
      const lines = txt.split(/\r\n|\r|\n/);
      const output = new ArrayBuffer(minSize, { maxByteLength: maxSize });
      let idx = 0, eof = false;
      const filler = new Uint8Array(output);
      filler.fill(fillVal);
      for (const line of lines) {
        ++idx;
        if (line.length == 0) continue;
        if (line.length < 10 || line[0] != "S") {
          throw new Error("Non-record or incomplete record on line " + idx);
        }
        const type = line.charCodeAt(1) - 48;
        const bytes = new Uint8Array(line.slice(2).match(/[0-9a-f]{2}/gi).map((hex) => Number.parseInt(hex, 16)));
        const count = bytes.at(0);
        const checksum = bytes.at(-1);
        if (!SRecordRecordType.isValidType(type)) {
          throw new Error("Invalid record type on line " + idx);
        }
        if (count != bytes.length - 1) {
          throw new Error("Byte count and length of data mismatch on line " + idx);
        }
        if (this.#calcRecordChecksum(bytes.subarray(0, -1)) != checksum) {
          throw new Error("Checksum mismatch on line " + idx);
        }
        const mergeDataToOutput = (addr, data) => {
          if (addr + data.length > output.byteLength) {
            const fillFrom = output.byteLength;
            try {
              output.resize(addr + data.length);
            } catch (err) {
              if (err instanceof RangeError) {
                err = new Error("Maximum size of " + output.maxByteLength.toLocaleString() + " bytes exceeded");
              }
              throw err;
            }
            filler.fill(fillVal, fillFrom);
          }
          new Uint8Array(output, addr, data.length).set(data);
        };
        switch (type) {
          case SRecordRecordType.Data16BitAddr.value:
            mergeDataToOutput(
              new DataView(bytes.buffer, 1, 2).getUint16(0),
              bytes.subarray(3, -1)
            );
            break;
          case SRecordRecordType.Data24BitAddr.value:
            mergeDataToOutput(
              new DataView(bytes.buffer, 1, 4).getUint32(0) >> 8,
              bytes.subarray(4, -1)
            );
            break;
          case SRecordRecordType.Data32BitAddr.value:
            mergeDataToOutput(
              new DataView(bytes.buffer, 1, 4).getUint32(0),
              bytes.subarray(5, -1)
            );
            break;
          case SRecordRecordType.Header.value:
          case SRecordRecordType.Reserved.value:
          case SRecordRecordType.RecordCount16Bit.value:
          case SRecordRecordType.RecordCount24Bit.value:
            break;
          case SRecordRecordType.StartAddr32Bit.value:
          case SRecordRecordType.StartAddr24Bit.value:
          case SRecordRecordType.StartAddr16Bit.value:
            eof = true;
            break;
        }
        if (eof) break;
      }
      if (!eof) throw new Error("Unexpected end of file (missing termination record) on line " + idx);
      return new Uint8Array(output);
    }
    static get forText() {
      return true;
    }
    static get formatName() {
      return "S-Record";
    }
  };

  // modules/parsers/elf.js
  var ELF_MAGIC = 2135247942;
  var ELF_CLASS_32BIT = 1;
  var ELF_DATA_LITTLE_ENDIAN = 1;
  var ELF_IDENT_VERSION_V1 = 1;
  var ELF_TYPE_EXECUTABLE = 2;
  var ELF_MACHINE_RISCV = 243;
  var ELF_VERSION_V1 = 1;
  var ELF_SECTION_TYPE_LOADABLE = 1;
  var ELF_HEADER_SIZE = 52;
  var ELF_PROGRAM_HEADER_SIZE = 32;
  var ElfRiscVParser = class {
    static parse(buf, maxSize = 1048576, minSize = 64, fillVal = 255) {
      const output = new ArrayBuffer(minSize, { maxByteLength: maxSize });
      const filler = new Uint8Array(output);
      filler.fill(fillVal);
      const header = new DataView(buf, 0, ELF_HEADER_SIZE);
      if (header.getUint32(0, false) !== ELF_MAGIC) throw new Error("Not an ELF file; non-matching magic bytes");
      if (header.getUint8(4) !== ELF_CLASS_32BIT) throw new Error("ELF must be 32-bit; 64-bit unsupported");
      if (header.getUint8(5) !== ELF_DATA_LITTLE_ENDIAN) throw new Error("ELF must be in little-endian format; big-endian unsupported");
      if (header.getUint8(6) !== ELF_IDENT_VERSION_V1) throw new Error("ELF ident version must be 1");
      if (header.getUint16(16, true) !== ELF_TYPE_EXECUTABLE) throw new Error("ELF object type is not executable");
      if (header.getUint16(18, true) !== ELF_MACHINE_RISCV) throw new Error("ELF machine ISA is not RISC-V");
      if (header.getUint32(20, true) !== ELF_VERSION_V1) throw new Error("ELF version must be 1");
      if (header.getUint16(40, true) !== ELF_HEADER_SIZE) throw new Error("ELF header size is unusual; not " + ELF_HEADER_SIZE + " bytes");
      const programHeaderOffset = header.getUint32(28, true);
      const programHeaderSize = header.getUint16(42, true);
      const programHeaderCount = header.getUint16(44, true);
      if (programHeaderSize !== ELF_PROGRAM_HEADER_SIZE) throw new Error("Unusual program header table entry size; not " + ELF_PROGRAM_HEADER_SIZE + " bytes");
      if (programHeaderCount === 0) throw new Error("Program header table entry count is zero");
      if (programHeaderOffset < ELF_HEADER_SIZE || programHeaderOffset >= buf.byteLength - programHeaderSize * programHeaderCount) {
        throw new Error("Invalid program header table offset");
      }
      for (let i = 0; i < programHeaderCount; i++) {
        const progHeader = new DataView(buf, programHeaderOffset + i * programHeaderSize, programHeaderSize);
        const type = progHeader.getUint32(0, true);
        const offset = progHeader.getUint32(4, true);
        const virtualAddr = progHeader.getUint32(8, true);
        const physicalAddr = progHeader.getUint32(12, true);
        const fileSize = progHeader.getUint32(16, true);
        const memSize = progHeader.getUint32(20, true);
        const flags = progHeader.getUint32(24, true);
        if (type === ELF_SECTION_TYPE_LOADABLE && fileSize > 0) {
          if (offset >= buf.byteLength) throw new Error("Invalid segment offset; past end of file");
          if (physicalAddr + fileSize > output.byteLength) {
            const fillFrom = output.byteLength;
            try {
              output.resize(physicalAddr + fileSize);
            } catch (err) {
              if (err instanceof RangeError) {
                err = new Error("Maximum size of " + output.maxByteLength.toLocaleString() + " bytes exceeded");
              }
              throw err;
            }
            filler.fill(fillVal, fillFrom);
          }
          const data = new Uint8Array(buf, offset, fileSize);
          new Uint8Array(output, physicalAddr, fileSize).set(data);
        }
      }
      return new Uint8Array(output);
    }
    static get forText() {
      return false;
    }
    static get formatName() {
      return "ELF";
    }
  };

  // modules/util.js
  var BYTE_UNITS = ["B", "KiB", "MiB"];
  var Formatter = class {
    static hex(values, minLen = 0) {
      if (!values.reduce) values = [values];
      return values.reduce((str, val) => {
        return str + val.toString(16).padStart(minLen, "0");
      }, "").toUpperCase();
    }
    static binary(values) {
      if (!values.reduce) values = [values];
      return values.reduce((str, val) => str + val.toString(2), "");
    }
    static printableText(values, non = ".") {
      if (!values.reduce) values = [values];
      return values.reduce((str, val) => {
        return str + (val >= 32 && val <= 126 ? String.fromCharCode(val) : non);
      }, "");
    }
    static byteSize(value) {
      const exponent = Math.min(Math.floor(Math.log(value) / Math.log(1024)), BYTE_UNITS.length - 1);
      value /= 1024 ** exponent;
      return value.toLocaleString() + " " + BYTE_UNITS[exponent];
    }
  };
  var Delay = class {
    static milliseconds(ms) {
      return new Promise((r) => setTimeout(r, ms));
    }
  };
  var ContentDispositionDecoder = class {
    static #entityDecode(str) {
      return new Uint8Array(
        // Find all percent-hex-encoded values, or regular characters, and
        // decode the hex digits to, or convert chars to, integers.
        str.match(/((?:%[0-9a-fA-F]{2})|.)/g).map((val) => val.startsWith("%") ? parseInt(val.slice(-2), 16) : val.charCodeAt(0))
      );
    }
    static #getFilenameParam(str) {
      let name = null;
      const match = str.match(/filename=(?:"((?:[^"]|\\")+)"|([^ ]+))(?:;|$)/);
      if (match) {
        if (match[1]) {
          name = match[1].replaceAll(/\\(.)/g, "$1");
        } else if (match[2]) {
          name = match[2];
        }
      }
      return name;
    }
    static #getEncodedFilenameParam(str) {
      let name = null;
      const match = str.match(/filename\*=([\w-]+)'([\w-]*)'(.+?)(?:;|$)/);
      if (match && match[1] && match[3]) {
        const bytes = this.#entityDecode(match[3]);
        name = new TextDecoder(match[1]).decode(bytes);
      }
      return name;
    }
    static getFilename(value) {
      return this.#getEncodedFilenameParam(value) || this.#getFilenameParam(value) || "[unknown]";
    }
  };

  // modules/firmware.js
  var MAX_SIZE_BYTES = 1048576;
  var Firmware = class {
    #bytes;
    #name;
    #extension;
    #format;
    constructor(bytes, name, format) {
      this.#bytes = bytes;
      this.#name = name;
      this.#extension = this.#getFilenameExtension(name);
      this.#format = format;
    }
    #getFilenameExtension(name) {
      const nameDotPos = name.lastIndexOf(".");
      return nameDotPos >= 0 ? name.slice(nameDotPos + 1).toLowerCase() : "";
    }
    fillToEndOfSegment(segmentSize, fillVal = 255) {
      if (this.#bytes.length % segmentSize != 0) {
        const oldSize = this.#bytes.length;
        const newSize = Math.ceil(this.#bytes.length / segmentSize) * segmentSize;
        this.#bytes = new Uint8Array(this.#bytes.buffer.transfer(newSize));
        this.#bytes.fill(fillVal, oldSize);
      }
    }
    getPageCount(pageSize) {
      return Math.ceil(this.#bytes.length / pageSize);
    }
    getSectorCount(sectorSize) {
      return Math.ceil(this.#bytes.length / sectorSize);
    }
    get fileName() {
      return this.#name;
    }
    get fileExtension() {
      return this.#extension;
    }
    get size() {
      return this.#bytes.length;
    }
    get bytes() {
      return this.#bytes;
    }
    get format() {
      return this.#format;
    }
  };
  var FirmwareLoader = class extends EventTarget {
    #parsers = /* @__PURE__ */ new Map();
    constructor() {
      super();
    }
    #getFilenameExtension(name) {
      const nameDotPos = name.lastIndexOf(".");
      return nameDotPos >= 0 ? name.slice(nameDotPos + 1).toLowerCase() : "";
    }
    #getUrlResponseFilename(response) {
      if (response.headers.has("Content-Disposition")) {
        return ContentDispositionDecoder.getFilename(response.headers.get("Content-Disposition"));
      }
      const url = new URL(response.url);
      const slashPos = url.pathname.lastIndexOf("/");
      if (url.pathname.length > 1 && slashPos >= 0) {
        return url.pathname.slice(slashPos + 1);
      }
      return "[unknown]";
    }
    #progressEvent(incr, total) {
      this.dispatchEvent(new CustomEvent("progress", {
        detail: {
          increment: incr,
          total
        }
      }));
    }
    async #parseBlob(blob, name) {
      if (blob.size == 0) throw new Error("No data to parse; file is empty");
      const extension = this.#getFilenameExtension(name);
      let bytes, format;
      if (this.#parsers.has(extension)) {
        const parser = this.#parsers.get(extension);
        if (parser.forText) {
          bytes = parser.parse(await blob.text(), MAX_SIZE_BYTES);
        } else {
          bytes = parser.parse(await blob.arrayBuffer(), MAX_SIZE_BYTES);
        }
        format = parser.formatName;
      } else {
        if (blob.size > MAX_SIZE_BYTES) {
          throw new Error("Maximum size of " + MAX_SIZE_BYTES.toLocaleString() + " bytes exceeded");
        }
        bytes = new Uint8Array(await blob.arrayBuffer());
        format = "Raw Binary";
      }
      return { bytes, format };
    }
    addParser(extensions, parser) {
      for (const ext of extensions) {
        this.#parsers.set(ext.trim().toLowerCase(), parser);
      }
    }
    async fromFile(file) {
      const { bytes, format } = await this.#parseBlob(file, file.name);
      return new Firmware(bytes, file.name, format);
    }
    async fromUrl(urlStr) {
      const protoMatch = urlStr.match(/^([a-z]+):\/\//i);
      if (!protoMatch) {
        urlStr = "http://" + urlStr;
      } else if (protoMatch[1].toLowerCase() !== "http" && protoMatch[1].toLowerCase() !== "https") {
        throw new Error("Loading from non-HTTP protocol URLs not supported");
      }
      const url = URL.parse(urlStr);
      if (!url) throw new Error('URL "' + urlStr + '" is not valid');
      this.#progressEvent(null, null);
      const response = await window.fetch(url);
      if (!response.ok) {
        throw new Error("Server response: " + response.status + " " + response.statusText);
      }
      const reader = response.body.getReader();
      let totalLength = Number.parseInt(response.headers.get("Content-Length")) || 0;
      if (response.headers.has("Content-Encoding")) totalLength *= 2;
      let chunks = [];
      let receivedLength = 0;
      this.#progressEvent(receivedLength, totalLength);
      while (true) {
        const { value: chunk, done } = await reader.read();
        if (done) break;
        chunks.push(chunk);
        receivedLength += chunk.length;
        totalLength = Math.max(receivedLength, totalLength);
        this.#progressEvent(receivedLength, totalLength);
      }
      this.#progressEvent(totalLength, totalLength);
      const name = this.#getUrlResponseFilename(response);
      const blob = new Blob(chunks, {
        type: response.headers.get("Content-Type"),
        endings: "native"
      });
      const { bytes, format } = await this.#parseBlob(blob, name);
      return new Firmware(bytes, name, format);
    }
  };

  // modules/command.js
  var CommandType = class _CommandType {
    static Identify = new _CommandType("Identify", 161);
    static End = new _CommandType("End", 162);
    static Key = new _CommandType("Key", 163);
    static FlashErase = new _CommandType("FlashErase", 164);
    static FlashWrite = new _CommandType("FlashWrite", 165);
    static FlashVerify = new _CommandType("FlashVerify", 166);
    static ConfigRead = new _CommandType("ConfigRead", 167);
    static ConfigWrite = new _CommandType("ConfigWrite", 168);
    #name;
    #code;
    constructor(name, code) {
      this.#name = name;
      this.#code = code;
    }
    toString() {
      return "CommandType." + this.#name;
    }
    get code() {
      return this.#code;
    }
    static isValidCode(code) {
      for (let t in _CommandType) {
        if (_CommandType[t].#code == code) return true;
      }
      return false;
    }
  };
  var Command = class {
    #type;
    #data = [];
    #length = 0;
    constructor(type, data, length = data.length) {
      this.#type = type;
      this.#data = data;
      this.#length = length;
    }
    toBytes() {
      const buf = new ArrayBuffer(this.#length + 3);
      const bytes = new Uint8Array(buf);
      bytes[0] = this.#type.code;
      new DataView(buf).setUint16(1, this.#length, true);
      bytes.set(this.#data, 3);
      return bytes;
    }
    get data() {
      return this.#data;
    }
    get length() {
      return this.#length;
    }
  };
  var IdentifyCommand = class extends Command {
    constructor(dev_variant, dev_type) {
      const passwd = "MCU ISP & WCH.CN";
      const data = new Uint8Array(2 + passwd.length);
      data[0] = dev_variant;
      data[1] = dev_type;
      new TextEncoder().encodeInto(passwd, data.subarray(2));
      super(CommandType.Identify, data);
    }
  };
  var EndCommand = class extends Command {
    constructor(do_reset) {
      super(CommandType.End, [do_reset ? 1 : 0]);
    }
  };
  var KeyCommand = class extends Command {
    #key = new Uint8Array(8);
    #key_checksum = 0;
    constructor(unique_id, dev_variant, seed_len = 60) {
      seed_len = Math.min(Math.max(seed_len, 30), 60);
      const a = Math.floor(seed_len / 5);
      const b = Math.floor(seed_len / 7);
      const seed = crypto.getRandomValues(new Uint8Array(seed_len));
      super(CommandType.Key, seed);
      const unique_id_checksum = unique_id.reduce((acc, val) => acc = (acc + val) % 256, 0);
      this.#key[0] = unique_id_checksum ^ seed[b * 4];
      this.#key[1] = unique_id_checksum ^ seed[a];
      this.#key[2] = unique_id_checksum ^ seed[b];
      this.#key[3] = unique_id_checksum ^ seed[b * 6];
      this.#key[4] = unique_id_checksum ^ seed[b * 3];
      this.#key[5] = unique_id_checksum ^ seed[a * 3];
      this.#key[6] = unique_id_checksum ^ seed[b * 5];
      this.#key[7] = (this.#key[0] + dev_variant) % 256;
      this.#key_checksum = this.#key.reduce((acc, val) => acc = (acc + val) % 256, 0);
    }
    get key() {
      return this.#key;
    }
    get keyChecksum() {
      return this.#key_checksum;
    }
  };
  var FlashEraseCommand = class extends Command {
    constructor(num_sectors) {
      const buf = new ArrayBuffer(4);
      new DataView(buf).setUint32(0, num_sectors, true);
      super(CommandType.FlashErase, new Uint8Array(buf));
    }
  };
  var FlashWriteCommand = class extends Command {
    constructor(addr, data, key) {
      const buf = new ArrayBuffer(5 + data.length);
      new DataView(buf).setUint32(0, addr, true);
      if (data.length > 0 && key.length > 0) {
        new Uint8Array(buf, 5, data.length).set(data.map((val, idx) => val ^ key[idx % key.length]));
      }
      super(CommandType.FlashWrite, new Uint8Array(buf));
    }
  };
  var FlashVerifyCommand = class extends Command {
    constructor(addr, data, key) {
      const buf = new ArrayBuffer(5 + data.length);
      new DataView(buf).setUint32(0, addr, true);
      if (data.length > 0 && key.length > 0) {
        new Uint8Array(buf, 5, data.length).set(data.map((val, idx) => val ^ key[idx % key.length]));
      }
      super(CommandType.FlashVerify, new Uint8Array(buf));
    }
  };
  var ConfigReadCommand = class extends Command {
    constructor() {
      super(CommandType.ConfigRead, [31, 0]);
    }
  };
  var ConfigWriteCommand = class extends Command {
    constructor(config) {
      const data = new Uint8Array(14);
      data[0] = 7;
      data[2] = config[0];
      data[3] = ~config[0];
      data[4] = config[1];
      data[5] = ~config[1];
      data[6] = config[2];
      data[7] = ~config[2];
      data[8] = config[3];
      data[9] = ~config[3];
      data.set(config.slice(4, 8), 10);
      super(CommandType.ConfigWrite, data);
    }
  };

  // modules/response.js
  var ResponseType = class _ResponseType {
    static Identify = new _ResponseType("Identify", 161, 6);
    static End = new _ResponseType("End", 162, 6);
    static Key = new _ResponseType("Key", 163, 6);
    static FlashErase = new _ResponseType("FlashErase", 164, 6);
    static FlashWrite = new _ResponseType("FlashWrite", 165, 6);
    static FlashVerify = new _ResponseType("FlashVerify", 166, 6);
    static ConfigRead = new _ResponseType("ConfigRead", 167, 30);
    static ConfigWrite = new _ResponseType("ConfigWrite", 168, 6);
    #name;
    #code;
    #size;
    constructor(name, code, size) {
      this.#name = name;
      this.#code = code;
      this.#size = size;
    }
    toString() {
      return "ResponseType." + this.#name;
    }
    get code() {
      return this.#code;
    }
    get size() {
      return this.#size;
    }
    static fromCode(code) {
      for (let t in _ResponseType) {
        if (_ResponseType[t].#code == code) return _ResponseType[t];
      }
      return void 0;
    }
  };
  var Response = class {
    #type;
    #data = [];
    #length = 0;
    constructor(type, data, length = data.length) {
      this.#type = type;
      this.#data = data;
      this.#length = length;
    }
    // TODO: maybe change this to a read-only property?
    isValid() {
      return this.#type instanceof ResponseType && this.#length > 0 && this.#data.length > 0 && this.#length == this.#data.length;
    }
    get data() {
      return this.#data;
    }
    get length() {
      return this.#length;
    }
    static fromPacket(packet) {
      return this.fromBytes(packet.payload);
    }
    static fromBytes(bytes) {
      if (bytes.length >= 4) {
        return new this(
          ResponseType.fromCode(bytes[0]),
          bytes.slice(4),
          new DataView(bytes.buffer).getUint16(2, true)
          // little-endian
        );
      } else {
        return void 0;
      }
    }
  };
  var IdentifyResponse = class extends Response {
    get success() {
      return this.length == 2 && this.data[0] < 240;
    }
    get deviceVariant() {
      return this.data[0];
    }
    get deviceType() {
      return this.data[1];
    }
  };
  var EndResponse = class extends Response {
    get success() {
      return this.length == 2 && this.data[0] == 0;
    }
  };
  var KeyResponse = class extends Response {
    get success() {
      return this.length == 2 && this.data[0] > 0;
    }
    get keyChecksum() {
      return this.data[0];
    }
  };
  var FlashEraseResponse = class extends Response {
    get success() {
      return this.length == 2 && this.data[0] == 0;
    }
  };
  var FlashWriteResponse = class extends Response {
    get success() {
      return this.length == 2 && this.data[0] == 0;
    }
  };
  var FlashVerifyResponse = class extends Response {
    get success() {
      return this.length == 2 && this.data[0] == 0;
    }
  };
  var ConfigReadResponse = class extends Response {
    get success() {
      return this.length == 26 && this.data[0] > 0;
    }
    get optionBytesRaw() {
      return [
        this.data[2],
        this.data[4],
        this.data[6],
        this.data[8]
      ].concat(Array.from(this.data.subarray(10, 14)));
    }
    get optionBytes() {
      return {
        "rdpr": this.data[2],
        "user": this.data[4],
        "data": [this.data[6], this.data[8]],
        "wrpr": Array.from(this.data.subarray(10, 14))
      };
    }
    get bootloaderVersion() {
      return {
        "major": this.data[14] * 10 + this.data[15],
        "minor": this.data[16] * 10 + this.data[17]
      };
    }
    get chipUniqueID() {
      return this.data.slice(18);
    }
  };
  var ConfigWriteResponse = class extends Response {
    get success() {
      return this.length == 2 && this.data[0] == 0;
    }
  };
  var InvalidResponseError = class extends Error {
    constructor() {
      super("Invalid response; unknown type or bad data length");
    }
  };
  var UnsuccessfulResponseError = class extends Error {
    constructor() {
      super("Unsuccessful response; command returned error");
    }
  };

  // modules/packet.js
  var PacketType = class _PacketType {
    static Command = new _PacketType("Command", [87, 171]);
    static Response = new _PacketType("Response", [85, 170]);
    #name;
    #header;
    constructor(name, header) {
      this.#name = name;
      this.#header = header;
    }
    toString() {
      return "PacketType." + this.#name;
    }
    get header() {
      return this.#header;
    }
  };
  var Packet = class {
    #type;
    #header = [];
    #payload = [];
    #checksum = 0;
    constructor(payload, type = PacketType.Command) {
      this.#type = type;
      this.#header = type.header;
      this.#payload = payload;
      this.#checksum = this.calculateChecksum();
    }
    calculateChecksum() {
      return this.#payload.reduce((acc, val) => acc = (acc + val) % 256, 0);
    }
    // TODO: maybe change this to a read-only property?
    isValid() {
      return this.#header.length == this.#type.header.length && this.#header.every((val, idx) => val == this.#type.header[idx]) && this.#checksum == this.calculateChecksum();
    }
    toBytes() {
      const packet = new Uint8Array(this.#payload.length + 3);
      packet.set(this.#header, 0);
      packet.set(this.#payload, 2);
      packet[this.#payload.length + 2] = this.#checksum;
      return packet;
    }
    toString() {
      let str = "";
      str += Formatter.hex(this.#header, 2);
      str += Formatter.hex(this.#payload, 2);
      str += Formatter.hex(this.#checksum, 2);
      return str;
    }
    get length() {
      return this.#header.length + this.#payload.length + 1;
    }
    get payload() {
      return this.#payload;
    }
    static fromCommand(cmd) {
      return new this(cmd.toBytes());
    }
    static fromBytes(bytes) {
      if (bytes.length >= 3) {
        const packet = new this(bytes.slice(2, -1), PacketType.Response);
        packet.#header = bytes.slice(0, 2);
        packet.#checksum = bytes.at(-1);
        return packet;
      } else {
        return void 0;
      }
    }
    static sizeForResponseType(type) {
      return type.size + 3;
    }
  };
  var InvalidPacketError = class extends Error {
    constructor() {
      super("Invalid packet; bad header or checksum");
    }
  };

  // modules/transceiver.js
  var PORT_FLUSH_BLOCKLIST = [
    // Silicon Labs CP2102N
    { vid: 4292, pid: 6e4 },
    { vid: 4292, pid: 60001 },
    { vid: 4292, pid: 60003 }
  ];
  var Transceiver = class {
    #port;
    #dtrRtsReset = false;
    constructor(dtrRtsReset = false) {
      this.#dtrRtsReset = dtrRtsReset;
    }
    #canFlushPort(vid, pid) {
      return !PORT_FLUSH_BLOCKLIST.some((elem) => elem.vid === vid && elem.pid === pid);
    }
    async #resetWithDtrRts(resetPeriodMs = 100, delayPeriodMs = 100) {
      try {
        await this.#port.setSignals({
          dataTerminalReady: false,
          requestToSend: true
        });
        await Delay.milliseconds(resetPeriodMs);
        await this.#port.setSignals({
          dataTerminalReady: true,
          requestToSend: false
        });
        await Delay.milliseconds(delayPeriodMs);
        await this.#port.setSignals({
          dataTerminalReady: false
        });
      } catch (err) {
        throw new Error("Error occurred attempting to toggle DTR/RTS sequence for reset into bootloader", { cause: err });
      }
    }
    async open() {
      if (!("serial" in navigator)) {
        throw new Error("Web Serial API is unsupported by this browser");
      }
      try {
        this.#port = await navigator.serial.requestPort();
      } catch (err) {
        throw new Error("Serial port selection cancelled or permission denied", { cause: err });
      }
      const portInfo = this.#port.getInfo();
      try {
        await this.#port.open({
          baudRate: 115200,
          dataBits: 8,
          stopBits: 1,
          parity: "none",
          flowControl: "none"
        });
        if (this.#canFlushPort(portInfo.usbVendorId, portInfo.usbProductId)) {
          await this.#port.readable.cancel();
        }
      } catch (err) {
        throw new Error("Error occurred attempting to open serial port", { cause: err });
      }
      if (this.#dtrRtsReset) {
        await this.#resetWithDtrRts();
      }
    }
    async transmitPacket(packet) {
      const writer = this.#port.writable.getWriter();
      await writer.write(packet.toBytes());
      writer.releaseLock();
    }
    async receivePacket(length, timeout_ms = 3e3) {
      const bytes = new Uint8Array(length);
      let offset = 0, stop = false, error;
      const reader = this.#port.readable.getReader();
      const timer = setTimeout(() => {
        stop = true;
        reader.releaseLock();
      }, timeout_ms);
      while (!stop && offset < bytes.length) {
        try {
          const { value: chunk, done } = await reader.read();
          if (done) break;
          if (offset + chunk.length <= bytes.length) {
            bytes.set(chunk, offset);
            offset += chunk.length;
          } else {
            error = new Error("Unexpected data; received more than " + bytes.length + " bytes");
            break;
          }
        } catch (err) {
          error = new Error("Timed-out after " + timeout_ms + " ms waiting to receive, or read failure", { cause: err });
          break;
        }
      }
      clearTimeout(timer);
      reader.releaseLock();
      if (error) throw error;
      return Packet.fromBytes(bytes);
    }
    async close() {
      if (this.#port !== void 0) {
        await this.#port.close();
      }
    }
  };

  // modules/logger.js
  var LoggerLevel = class _LoggerLevel {
    static Info = new _LoggerLevel("Info", " INFO");
    static Warning = new _LoggerLevel("Warning", " WARN");
    static Error = new _LoggerLevel("Error", "ERROR");
    static Debug = new _LoggerLevel("Debug", "DEBUG");
    #name;
    #shortName;
    constructor(name, shortName) {
      this.#name = name;
      this.#shortName = shortName;
    }
    get name() {
      return this.#name;
    }
    get shortName() {
      return this.#shortName;
    }
  };
  var Logger = class {
    #output = console.log;
    constructor(outputCallback) {
      if (!(outputCallback instanceof Function)) {
        throw new Error("Output argument must be a callback function");
      }
      this.#output = outputCallback;
    }
    #outputMessage(msg, level = void 0) {
      if (!(level instanceof LoggerLevel)) level = LoggerLevel.Info;
      this.#output(msg, /* @__PURE__ */ new Date(), level.name, level.shortName);
    }
    log(...messages) {
      for (const msg of messages) {
        this.#outputMessage(msg, LoggerLevel.Info);
      }
    }
    info(...messages) {
      for (const msg of messages) {
        this.#outputMessage(msg, LoggerLevel.Info);
      }
    }
    warn(...messages) {
      for (const msg of messages) {
        this.#outputMessage(msg, LoggerLevel.Warning);
      }
    }
    error(...messages) {
      for (const msg of messages) {
        this.#outputMessage(msg, LoggerLevel.Error);
      }
    }
    debug(...messages) {
      for (const msg of messages) {
        this.#outputMessage(msg, LoggerLevel.Debug);
      }
    }
  };

  // modules/session.js
  var CHUNK_SIZE = 56;
  var Session = class extends EventTarget {
    #trx;
    #device;
    #logger = console;
    #optBytes;
    #bootVer;
    #chipUID;
    #key;
    #sequence = 0;
    constructor(deviceVariant, deviceType, deviceDtrRtsReset) {
      super();
      this.#trx = new Transceiver(deviceDtrRtsReset);
      this.#device = { variant: deviceVariant, type: deviceType };
    }
    #logPacket(prefix, packet) {
      this.#logger.debug(prefix + " (" + packet.length + " bytes): " + packet.toString());
    }
    #progressEvent(incr, total) {
      this.dispatchEvent(new CustomEvent("progress", {
        detail: {
          increment: incr,
          total
        }
      }));
    }
    setLogger(logger2) {
      if (!(logger2 instanceof Logger)) throw new Error("Logger argument must be a Logger object");
      this.#logger = logger2;
    }
    async start() {
      this.#logger.info("Starting new session");
      await this.#trx.open();
      this.#sequence = 0;
    }
    async end() {
      await this.#trx.close();
      this.#logger.info("Ended session");
    }
    async identify() {
      this.#logger.debug(++this.#sequence + ": Identify");
      let packet, cmd, resp;
      this.#progressEvent(null, null);
      cmd = new IdentifyCommand(this.#device.variant, this.#device.type);
      packet = Packet.fromCommand(cmd);
      this.#logPacket("TX", packet);
      await this.#trx.transmitPacket(packet);
      packet = await this.#trx.receivePacket(Packet.sizeForResponseType(ResponseType.Identify));
      this.#logPacket("RX", packet);
      if (!packet.isValid()) throw new InvalidPacketError();
      resp = IdentifyResponse.fromPacket(packet);
      if (!resp.isValid()) throw new InvalidResponseError();
      if (!resp.success) throw new UnsuccessfulResponseError();
      this.#logger.info(
        "Device variant: 0x" + Formatter.hex(resp.deviceVariant, 2) + ", type: 0x" + Formatter.hex(resp.deviceType, 2)
      );
      if (resp.deviceType != this.#device.type) {
        throw new Error("Reported device type does not match selected device");
      } else if (resp.deviceVariant != this.#device.variant) {
        this.#logger.warn("Reported device variant does not match selected device");
      }
      this.#device = {
        variant: resp.deviceVariant,
        type: resp.deviceType
      };
      this.#progressEvent(100, 100);
      return this.#device;
    }
    async reset(doReset) {
      this.#logger.debug(++this.#sequence + ": Reset");
      let packet, cmd, resp;
      this.#progressEvent(null, null);
      cmd = new EndCommand(doReset);
      packet = Packet.fromCommand(cmd);
      this.#logPacket("TX", packet);
      await this.#trx.transmitPacket(packet);
      packet = await this.#trx.receivePacket(Packet.sizeForResponseType(ResponseType.End));
      this.#logPacket("RX", packet);
      if (!packet.isValid()) throw new InvalidPacketError();
      resp = EndResponse.fromPacket(packet);
      if (!resp.isValid()) throw new InvalidResponseError();
      if (!resp.success) throw new UnsuccessfulResponseError();
      this.#progressEvent(100, 100);
    }
    async keyGenerate() {
      this.#logger.debug(++this.#sequence + ": Key Generate");
      let packet, cmd, resp;
      this.#progressEvent(null, null);
      cmd = new KeyCommand(this.#chipUID, this.#device.variant);
      packet = Packet.fromCommand(cmd);
      this.#logPacket("TX", packet);
      await this.#trx.transmitPacket(packet);
      this.#key = cmd.key;
      packet = await this.#trx.receivePacket(Packet.sizeForResponseType(ResponseType.Key));
      this.#logPacket("RX", packet);
      if (!packet.isValid()) throw new InvalidPacketError();
      resp = KeyResponse.fromPacket(packet);
      if (!resp.isValid()) throw new InvalidResponseError();
      if (!resp.success) throw new UnsuccessfulResponseError();
      if (cmd.keyChecksum != resp.keyChecksum) throw new Error("Key checksum mismatch");
      this.#progressEvent(100, 100);
      return this.#key;
    }
    async flashErase(sectorCount) {
      this.#logger.debug(++this.#sequence + ": Flash Erase");
      let packet, cmd, resp;
      this.#progressEvent(null, null);
      cmd = new FlashEraseCommand(sectorCount);
      packet = Packet.fromCommand(cmd);
      this.#logPacket("TX", packet);
      await this.#trx.transmitPacket(packet);
      packet = await this.#trx.receivePacket(Packet.sizeForResponseType(ResponseType.FlashErase));
      this.#logPacket("RX", packet);
      if (!packet.isValid()) throw new InvalidPacketError();
      resp = FlashEraseResponse.fromPacket(packet);
      if (!resp.isValid()) throw new InvalidResponseError();
      if (!resp.success) throw new UnsuccessfulResponseError();
      this.#progressEvent(100, 100);
    }
    async flashWrite(bytes) {
      this.#logger.debug(++this.#sequence + ": Flash Write");
      let packet, cmd, resp;
      for (let offset = 0; offset < bytes.length; offset += CHUNK_SIZE) {
        this.#progressEvent(offset, bytes.length);
        cmd = new FlashWriteCommand(offset, bytes.subarray(offset, offset + CHUNK_SIZE), this.#key);
        packet = Packet.fromCommand(cmd);
        this.#logPacket("TX", packet);
        await this.#trx.transmitPacket(packet);
        packet = await this.#trx.receivePacket(Packet.sizeForResponseType(ResponseType.FlashWrite));
        this.#logPacket("RX", packet);
        if (!packet.isValid()) throw new InvalidPacketError();
        resp = FlashWriteResponse.fromPacket(packet);
        if (!resp.isValid()) throw new InvalidResponseError();
        if (!resp.success) throw new UnsuccessfulResponseError();
      }
      cmd = new FlashWriteCommand(bytes.length, new Uint8Array(0), this.#key);
      packet = Packet.fromCommand(cmd);
      this.#logPacket("TX", packet);
      await this.#trx.transmitPacket(packet);
      packet = await this.#trx.receivePacket(Packet.sizeForResponseType(ResponseType.FlashWrite));
      this.#logPacket("RX", packet);
      if (!packet.isValid()) throw new InvalidPacketError();
      resp = FlashWriteResponse.fromPacket(packet);
      if (!resp.isValid()) throw new InvalidResponseError();
      if (!resp.success) throw new UnsuccessfulResponseError();
      this.#progressEvent(bytes.length, bytes.length);
    }
    async flashVerify(bytes) {
      this.#logger.debug(++this.#sequence + ": Flash Verify");
      let packet, cmd, resp;
      for (let offset = 0; offset < bytes.length; offset += CHUNK_SIZE) {
        this.#progressEvent(offset, bytes.length);
        cmd = new FlashVerifyCommand(offset, bytes.subarray(offset, offset + CHUNK_SIZE), this.#key);
        packet = Packet.fromCommand(cmd);
        this.#logPacket("TX", packet);
        await this.#trx.transmitPacket(packet);
        packet = await this.#trx.receivePacket(Packet.sizeForResponseType(ResponseType.FlashVerify));
        this.#logPacket("RX", packet);
        if (!packet.isValid()) throw new InvalidPacketError();
        resp = FlashVerifyResponse.fromPacket(packet);
        if (!resp.isValid()) throw new InvalidResponseError();
        if (!resp.success) throw new UnsuccessfulResponseError();
      }
      this.#progressEvent(bytes.length, bytes.length);
    }
    async configRead() {
      this.#logger.debug(++this.#sequence + ": Config Read");
      let packet, cmd, resp;
      this.#progressEvent(null, null);
      cmd = new ConfigReadCommand();
      packet = Packet.fromCommand(cmd);
      this.#logPacket("TX", packet);
      await this.#trx.transmitPacket(packet);
      packet = await this.#trx.receivePacket(Packet.sizeForResponseType(ResponseType.ConfigRead));
      this.#logPacket("RX", packet);
      if (!packet.isValid()) throw new InvalidPacketError();
      resp = ConfigReadResponse.fromPacket(packet);
      if (!resp.isValid()) throw new InvalidResponseError();
      if (!resp.success) throw new UnsuccessfulResponseError();
      if (resp.chipUniqueID.length == 8) {
        const uidWords = new Uint16Array(resp.chipUniqueID.buffer, 0, 4);
        if ((uidWords[0] + uidWords[1] + uidWords[2]) % 65536 != uidWords[3]) {
          this.#logger.warn("Possibly invalid chip unique ID; checksum mismatch");
        }
      }
      this.#optBytes = resp.optionBytesRaw;
      this.#bootVer = resp.bootloaderVersion;
      this.#chipUID = resp.chipUniqueID;
      this.#logger.info("Device configuration:");
      this.#logger.info("   RDPR: 0x" + Formatter.hex(this.#optBytes[0], 2));
      this.#logger.info("   USER: 0x" + Formatter.hex(this.#optBytes[1], 2));
      this.#logger.info("  DATA0: 0x" + Formatter.hex(this.#optBytes[2], 2));
      this.#logger.info("  DATA1: 0x" + Formatter.hex(this.#optBytes[3], 2));
      this.#logger.info("  WRPR0: 0x" + Formatter.hex(this.#optBytes[4], 2));
      this.#logger.info("  WRPR1: 0x" + Formatter.hex(this.#optBytes[5], 2));
      this.#logger.info("  WRPR2: 0x" + Formatter.hex(this.#optBytes[6], 2));
      this.#logger.info("  WRPR3: 0x" + Formatter.hex(this.#optBytes[7], 2));
      this.#logger.info("  BTVER: " + this.#bootVer["major"] + "." + this.#bootVer["minor"]);
      this.#logger.info("  UNIID: " + Formatter.hex(this.#chipUID, 2));
      this.#progressEvent(100, 100);
      return {
        optionBytes: this.#optBytes,
        bootloaderVersion: this.#bootVer,
        chipUniqueID: this.#chipUID
      };
    }
    async configWrite(config) {
      this.#logger.debug(++this.#sequence + ": Config Write");
      let packet, cmd, resp;
      this.#progressEvent(null, null);
      cmd = new ConfigWriteCommand(config);
      packet = Packet.fromCommand(cmd);
      this.#logPacket("TX", packet);
      await this.#trx.transmitPacket(packet);
      packet = await this.#trx.receivePacket(Packet.sizeForResponseType(ResponseType.ConfigWrite));
      this.#logPacket("RX", packet);
      if (!packet.isValid()) throw new InvalidPacketError();
      resp = ConfigWriteResponse.fromPacket(packet);
      if (!resp.isValid()) throw new InvalidResponseError();
      if (!resp.success) throw new UnsuccessfulResponseError();
      this.#progressEvent(100, 100);
    }
  };

  // modules/devices.json
  var devices_default = [
    {
      family: "CH32V00x",
      devices: [
        {
          name: "CH32V002A4M6",
          package: "SOP16",
          type: 33,
          variant: 34,
          flash: {
            size: 16384,
            page_size: 256,
            page_count: 64,
            sector_size: 1024,
            sector_count: 16
          }
        },
        {
          name: "CH32V002D4U6",
          package: "QFN12",
          type: 33,
          variant: 35,
          flash: {
            size: 16384,
            page_size: 256,
            page_count: 64,
            sector_size: 1024,
            sector_count: 16
          }
        },
        {
          name: "CH32V002F4P6",
          package: "TSSOP20",
          type: 33,
          variant: 32,
          flash: {
            size: 16384,
            page_size: 256,
            page_count: 64,
            sector_size: 1024,
            sector_count: 16
          }
        },
        {
          name: "CH32V002F4U6",
          package: "QFN20",
          type: 33,
          variant: 33,
          flash: {
            size: 16384,
            page_size: 256,
            page_count: 64,
            sector_size: 1024,
            sector_count: 16
          }
        },
        {
          name: "CH32V002J4M6",
          package: "SOP8",
          type: 33,
          variant: 36,
          flash: {
            size: 16384,
            page_size: 256,
            page_count: 64,
            sector_size: 1024,
            sector_count: 16
          }
        },
        {
          name: "CH32V003F4P6",
          package: "TSSOP20",
          type: 33,
          variant: 48,
          flash: {
            size: 16384,
            page_size: 64,
            page_count: 256,
            sector_size: 1024,
            sector_count: 16
          }
        },
        {
          name: "CH32V003F4U6",
          package: "QFN20",
          type: 33,
          variant: 49,
          flash: {
            size: 16384,
            page_size: 64,
            page_count: 256,
            sector_size: 1024,
            sector_count: 16
          }
        },
        {
          name: "CH32V003A4M6",
          package: "SOP16",
          type: 33,
          variant: 50,
          flash: {
            size: 16384,
            page_size: 64,
            page_count: 256,
            sector_size: 1024,
            sector_count: 16
          }
        },
        {
          name: "CH32V003J4M6",
          package: "SOP8",
          type: 33,
          variant: 51,
          flash: {
            size: 16384,
            page_size: 64,
            page_count: 256,
            sector_size: 1024,
            sector_count: 16
          }
        },
        {
          name: "CH32V004F6P1",
          package: "TSSOP20",
          type: 33,
          variant: 64,
          flash: {
            size: 32768,
            page_size: 256,
            page_count: 128,
            sector_size: 1024,
            sector_count: 32
          }
        },
        {
          name: "CH32V004F6U1",
          package: "QFN20",
          type: 33,
          variant: 65,
          flash: {
            size: 32768,
            page_size: 256,
            page_count: 128,
            sector_size: 1024,
            sector_count: 32
          }
        },
        {
          name: "CH32V005D6U6",
          package: "QFN12",
          type: 33,
          variant: 83,
          flash: {
            size: 32768,
            page_size: 256,
            page_count: 128,
            sector_size: 1024,
            sector_count: 32
          }
        },
        {
          name: "CH32V005E6R6",
          package: "QSOP24",
          type: 33,
          variant: 80,
          flash: {
            size: 32768,
            page_size: 256,
            page_count: 128,
            sector_size: 1024,
            sector_count: 32
          }
        },
        {
          name: "CH32V005F6P6",
          package: "TSSOP20",
          type: 33,
          variant: 82,
          flash: {
            size: 32768,
            page_size: 256,
            page_count: 128,
            sector_size: 1024,
            sector_count: 32
          }
        },
        {
          name: "CH32V005F6U6",
          package: "QFN20",
          type: 33,
          variant: 81,
          flash: {
            size: 32768,
            page_size: 256,
            page_count: 128,
            sector_size: 1024,
            sector_count: 32
          }
        },
        {
          name: "CH32V006E8R6",
          package: "QSOP24",
          type: 33,
          variant: 97,
          flash: {
            size: 63488,
            page_size: 256,
            page_count: 248,
            sector_size: 1024,
            sector_count: 62
          }
        },
        {
          name: "CH32V006F8P6",
          package: "TSSOP20",
          type: 33,
          variant: 99,
          flash: {
            size: 63488,
            page_size: 256,
            page_count: 248,
            sector_size: 1024,
            sector_count: 62
          }
        },
        {
          name: "CH32V006F8U6",
          package: "QFN20",
          type: 33,
          variant: 98,
          flash: {
            size: 63488,
            page_size: 256,
            page_count: 248,
            sector_size: 1024,
            sector_count: 62
          }
        },
        {
          name: "CH32V006K8U6",
          package: "QFN32",
          type: 33,
          variant: 96,
          flash: {
            size: 63488,
            page_size: 256,
            page_count: 248,
            sector_size: 1024,
            sector_count: 62
          }
        },
        {
          name: "CH32V007E8R6",
          package: "QSOP24",
          type: 33,
          variant: 113,
          flash: {
            size: 63488,
            page_size: 256,
            page_count: 248,
            sector_size: 1024,
            sector_count: 62
          }
        },
        {
          name: "CH32V007K8U6",
          package: "QFN32",
          type: 33,
          variant: 114,
          flash: {
            size: 63488,
            page_size: 256,
            page_count: 248,
            sector_size: 1024,
            sector_count: 62
          }
        }
      ]
    },
    {
      family: "CH32L103",
      devices: [
        {
          name: "CH32L103C8T6",
          package: "LQFP48",
          type: 37,
          variant: 49,
          flash: {
            size: 65536,
            page_size: 256,
            page_count: 256,
            sector_size: 1024,
            sector_count: 64
          }
        },
        {
          name: "CH32L103F8P6",
          package: "TSSOP20",
          type: 37,
          variant: 58,
          flash: {
            size: 65536,
            page_size: 256,
            page_count: 256,
            sector_size: 1024,
            sector_count: 64
          }
        },
        {
          name: "CH32L103F8U6",
          package: "QFN20",
          type: 37,
          variant: 61,
          flash: {
            size: 65536,
            page_size: 256,
            page_count: 256,
            sector_size: 1024,
            sector_count: 64
          }
        },
        {
          name: "CH32L103G8R6",
          package: "QSOP28",
          type: 37,
          variant: 59,
          flash: {
            size: 65536,
            page_size: 256,
            page_count: 256,
            sector_size: 1024,
            sector_count: 64
          }
        },
        {
          name: "CH32L103K8U6",
          package: "QFN32",
          type: 37,
          variant: 50,
          flash: {
            size: 65536,
            page_size: 256,
            page_count: 256,
            sector_size: 1024,
            sector_count: 64
          }
        }
      ]
    },
    {
      family: "CH32V103",
      devices: [
        {
          name: "CH32V103C6T6",
          package: "LQFP48",
          type: 21,
          variant: 50,
          flash: {
            size: 32768,
            page_size: 128,
            page_count: 256,
            sector_size: 1024,
            sector_count: 32
          }
        },
        {
          name: "CH32V103C8T6",
          package: "LQFP48",
          type: 21,
          variant: 63,
          flash: {
            size: 65536,
            page_size: 128,
            page_count: 512,
            sector_size: 1024,
            sector_count: 64
          }
        },
        {
          name: "CH32V103C8U6",
          package: "QFN48",
          type: 21,
          variant: 63,
          flash: {
            size: 65536,
            page_size: 128,
            page_count: 512,
            sector_size: 1024,
            sector_count: 64
          }
        },
        {
          name: "CH32V103R8T6",
          package: "LQFP64M",
          type: 21,
          variant: 63,
          flash: {
            size: 65536,
            page_size: 128,
            page_count: 512,
            sector_size: 1024,
            sector_count: 64
          }
        }
      ]
    },
    {
      family: "CH32V203",
      devices: [
        {
          name: "CH32V203C6T6",
          package: "LQFP48",
          type: 25,
          variant: 51,
          flash: {
            size: 229376,
            page_size: 256,
            page_count: 128,
            sector_size: 4096,
            sector_count: 8
          }
        },
        {
          name: "CH32V203C8T6",
          package: "LQFP48",
          type: 25,
          variant: 49,
          flash: {
            size: 229376,
            page_size: 256,
            page_count: 256,
            sector_size: 4096,
            sector_count: 16
          }
        },
        {
          name: "CH32V203C8U6",
          package: "QFN48",
          type: 25,
          variant: 48,
          flash: {
            size: 229376,
            page_size: 256,
            page_count: 256,
            sector_size: 4096,
            sector_count: 16
          }
        },
        {
          name: "CH32V203F6P6",
          package: "TSSOP20",
          type: 25,
          variant: 55,
          flash: {
            size: 229376,
            page_size: 256,
            page_count: 128,
            sector_size: 4096,
            sector_count: 8
          }
        },
        {
          name: "CH32V203F8P6",
          package: "TSSOP20",
          type: 25,
          variant: 58,
          flash: {
            size: 229376,
            page_size: 256,
            page_count: 256,
            sector_size: 4096,
            sector_count: 16
          }
        },
        {
          name: "CH32V203F8U6",
          package: "QFN20",
          type: 25,
          variant: 62,
          flash: {
            size: 229376,
            page_size: 256,
            page_count: 256,
            sector_size: 4096,
            sector_count: 16
          }
        },
        {
          name: "CH32V203G6U6",
          package: "QFN28",
          type: 25,
          variant: 54,
          flash: {
            size: 229376,
            page_size: 256,
            page_count: 128,
            sector_size: 4096,
            sector_count: 8
          }
        },
        {
          name: "CH32V203G8R6",
          package: "QSOP28",
          type: 25,
          variant: 59,
          flash: {
            size: 229376,
            page_size: 256,
            page_count: 256,
            sector_size: 4096,
            sector_count: 16
          }
        },
        {
          name: "CH32V203K6T6",
          package: "LQFP32",
          type: 25,
          variant: 53,
          flash: {
            size: 229376,
            page_size: 256,
            page_count: 128,
            sector_size: 4096,
            sector_count: 8
          }
        },
        {
          name: "CH32V203K8T6",
          package: "LQFP32",
          type: 25,
          variant: 50,
          flash: {
            size: 229376,
            page_size: 256,
            page_count: 256,
            sector_size: 4096,
            sector_count: 16
          }
        },
        {
          name: "CH32V203RBT6",
          package: "LQFP64M",
          type: 25,
          variant: 52,
          flash: {
            size: 229376,
            page_size: 256,
            page_count: 512,
            sector_size: 4096,
            sector_count: 32
          }
        }
      ]
    },
    {
      family: "CH32V208",
      devices: [
        {
          name: "CH32V208CBU6",
          package: "QFN48",
          type: 25,
          variant: 130,
          flash: {
            size: 491520,
            page_size: 256,
            page_count: 512,
            sector_size: 4096,
            sector_count: 32
          }
        },
        {
          name: "CH32V208GBU6",
          package: "QFN28",
          type: 25,
          variant: 131,
          flash: {
            size: 491520,
            page_size: 256,
            page_count: 512,
            sector_size: 4096,
            sector_count: 32
          }
        },
        {
          name: "CH32V208RBT6",
          package: "LQFP64M",
          type: 25,
          variant: 129,
          flash: {
            size: 491520,
            page_size: 256,
            page_count: 512,
            sector_size: 4096,
            sector_count: 32
          }
        },
        {
          name: "CH32V208WBU6",
          package: "QFN68",
          type: 25,
          variant: 128,
          flash: {
            size: 491520,
            page_size: 256,
            page_count: 512,
            sector_size: 4096,
            sector_count: 32
          }
        }
      ]
    },
    {
      family: "CH32V30x",
      devices: [
        {
          name: "CH32V303CBT6",
          package: "LQFP48",
          type: 23,
          variant: 51,
          flash: {
            size: 491520,
            page_size: 256,
            page_count: 512,
            sector_size: 4096,
            sector_count: 32
          }
        },
        {
          name: "CH32V303RBT6",
          package: "LQFP64M",
          type: 23,
          variant: 50,
          flash: {
            size: 491520,
            page_size: 256,
            page_count: 512,
            sector_size: 4096,
            sector_count: 32
          }
        },
        {
          name: "CH32V303RCT6",
          package: "LQFP64M",
          type: 23,
          variant: 49,
          flash: {
            size: 491520,
            page_size: 256,
            page_count: 1024,
            sector_size: 4096,
            sector_count: 64
          }
        },
        {
          name: "CH32V303VCT6",
          package: "LQFP100",
          type: 23,
          variant: 48,
          flash: {
            size: 491520,
            page_size: 256,
            page_count: 1024,
            sector_size: 4096,
            sector_count: 64
          }
        },
        {
          name: "CH32V305FBP6",
          package: "TSSOP20",
          type: 23,
          variant: 82,
          flash: {
            size: 491520,
            page_size: 256,
            page_count: 512,
            sector_size: 4096,
            sector_count: 32
          }
        },
        {
          name: "CH32V305GBU6",
          package: "QFN28",
          type: 23,
          variant: 91,
          flash: {
            size: 491520,
            page_size: 256,
            page_count: 512,
            sector_size: 4096,
            sector_count: 32
          }
        },
        {
          name: "CH32V305RBT6",
          package: "LQFP64M",
          type: 23,
          variant: 80,
          flash: {
            size: 491520,
            page_size: 256,
            page_count: 512,
            sector_size: 4096,
            sector_count: 32
          }
        },
        {
          name: "CH32V307FBP6",
          package: "TSSOP20",
          type: 23,
          variant: 114,
          flash: {
            size: 491520,
            page_size: 256,
            page_count: 512,
            sector_size: 4096,
            sector_count: 32
          }
        },
        {
          name: "CH32V307RCT6",
          package: "LQFP64M",
          type: 23,
          variant: 113,
          flash: {
            size: 491520,
            page_size: 256,
            page_count: 1024,
            sector_size: 4096,
            sector_count: 64
          }
        },
        {
          name: "CH32V307WCU6",
          package: "QFN68",
          type: 23,
          variant: 115,
          flash: {
            size: 491520,
            page_size: 256,
            page_count: 1024,
            sector_size: 4096,
            sector_count: 64
          }
        },
        {
          name: "CH32V307VCT6",
          package: "LQFP100",
          type: 23,
          variant: 112,
          flash: {
            size: 491520,
            page_size: 256,
            page_count: 1024,
            sector_size: 4096,
            sector_count: 64
          }
        }
      ]
    },
    {
      family: "CH32X03x",
      devices: [
        {
          name: "CH32X033F8P6",
          package: "TSSOP20",
          type: 35,
          variant: 90,
          flash: {
            size: 63488,
            page_size: 256,
            page_count: 248,
            sector_size: 1024,
            sector_count: 62
          }
        },
        {
          name: "CH32X035C8T6",
          package: "LQFP48",
          type: 35,
          variant: 81,
          flash: {
            size: 63488,
            page_size: 256,
            page_count: 248,
            sector_size: 1024,
            sector_count: 62
          }
        },
        {
          name: "CH32X035F7P6",
          package: "TSSOP20",
          type: 35,
          variant: 87,
          flash: {
            size: 63488,
            page_size: 256,
            page_count: 248,
            sector_size: 1024,
            sector_count: 62
          }
        },
        {
          name: "CH32X035F8U6",
          package: "QFN20",
          type: 35,
          variant: 94,
          flash: {
            size: 63488,
            page_size: 256,
            page_count: 248,
            sector_size: 1024,
            sector_count: 62
          }
        },
        {
          name: "CH32X035G8R6",
          package: "QSOP28",
          type: 35,
          variant: 91,
          flash: {
            size: 63488,
            page_size: 256,
            page_count: 248,
            sector_size: 1024,
            sector_count: 62
          }
        },
        {
          name: "CH32X035G8U6",
          package: "QFN28",
          type: 35,
          variant: 86,
          flash: {
            size: 63488,
            page_size: 256,
            page_count: 248,
            sector_size: 1024,
            sector_count: 62
          }
        },
        {
          name: "CH32X035R8T6",
          package: "LQFP64M",
          type: 35,
          variant: 80,
          flash: {
            size: 63488,
            page_size: 256,
            page_count: 248,
            sector_size: 1024,
            sector_count: 62
          }
        }
      ]
    }
  ];

  // modules/devices.js
  var DevicesDatabase = class {
    #devices = devices_default;
    constructor() {
    }
    populateDeviceList(list) {
      this.#devices.forEach((fam, famIdx) => {
        const grp = document.createElement("optgroup");
        grp.setAttribute("label", fam["family"]);
        fam["devices"].forEach((dev, devIdx) => {
          const opt = document.createElement("option");
          opt.setAttribute("value", famIdx.toString() + ":" + devIdx.toString());
          opt.textContent = dev["name"] + " (" + dev["package"] + ", " + Formatter.byteSize(dev["flash"]["size"]) + ")";
          grp.appendChild(opt);
        });
        list.appendChild(grp);
      });
    }
    findDeviceByIndex(val) {
      const [famIdx, devIdx] = val.split(":").map((str) => Number.parseInt(str));
      if (famIdx >= 0 && devIdx >= 0) {
        const family = this.#devices.at(famIdx);
        if (family) {
          const device = family["devices"].at(devIdx);
          if (device) {
            return device;
          }
        }
      }
      throw new Error("Device not found or invalid index string");
    }
    findDeviceIndexByName(name) {
      name = name.trim().toLowerCase();
      let famIdx, devIdx;
      famIdx = this.#devices.findIndex((fam) => {
        devIdx = fam["devices"].findIndex((dev) => dev["name"].toLowerCase() === name);
        return devIdx >= 0;
      });
      return famIdx >= 0 && devIdx >= 0 ? famIdx + ":" + devIdx : null;
    }
  };

  // wchisp.js
  function clearHexListing() {
    document.getElementById("fw_hex").replaceChildren();
  }
  function createHexListing(bytes, fileName) {
    const container = document.getElementById("fw_hex");
    const offset_max_digits = bytes.length.toString(16).length;
    const groups_count = 8;
    const row_size = groups_count * 2;
    for (let i = 0; i < bytes.length; i += row_size) {
      let data = "", text = "";
      for (let j = 0; j < groups_count; j++) {
        const n = i + j * 2;
        if (n < bytes.length) {
          data += Formatter.hex(bytes[n], 2);
          text += Formatter.printableText(bytes[n], "\xB7");
        }
        if (n + 1 < bytes.length) {
          data += Formatter.hex(bytes[n + 1], 2);
          text += Formatter.printableText(bytes[n + 1], "\xB7");
        }
        data += " ";
      }
      const offset = document.createElement("span");
      offset.classList.add("o");
      offset.textContent = "0x" + Formatter.hex(i, offset_max_digits);
      const printable = document.createElement("span");
      printable.classList.add("p");
      printable.textContent = text;
      const br = document.createElement("br");
      container.append(offset, data.trimEnd(), printable, br);
    }
    document.getElementById("fw_name_val").textContent = fileName;
    document.getElementById("fw_size_val").textContent = bytes.length.toLocaleString();
  }
  function updateUrlLoadProgress(event) {
    const bar = document.getElementById("fw_url_progress");
    if (event.detail.increment === null || event.detail.total === null) {
      bar.removeAttribute("value");
    } else {
      const val = Math.min(event.detail.increment / event.detail.total, 1);
      bar.setAttribute("value", val);
    }
  }
  function configInputIds() {
    const inputIds = [
      "cfg_rdpr",
      "cfg_user",
      "cfg_data0",
      "cfg_data1",
      "cfg_wrpr0",
      "cfg_wrpr1",
      "cfg_wrpr2",
      "cfg_wrpr3"
    ];
    return inputIds;
  }
  function populateConfig(config) {
    if ("optionBytes" in config) {
      configInputIds().forEach((id, idx) => {
        document.getElementById(id).value = "0x" + Formatter.hex(config.optionBytes[idx], 2);
      });
    }
  }
  function getConfigIsValid() {
    return configInputIds().every((id) => {
      const input = document.getElementById(id);
      return input.checkValidity() && !Number.isNaN(Number.parseInt(input.value, 16));
    });
  }
  function getConfigBytes() {
    if (!getConfigIsValid()) {
      throw new Error("One or more configuration option byte values is missing or invalid");
    }
    return configInputIds().map((id) => Number.parseInt(document.getElementById(id).value, 16));
  }
  function setActionButtonsEnabled(enable, ids = null) {
    const buttons = document.querySelectorAll("#actions > button");
    const prevState = new Array(buttons.length);
    buttons.forEach((btn, idx) => {
      prevState[idx] = btn.disabled;
      if (!Array.isArray(ids) || ids.includes(btn.id)) {
        btn.disabled = !enable;
      }
    });
    return prevState;
  }
  function restoreActionButtonsEnabled(prevState) {
    document.querySelectorAll("#actions > button").forEach((btn, idx) => {
      btn.disabled = prevState[idx];
    });
  }
  function checkFirmwareSize(fwSize, flashSize) {
    if (fwSize > flashSize) {
      window.alert(
        "Currently loaded firmware file size is LARGER than device flash size!\n\nFirmware size: " + Formatter.byteSize(fwSize) + "\nDevice flash size: " + Formatter.byteSize(flashSize)
      );
      setActionButtonsEnabled(false, ["flash_write", "flash_verify"]);
    } else {
      setActionButtonsEnabled(true, ["flash_write", "flash_verify"]);
    }
  }
  function updateOperationProgress(event) {
    const bar = document.getElementById("progress_bar");
    const pct = document.getElementById("progress_pct");
    const icon = document.getElementById("progress_result");
    if (event.detail.increment === null || event.detail.total === null) {
      bar.removeAttribute("value");
      pct.textContent = "\u221E";
    } else {
      const val = Math.min(event.detail.increment / event.detail.total, 1);
      bar.setAttribute("value", val);
      pct.textContent = Math.floor(val * 100) + "%";
    }
    icon.classList.remove("failure", "success");
    icon.removeAttribute("title");
  }
  function updateOperationResult(success) {
    const icon = document.getElementById("progress_result");
    icon.classList.remove("failure", "success");
    icon.classList.add(success ? "success" : "failure");
    icon.setAttribute("title", "Operation " + (success ? "succeeded" : "failed"));
    if (!success) window.alert(
      "Operation failed!\n\nSee log for details."
    );
  }
  function logMessage(msg, date, levelName, levelShortName) {
    const log = document.getElementById("log");
    const debug = document.getElementById("log_debug");
    if (levelName !== "Debug" || debug.checked && levelName === "Debug") {
      const line = document.createElement("p");
      const time = document.createElement("span");
      time.classList.add("time");
      time.textContent = date.toLocaleTimeString([], {
        hour: "2-digit",
        minute: "2-digit",
        second: "2-digit",
        fractionalSecondDigits: 3
      });
      const level = document.createElement("span");
      level.classList.add("level", levelName.toLowerCase());
      level.textContent = levelShortName;
      line.append("[", time, "][", level, "] ", msg);
      log.appendChild(line);
      log.scrollTop = log.scrollHeight;
    }
  }
  function clearLog() {
    document.getElementById("log").replaceChildren();
  }
  var loader = new FirmwareLoader();
  var logger = new Logger(logMessage);
  var devices = new DevicesDatabase();
  var params = new URLSearchParams(window.location.search);
  loader.addParser(["hex", "ihx"], IntelHexParser);
  loader.addParser(["srec", "s19", "s28", "s37"], SRecordParser);
  loader.addParser(["elf"], ElfRiscVParser);
  loader.addEventListener("progress", updateUrlLoadProgress);
  var windowLoaded = new Promise((resolve) => window.addEventListener("load", resolve, false));
  windowLoaded.then(() => {
    const deviceList = document.getElementById("device_list");
    const deviceDtrRtsReset = document.getElementById("device_dtr_rts_reset");
    const fwTabFile = document.getElementById("fw_tab_file");
    const fwTabUrl = document.getElementById("fw_tab_url");
    const fwUrl = document.getElementById("fw_url");
    const fwUrlLoad = document.getElementById("fw_url_load");
    const fwFile = document.getElementById("fw_file");
    const fwHex = document.getElementById("fw_hex");
    const configRead = document.getElementById("config_read");
    const configWrite = document.getElementById("config_write");
    const flashWrite = document.getElementById("flash_write");
    const flashVerify = document.getElementById("flash_verify");
    const flashErase = document.getElementById("flash_erase");
    const logClear = document.getElementById("log_clear");
    let device, firmware;
    devices.populateDeviceList(deviceList);
    device = devices.findDeviceByIndex(deviceList.value);
    fwUrl.addEventListener("input", (event) => {
      fwUrlLoad.disabled = !event.target.validity.valid;
    });
    fwUrl.addEventListener("keydown", (event) => {
      if (event.key == "Enter" && event.target.validity.valid) {
        fwUrlLoad.dispatchEvent(new Event("click"));
      }
    });
    fwUrlLoad.addEventListener("click", (event) => {
      clearHexListing();
      loader.fromUrl(fwUrl.value).then((fw) => {
        logger.info("Loaded " + fw.format + ' firmware file from "' + fwUrl.value + '"');
        fw.fillToEndOfSegment(1024);
        createHexListing(fw.bytes, fw.fileName);
        checkFirmwareSize(fw.size, device["flash"]["size"]);
        firmware = fw;
      }).catch((err) => {
        logger.error('Failed to load firmware from URL "' + fwUrl.value + '"');
        logger.error(err.message);
        window.alert(
          'Failed to load firmware from URL "' + fwUrl.value + '".\n\nSee log for details.'
        );
        firmware = void 0;
        setActionButtonsEnabled(false, ["flash_write", "flash_verify"]);
      });
    });
    fwFile.addEventListener("change", (event) => {
      if (fwFile.files.length > 0) {
        clearHexListing();
        loader.fromFile(fwFile.files[0]).then((fw) => {
          logger.info("Loaded " + fw.format + ' firmware file from "' + fwFile.files[0].name + '"');
          fw.fillToEndOfSegment(1024);
          createHexListing(fw.bytes, fw.fileName);
          checkFirmwareSize(fw.size, device["flash"]["size"]);
          firmware = fw;
        }).catch((err) => {
          logger.error('Failed to load firmware from file "' + fwFile.files[0].name + '"');
          logger.error(err.message);
          window.alert(
            'Failed to load firmware from file "' + fwFile.files[0].name + '".\n\nSee log for details.'
          );
          firmware = void 0;
          setActionButtonsEnabled(false, ["flash_write", "flash_verify"]);
        });
      }
    });
    fwHex.addEventListener("dragover", (event) => {
      event.dataTransfer.dropEffect = event.dataTransfer.types.includes("Files") ? "copy" : "none";
      event.preventDefault();
    });
    fwHex.addEventListener("drop", (event) => {
      for (const item of event.dataTransfer.items) {
        if (item.kind === "string" && item.type === "text/uri-list") {
          item.getAsString((uri) => {
            fwTabUrl.checked = true;
            fwUrl.value = uri;
            fwUrl.dispatchEvent(new Event("input"));
            fwUrlLoad.dispatchEvent(new Event("click"));
          });
          break;
        } else if (item.kind === "file") {
          fwTabFile.checked = true;
          fwFile.files = event.dataTransfer.files;
          fwFile.dispatchEvent(new Event("change"));
          break;
        }
      }
      event.preventDefault();
    });
    deviceList.addEventListener("change", (event) => {
      device = devices.findDeviceByIndex(deviceList.value);
      logger.info(
        "Selected device changed to: " + device["name"] + " (" + device["package"] + ", " + Formatter.byteSize(device["flash"]["size"]) + " flash)"
      );
      if (firmware !== void 0) {
        checkFirmwareSize(firmware.size, device["flash"]["size"]);
      }
    });
    [
      "cfg_rdpr",
      "cfg_user",
      "cfg_data0",
      "cfg_data1",
      "cfg_wrpr0",
      "cfg_wrpr1",
      "cfg_wrpr2",
      "cfg_wrpr3"
    ].forEach((id) => {
      document.getElementById(id).addEventListener("input", (event) => {
        setActionButtonsEnabled(getConfigIsValid(), ["config_write"]);
      });
    });
    configRead.addEventListener("click", (event) => {
      const btnState = setActionButtonsEnabled(false);
      let success = true;
      const sess = new Session(device["variant"], device["type"], deviceDtrRtsReset.checked);
      sess.setLogger(logger);
      sess.addEventListener("progress", updateOperationProgress);
      sess.start().then(() => sess.identify()).then(() => sess.configRead()).then((config) => {
        populateConfig(config);
        return sess.reset(true);
      }).catch((err) => {
        logger.error(err.message);
        success = false;
      }).finally(() => {
        sess.end();
        updateOperationResult(success);
        restoreActionButtonsEnabled(btnState);
        setActionButtonsEnabled(getConfigIsValid(), ["config_write"]);
      });
    });
    configWrite.addEventListener("click", (event) => {
      const btnState = setActionButtonsEnabled(false);
      let success = true;
      const sess = new Session(device["variant"], device["type"], deviceDtrRtsReset.checked);
      sess.setLogger(logger);
      sess.addEventListener("progress", updateOperationProgress);
      sess.start().then(() => sess.identify()).then(() => sess.configRead()).then(() => sess.configWrite(getConfigBytes())).then(() => sess.reset(true)).catch((err) => {
        logger.error(err.message);
        success = false;
      }).finally(() => {
        sess.end();
        updateOperationResult(success);
        restoreActionButtonsEnabled(btnState);
      });
    });
    flashWrite.addEventListener("click", (event) => {
      const btnState = setActionButtonsEnabled(false);
      let success = true;
      const sess = new Session(device["variant"], device["type"], deviceDtrRtsReset.checked);
      sess.setLogger(logger);
      sess.addEventListener("progress", updateOperationProgress);
      sess.start().then(() => sess.identify()).then(() => sess.configRead()).then(() => sess.keyGenerate()).then(() => sess.flashErase(firmware.getSectorCount(1024))).then(() => sess.flashWrite(firmware.bytes)).then(() => sess.keyGenerate()).then(() => sess.flashVerify(firmware.bytes)).then(() => sess.reset(true)).catch((err) => {
        logger.error(err.message);
        success = false;
      }).finally(() => {
        sess.end();
        updateOperationResult(success);
        restoreActionButtonsEnabled(btnState);
      });
    });
    flashVerify.addEventListener("click", (event) => {
      const btnState = setActionButtonsEnabled(false);
      let success = true;
      const sess = new Session(device["variant"], device["type"], deviceDtrRtsReset.checked);
      sess.setLogger(logger);
      sess.addEventListener("progress", updateOperationProgress);
      sess.start().then(() => sess.identify()).then(() => sess.configRead()).then(() => sess.keyGenerate()).then(() => sess.flashVerify(firmware.bytes)).then(() => sess.reset(true)).catch((err) => {
        logger.error(err.message);
        success = false;
      }).finally(() => {
        sess.end();
        updateOperationResult(success);
        restoreActionButtonsEnabled(btnState);
      });
    });
    flashErase.addEventListener("click", (event) => {
      if (window.confirm(
        "Are you sure you want to ERASE the device?\n\nThis will destroy ALL data in the user application flash!"
      )) {
        const btnState = setActionButtonsEnabled(false);
        let success = true;
        const sess = new Session(device["variant"], device["type"], deviceDtrRtsReset.checked);
        sess.setLogger(logger);
        sess.addEventListener("progress", updateOperationProgress);
        sess.start().then(() => sess.identify()).then(() => sess.configRead()).then(() => sess.flashErase(Math.ceil(device["flash"]["size"] / 1024))).then(() => sess.reset(true)).catch((err) => {
          logger.error(err.message);
          success = false;
        }).finally(() => {
          sess.end();
          updateOperationResult(success);
          restoreActionButtonsEnabled(btnState);
        });
      }
    });
    logClear.addEventListener("click", (event) => {
      clearLog();
    });
    setTimeout(() => {
      if (params.has("dev")) {
        const idx = devices.findDeviceIndexByName(params.get("dev"));
        if (idx) {
          deviceList.value = idx;
          deviceList.dispatchEvent(new Event("change"));
        } else {
          throw new Error(`Couldn't find device with name "` + params.get("dev") + '"');
        }
      } else {
        if (deviceList.selectedOptions.length > 0) {
          deviceList.dispatchEvent(new Event("change"));
        }
      }
      if (params.has("fw")) {
        fwTabUrl.checked = true;
        fwUrl.value = params.get("fw");
        fwUrl.dispatchEvent(new Event("input"));
        fwUrlLoad.dispatchEvent(new Event("click"));
      } else {
        if (fwTabFile.checked && fwFile.files.length > 0) {
          fwFile.dispatchEvent(new Event("change"));
        } else if (fwTabUrl.checked && fwUrl.validity.valid) {
          fwUrl.dispatchEvent(new Event("input"));
          fwUrlLoad.dispatchEvent(new Event("click"));
        }
      }
    }, 250);
  }).catch((err) => {
    console.error(err);
    logger.error(err.message);
    if (err.cause instanceof Error) {
      logger.error(err.cause.message);
    }
  });
})();
