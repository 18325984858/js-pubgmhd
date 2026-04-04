"use strict";

// =====================================================================
//  UE4.18 GNames / GUObjectArray / GWorld Dump — Frida Script
//  Target: com.tencent.tmgp.pubgmhd  (ARM64 Android)
//  所有偏移经 IDA MCP 反编译验证
// =====================================================================

// ===================== CONFIGURATION =================================
var CONFIG = {
	moduleName: "libUE4.so",

	// ---- 全局变量偏移 (相对 libUE4.so 基址) ----
	GNames: 0x146f9f30, // static TNameEntryArray* Names (FName::GetNames)
	GUObjectArray: 0x14706480, // FUObjectArray GUObjectArray
	GWorld: 0x14988578, // UWorldProxy GWorld

	// ---- TNameEntryArray (PUBG 修改版, IDA 验证) ----
	//   Chunks[640]  : 640 × 8 = 0x1400 bytes
	//   NumElements  : int32 @ +0x1400  (IDA: *((_DWORD*)Names + 1280))
	//   NumChunks    : int32 @ +0x1404
	//   ElementsPerChunk = 16384 (0x4000)
	ElementsPerChunk: 16384,
	NumElementsOff: 0x1400,

	// ---- FNameEntry (IDA 反编译 FName::InitInternal_FindOrAddNameEntry 验证) ----
	//   +0x00  FNameEntry* HashNext   (链表指针, IDA: *v10 遍历)
	//   +0x08  int32 Index            (bit0=IsWide, >>1=real index, IDA: v10+8, 写入 2*NumElements)
	//   +0x0C  char AnsiName[]        (IDA: strcpy((char*)v44+12, s), strcmp((char*)(v21+12), s))
	NameEntryIndexOff: 0x08,
	NameEntryNameOff: 0x0c,

	// ---- UObjectBase (IDA 验证: +0x0C=InternalIndex, +0x18=NamePrivate) ----
	//   +0x00  void* vtable
	//   +0x08  int32 ObjectFlags
	//   +0x0C  int32 InternalIndex
	//   +0x10  UClass* ClassPrivate
	//   +0x18  FName NamePrivate { ComparisonIndex(4), Number(4) }
	//   +0x20  UObject* OuterPrivate
	UObj_ClassOff: 0x10,
	UObj_NameIdxOff: 0x18,
	UObj_NameNumOff: 0x1c,
	UObj_OuterOff: 0x20,

	// ---- FUObjectArray (PUBG 分块版, IDA 验证) ----
	//   +0xC8  void* ChunkPtrs[]           chunk 指针数组
	//   +0xE8  int32 ChunkElementCounts[]   每块元素数
	//   +0xF8  int32 NumChunks
	//   +0x100 int32 TotalNumElements
	//
	// IDA 遍历模式 (sub_5466744):
	//   chunk_ptr = *(void**)(arr + 0xC8 + chunk_idx * 8)
	//   chunk_cnt = *(int*)(arr + 0xE8 + chunk_idx * 4)
	//   item = chunk_ptr + 24 * within_chunk_index
	ObjChunkPtrsOff: 0xc8,
	ObjChunkCountsOff: 0xe8,
	ObjNumChunksOff: 0xf8,
	ObjTotalNumOff: 0x100,

	// ---- FUObjectItem (IDA 验证: 步长 24) ----
	//   +0x00  UObjectBase* Object
	//   +0x08  int32 Flags
	//   +0x0C  int32 ClusterRootIndex
	//   +0x10  int32 SerialNumber
	//   +0x14  padding
	FUObjectItemSize: 24,

	WideCharSize: 4,
	NamesBatch: 5000,
	ObjectsBatch: 2000,
	OutputDir: "/data/data/com.tencent.tmgp.pubgmhd/cache/ue4_dump/",
};

// ===================== GLOBALS =======================================
var gBase = null;
var gNamesArray = null;
var gNumNames = 0;
var nameCache = {};

// ===================== 安全读取 ======================================
function safePtr(addr) {
	try {
		return addr.readPointer();
	} catch (_) {
		return ptr(0);
	}
}
function safeS32(addr) {
	try {
		return addr.readS32();
	} catch (_) {
		return 0;
	}
}

// ===================== FName 解析 ====================================

function getNameByIndex(index) {
	if (index in nameCache) return nameCache[index];
	if (index < 0 || index >= gNumNames) return null;

	var chunkIdx = (index / CONFIG.ElementsPerChunk) >>> 0;
	var withinIdx = index % CONFIG.ElementsPerChunk;

	var chunkPtr = safePtr(gNamesArray.add(chunkIdx * Process.pointerSize));
	if (chunkPtr.isNull()) return null;

	var entryPtr = safePtr(chunkPtr.add(withinIdx * Process.pointerSize));
	if (entryPtr.isNull()) return null;

	var rawIndex = safeS32(entryPtr.add(CONFIG.NameEntryIndexOff));
	var isWide = (rawIndex & 0x1) !== 0;
	var name = null;
	var nameAddr = entryPtr.add(CONFIG.NameEntryNameOff);

	if (!isWide) {
		try {
			name = nameAddr.readCString();
		} catch (_) {}
	} else {
		try {
			name = readWideString4(nameAddr, 1024);
		} catch (_) {}
	}

	if (name !== null && name.length > 0) nameCache[index] = name;
	return name;
}

function readWideString4(addr, maxLen) {
	var result = "";
	for (var i = 0; i < maxLen; i++) {
		var code = addr.add(i * 4).readU32();
		if (code === 0) break;
		result += String.fromCodePoint(code);
	}
	return result;
}

function fnameToString(nameIdx, number) {
	var base = getNameByIndex(nameIdx);
	if (base === null) return "<invalid>";
	if (number === 0) return base;
	return base + "_" + (number - 1);
}

// ===================== UObject 工具 ==================================

function readObjectFName(objPtr) {
	var idx = safeS32(objPtr.add(CONFIG.UObj_NameIdxOff));
	var num = safeS32(objPtr.add(CONFIG.UObj_NameNumOff));
	return fnameToString(idx, num);
}

function readClassName(objPtr) {
	var classPtr = safePtr(objPtr.add(CONFIG.UObj_ClassOff));
	if (classPtr.isNull()) return "<no_class>";
	return readObjectFName(classPtr);
}

function readFullPath(objPtr) {
	var parts = [];
	var cur = objPtr;
	var depth = 0;
	while (!cur.isNull() && depth < 64) {
		parts.unshift(readObjectFName(cur));
		cur = safePtr(cur.add(CONFIG.UObj_OuterOff));
		depth++;
	}
	return parts.join(".");
}

// ===================== GUObjectArray 分块遍历 ========================
// IDA 验证的遍历模式 (sub_5466744, sub_A657F94):
//   chunk_base = *(void**)(GUObjectArray + 0xC8 + chunk_idx * 8)
//   chunk_count = *(int*)(GUObjectArray + 0xE8 + chunk_idx * 4)
//   item = chunk_base + 24 * within_chunk_index

function forEachUObject(arrayBase, callback) {
	var numChunks = safeS32(arrayBase.add(CONFIG.ObjNumChunksOff));
	var totalNum = safeS32(arrayBase.add(CONFIG.ObjTotalNumOff));

	send({ type: "info", msg: "GUObjectArray: NumChunks=" + numChunks + " TotalNum=" + totalNum });

	if (numChunks <= 0 || totalNum <= 0) {
		send({ type: "error", msg: "GUObjectArray appears empty (NumChunks=" + numChunks + " Total=" + totalNum + ")" });
		return 0;
	}

	var globalIdx = 0;
	var total = 0;

	for (var ci = 0; ci < numChunks; ci++) {
		var chunkBase = safePtr(arrayBase.add(CONFIG.ObjChunkPtrsOff + ci * Process.pointerSize));
		var chunkCount = safeS32(arrayBase.add(CONFIG.ObjChunkCountsOff + ci * 4));

		if (chunkBase.isNull() || chunkCount <= 0) {
			globalIdx += chunkCount > 0 ? chunkCount : 0;
			continue;
		}

		for (var wi = 0; wi < chunkCount; wi++) {
			var itemAddr = chunkBase.add(wi * CONFIG.FUObjectItemSize);
			var objPtr = safePtr(itemAddr);

			if (!objPtr.isNull()) {
				try {
					callback(objPtr, globalIdx);
					total++;
				} catch (e) {}
			}
			globalIdx++;
			if (globalIdx >= totalNum) break;
		}
		if (globalIdx >= totalNum) break;
	}

	return total;
}

// ===================== DUMP LOGIC ====================================

function initGlobals() {
	var mod = Process.findModuleByName(CONFIG.moduleName);
	if (!mod) {
		send({ type: "error", msg: "Module " + CONFIG.moduleName + " not found!" });
		return false;
	}
	gBase = mod.base;
	send({ type: "info", msg: "Module base: " + gBase + ", size: 0x" + mod.size.toString(16) });

	// ---- GNames ----
	var pNames = gBase.add(CONFIG.GNames);
	gNamesArray = safePtr(pNames);
	if (gNamesArray.isNull()) {
		send({ type: "error", msg: "GNames pointer is NULL at " + pNames });
		return false;
	}
	gNumNames = safeS32(gNamesArray.add(CONFIG.NumElementsOff));
	send({ type: "info", msg: "GNames @ " + gNamesArray + ", NumNames=" + gNumNames });

	// 验证: entry[0] 应该是 "None"
	var chunk0 = safePtr(gNamesArray);
	if (!chunk0.isNull()) {
		var entry0 = safePtr(chunk0);
		if (!entry0.isNull()) {
			try {
				var name0 = entry0.add(CONFIG.NameEntryNameOff).readCString();
				send({ type: "info", msg: "Verify: Entry[0] = '" + name0 + "'" + (name0 === "None" ? " OK" : " MISMATCH") });
			} catch (_) {
				send({ type: "info", msg: "Verify: Entry[0] unreadable" });
			}
		}
	}

	// ---- GWorld ----
	var worldPtr = safePtr(gBase.add(CONFIG.GWorld));
	send({ type: "info", msg: "GWorld = " + worldPtr });

	// ---- GUObjectArray ----
	var objArr = gBase.add(CONFIG.GUObjectArray);
	var nChunks = safeS32(objArr.add(CONFIG.ObjNumChunksOff));
	var nTotal = safeS32(objArr.add(CONFIG.ObjTotalNumOff));
	send({ type: "info", msg: "GUObjectArray @ " + objArr + ", NumChunks=" + nChunks + " Total=" + nTotal });

	return true;
}

function ensureOutputDir() {
	try {
		var libc = Process.findModuleByName("libc.so");
		var mkdirAddr = libc.findExportByName("mkdir");
		if (mkdirAddr) {
			var mkdir = new NativeFunction(mkdirAddr, "int", ["pointer", "int"]);
			// 逐级创建: /data/data/<pkg>/cache/ 已存在, 只需创建 ue4_dump/
			mkdir(Memory.allocUtf8String(CONFIG.OutputDir), 0x1ff);
			send({ type: "info", msg: "Output dir: " + CONFIG.OutputDir });
		}
	} catch (e) {
		send({ type: "error", msg: "mkdir failed: " + e.message });
	}
}

function flushBatch(file, batch) {
	file.write(batch.join("\n") + "\n");
	file.flush();
}

// ---- Phase 1: GNames ----
function dumpGNames() {
	send({ type: "phase", msg: "=== Phase 1: Dumping GNames (" + gNumNames + " entries) ===" });

	if (gNumNames <= 0) {
		send({ type: "info", msg: "Skipping: NumNames=0" });
		return;
	}

	var filePath = CONFIG.OutputDir + "NamesDump.txt";
	var file = new File(filePath, "w");
	var batch = [];
	var total = 0;

	for (var i = 0; i < gNumNames; i++) {
		var name = getNameByIndex(i);
		if (name === null) continue;

		batch.push(i + " " + name);
		total++;

		if (batch.length >= CONFIG.NamesBatch) {
			flushBatch(file, batch);
			batch = [];
		}
	}
	if (batch.length > 0) flushBatch(file, batch);
	file.close();
	send({ type: "info", msg: "GNames done: " + total + " names -> " + filePath });
}

// ---- Phase 2: GUObjectArray (分块遍历) ----
function dumpGObjects() {
	send({ type: "phase", msg: "=== Phase 2: Dumping GUObjectArray (chunked) ===" });

	var arrayBase = gBase.add(CONFIG.GUObjectArray);
	var filePath = CONFIG.OutputDir + "ObjectsDump.txt";
	var file = new File(filePath, "w");
	var batch = [];

	var total = forEachUObject(arrayBase, function (objPtr, globalIdx) {
		var className = readClassName(objPtr);
		var fullPath = readFullPath(objPtr);
		batch.push("[" + globalIdx + "] " + className + " " + fullPath);

		if (batch.length >= CONFIG.ObjectsBatch) {
			flushBatch(file, batch);
			batch = [];
		}
	});

	if (batch.length > 0) flushBatch(file, batch);
	file.close();
	send({ type: "info", msg: "GObjects done: " + total + " objects -> " + filePath });
}

// ---- Phase 3: GWorld ----
function dumpGWorld() {
	send({ type: "phase", msg: "=== Phase 3: GWorld Info ===" });

	var worldPtr = safePtr(gBase.add(CONFIG.GWorld));
	if (worldPtr.isNull()) {
		send({ type: "info", msg: "GWorld is NULL" });
		return;
	}

	var worldName = readObjectFName(worldPtr);
	var worldClass = readClassName(worldPtr);
	var worldPath = readFullPath(worldPtr);
	var info = "GWorld: " + worldPtr + "\nClass: " + worldClass + "\nName: " + worldName + "\nPath: " + worldPath;

	var filePath = CONFIG.OutputDir + "GWorldInfo.txt";
	var file = new File(filePath, "w");
	file.write(info + "\n");
	file.close();

	send({ type: "info", msg: info });
	send({ type: "info", msg: "GWorld info -> " + filePath });
}

// ===================== MAIN ENTRY ====================================

function runDump() {
	if (!initGlobals()) return;
	ensureOutputDir();

	try {
		dumpGNames();
	} catch (e) {
		send({ type: "error", msg: "GNames failed: " + e.message });
	}

	try {
		dumpGObjects();
	} catch (e) {
		send({ type: "error", msg: "GObjects failed: " + e.message });
	}

	try {
		dumpGWorld();
	} catch (e) {
		send({ type: "error", msg: "GWorld failed: " + e.message });
	}

	send({ type: "done", msg: "All dumps completed." });
}

recv("start", function (_msg) {
	send({ type: "info", msg: "Received start signal, beginning dump..." });
	runDump();
});

send({ type: "ready", msg: "Script loaded. Waiting for start signal." });
