"use strict";

// =====================================================================
//  UE4.18 SDK-style Dump v2 — Frida Script
//  Target: com.tencent.tmgp.pubgmhd  (ARM64 Android)
// =====================================================================

var CONFIG = {
	moduleName: "libUE4.so",
	GNames: 0x146f9f30,
	GUObjectArray: 0x14706480,
	ElementsPerChunk: 16384,
	NumElementsOff: 0x1400,
	NameEntryIndexOff: 0x08,
	NameEntryNameOff: 0x0c,
	UObj_ClassOff: 0x10,
	UObj_NameIdxOff: 0x18,
	UObj_NameNumOff: 0x1c,
	UObj_OuterOff: 0x20,
	UField_NextOff: 0x28,
	UStruct_SuperOff: 0x30,
	UStruct_ChildrenOff: 0x38,
	UStruct_PropSizeOff: 0x40,
	UProp_ArrayDimOff: 0x30,
	UProp_ElementSizeOff: 0x34,
	UProp_PropFlagsOff: 0x38,
	UProp_OffsetOff: 0x44,
	UFunc_FuncFlagsOff: 0x88,
	UFunc_NumParmsOff: 0x8c,
	// UFunction::Func (FNativeFuncPtr / PMF) — IDA 反编译验证:
	//   sub_A55FF7C: a1[22] = +0xB0 (Func ptr), a1[23] = +0xB8 (PMF adj)
	//   对于 Native 函数, +0xB0 直接包含函数地址
	UFunc_FuncPtrOff: 0xb0,
	// UEnum: CppType(FString=0x10 bytes) starts at +0x30, Names(TArray) at +0x40
	UEnum_NamesOff: 0x40,
	ObjChunkPtrsOff: 0xc8,
	ObjChunkCountsOff: 0xe8,
	ObjNumChunksOff: 0xf8,
	ObjTotalNumOff: 0x100,
	FUObjectItemSize: 24,
	OutputDir: "/data/data/com.tencent.tmgp.pubgmhd/cache/ue4_dump/",
};

var gBase = null,
	gModSize = 0,
	gNamesArray = null,
	gNumNames = 0,
	nameCache = {};

function safePtr(a) {
	try {
		return a.readPointer();
	} catch (_) {
		return ptr(0);
	}
}
function safeS32(a) {
	try {
		return a.readS32();
	} catch (_) {
		return 0;
	}
}
function safeU32(a) {
	try {
		return a.readU32();
	} catch (_) {
		return 0;
	}
}

function getNameByIndex(index) {
	if (index in nameCache) return nameCache[index];
	if (index < 0 || index >= gNumNames) return null;
	var ci = (index / CONFIG.ElementsPerChunk) >>> 0;
	var wi = index % CONFIG.ElementsPerChunk;
	var chk = safePtr(gNamesArray.add(ci * 8));
	if (chk.isNull()) return null;
	var ent = safePtr(chk.add(wi * 8));
	if (ent.isNull()) return null;
	var name = null;
	var idx = safeS32(ent.add(CONFIG.NameEntryIndexOff));
	if ((idx & 1) === 0) {
		try {
			name = ent.add(CONFIG.NameEntryNameOff).readCString();
		} catch (_) {}
	} else {
		try {
			var r = "",
				a = ent.add(CONFIG.NameEntryNameOff);
			for (var i = 0; i < 512; i++) {
				var c = a.add(i * 4).readU32();
				if (!c) break;
				r += String.fromCodePoint(c);
			}
			name = r;
		} catch (_) {}
	}
	if (name && name.length > 0) nameCache[index] = name;
	return name;
}

function fn(p) {
	var i = safeS32(p.add(CONFIG.UObj_NameIdxOff));
	var n = safeS32(p.add(CONFIG.UObj_NameNumOff));
	var b = getNameByIndex(i);
	if (!b) return "<invalid>";
	return n === 0 ? b : b + "_" + (n - 1);
}

function cn(p) {
	var c = safePtr(p.add(CONFIG.UObj_ClassOff));
	return c.isNull() ? "<no_class>" : fn(c);
}

function getPackageName(p) {
	var cur = p,
		last = p;
	while (!cur.isNull()) {
		last = cur;
		cur = safePtr(cur.add(CONFIG.UObj_OuterOff));
	}
	return fn(last);
}

function outerChain(p) {
	var parts = [],
		cur = safePtr(p.add(CONFIG.UObj_OuterOff)),
		d = 0;
	while (!cur.isNull() && d < 32) {
		parts.unshift(fn(cur));
		cur = safePtr(cur.add(CONFIG.UObj_OuterOff));
		d++;
	}
	return parts.join("/");
}

// Property type mapping
var PROP_TYPE_MAP = {
	Bool: "bool",
	Int: "int32",
	UInt32: "uint32",
	Int8: "int8",
	Int16: "int16",
	Int64: "int64",
	UInt16: "uint16",
	UInt64: "uint64",
	Byte: "uint8",
	Float: "float",
	Double: "double",
	Str: "FString",
	Name: "FName",
	Text: "FText",
	Object: "UObject*",
	Class: "UClass*",
	SoftObject: "TSoftObjectPtr",
	SoftClass: "TSoftClassPtr",
	WeakObject: "TWeakObjectPtr",
	LazyObject: "TLazyObjectPtr",
	Interface: "TScriptInterface",
	Struct: "FStruct",
	Array: "TArray",
	Map: "TMap",
	Set: "TSet",
	Delegate: "FDelegate",
	MulticastDelegate: "FMulticastDelegate",
	MulticastInlineDelegate: "FMulticastInlineDelegate",
	Enum: "enum",
};

function getPropType(propPtr) {
	var c = cn(propPtr);
	if (c.length > 8 && c.substring(c.length - 8) === "Property") {
		var base = c.substring(0, c.length - 8);
		if (base in PROP_TYPE_MAP) return PROP_TYPE_MAP[base];
		return base;
	}
	return c;
}

// Read PropertyFlags as two uint32 values (avoids BigInt issues in QuickJS)
function readPropFlags(propPtr) {
	var lo = safeU32(propPtr.add(CONFIG.UProp_PropFlagsOff));
	var hi = safeU32(propPtr.add(CONFIG.UProp_PropFlagsOff + 4));
	return { lo: lo, hi: hi };
}

// ===================== ENUM VALUES ===================================
// UEnum.Names is TArray<TPair<FName, int64>>
// TPair<FName(8 bytes), int64(8 bytes)> = 16 bytes per entry
function dumpEnumValues(objPtr, file) {
	// TArray at UEnum_NamesOff: { void* Data, int32 Num, int32 Max }
	var arrayData = safePtr(objPtr.add(CONFIG.UEnum_NamesOff));
	var arrayNum = safeS32(objPtr.add(CONFIG.UEnum_NamesOff + 8));

	if (arrayData.isNull() || arrayNum <= 0 || arrayNum > 10000) {
		file.write("\t// (no enum values)\n");
		return;
	}

	for (var i = 0; i < arrayNum; i++) {
		// Each entry: FName(8 bytes) + int64(8 bytes) = 16 bytes
		var entryAddr = arrayData.add(i * 16);
		var nameIdx = safeS32(entryAddr);
		var nameNum = safeS32(entryAddr.add(4));
		var value = safeS32(entryAddr.add(8)); // read low 32 of int64

		var enumName = getNameByIndex(nameIdx);
		if (!enumName) enumName = "<unknown>";
		if (nameNum > 0) enumName += "_" + (nameNum - 1);

		file.write("\t" + enumName + " = " + value + ",\n");
	}
}

// ===================== SDK DUMP TYPE =================================
function dumpType(objPtr, file) {
	var typeCN = cn(objPtr);
	var isClass = typeCN === "Class";
	var isStruct = typeCN === "ScriptStruct";
	var isEnum = typeCN === "UserDefinedEnum" || typeCN === "Enum";

	if (!isClass && !isStruct && !isEnum) return;

	var objName = fn(objPtr);
	var pkg = getPackageName(objPtr);
	var outer = outerChain(objPtr);

	if (isEnum) {
		file.write("// Enum " + outer + "." + objName + "\n");
		file.write("enum " + objName + " {\n");
		try {
			dumpEnumValues(objPtr, file);
		} catch (_) {
			file.write("\t// (error reading values)\n");
		}
		file.write("};\n\n");
		return;
	}

	var superPtr = safePtr(objPtr.add(CONFIG.UStruct_SuperOff));
	var superName = superPtr.isNull() ? "" : fn(superPtr);
	var propSize = safeS32(objPtr.add(CONFIG.UStruct_PropSizeOff));

	file.write("// " + (isClass ? "Class" : "ScriptStruct") + " " + pkg + "." + objName + "\n");
	file.write("// Size: 0x" + (propSize >>> 0).toString(16).toUpperCase() + "\n");
	file.write((isClass ? "class " : "struct ") + objName);
	if (superName) file.write(" : public " + superName);
	file.write("\n{\n");

	// Traverse Children linked list — collect properties and functions
	var child = safePtr(objPtr.add(CONFIG.UStruct_ChildrenOff));
	var hasFields = false,
		hasFuncs = false;
	var depth = 0;

	// First pass: properties
	var fieldChild = child;
	while (!fieldChild.isNull() && depth < 5000) {
		var cc = cn(fieldChild);
		if (cc.length > 8 && cc.substring(cc.length - 8) === "Property") {
			if (!hasFields) {
				file.write("\t// Fields\n");
				hasFields = true;
			}
			try {
				var propName = fn(fieldChild);
				var typeName = getPropType(fieldChild);
				var offset = safeS32(fieldChild.add(CONFIG.UProp_OffsetOff));
				var elemSize = safeS32(fieldChild.add(CONFIG.UProp_ElementSizeOff));
				var arrayDim = safeS32(fieldChild.add(CONFIG.UProp_ArrayDimOff));

				var line = "\t" + typeName + " " + propName;
				if (arrayDim > 1) line += "[" + arrayDim + "]";
				line += "; // 0x" + (offset >>> 0).toString(16).toUpperCase();
				line += " (Size: 0x" + (elemSize >>> 0).toString(16).toUpperCase() + ")";
				file.write(line + "\n");
			} catch (_) {}
		}
		fieldChild = safePtr(fieldChild.add(CONFIG.UField_NextOff));
		depth++;
	}

	// Second pass: functions
	var funcChild = child;
	depth = 0;
	while (!funcChild.isNull() && depth < 5000) {
		var fc = cn(funcChild);
		if (fc === "Function") {
			if (!hasFuncs) {
				file.write("\n\t// Functions\n");
				hasFuncs = true;
			}
			try {
				var funcName = fn(funcChild);
				var funcFlags = safeS32(funcChild.add(CONFIG.UFunc_FuncFlagsOff));
				var numParms = safeS32(funcChild.add(CONFIG.UFunc_NumParmsOff)) & 0xff;

				var flags = [];
				if (funcFlags & 0x00000001) flags.push("Final");
				if (funcFlags & 0x00000002) flags.push("Static");
				if (funcFlags & 0x00000400) flags.push("Native");
				if (funcFlags & 0x00000800) flags.push("Event");
				if (funcFlags & 0x00002000) flags.push("NetMulticast");
				if (funcFlags & 0x00020000) flags.push("Net");
				if (funcFlags & 0x00200000) flags.push("BlueprintCallable");
				if (funcFlags & 0x00400000) flags.push("BlueprintEvent");
				if (funcFlags & 0x04000000) flags.push("Exec");

				// Read function parameters via Children
				var params = [];
				var retType = "void";
				var fparam = safePtr(funcChild.add(CONFIG.UStruct_ChildrenOff));
				var pd = 0;
				while (!fparam.isNull() && pd < 100) {
					var pc = cn(fparam);
					if (pc.length > 8 && pc.substring(pc.length - 8) === "Property") {
						var pn = fn(fparam);
						var pt = getPropType(fparam);
						var pf = readPropFlags(fparam);
						// CPF_ReturnParm = 0x400 (lo), CPF_Parm = 0x80 (lo), CPF_OutParm = 0x100 (lo)
						if (pf.lo & 0x400) {
							retType = pt;
						} else if (pf.lo & 0x80) {
							params.push((pf.lo & 0x100 ? "out " : "") + pt + " " + pn);
						}
					}
					fparam = safePtr(fparam.add(CONFIG.UField_NextOff));
					pd++;
				}

				// Read native function pointer at +0xB0
				var funcPtr = safePtr(funcChild.add(CONFIG.UFunc_FuncPtrOff));
				var funcOffset = "";
				if (!funcPtr.isNull()) {
					var off = funcPtr.sub(gBase);
					// Check if pointer is within module range
					if (off.compare(0) > 0 && off.compare(gModSize) < 0) {
						funcOffset = " // [Offset: 0x" + off.toString(16).toUpperCase() + "]";
					} else {
						funcOffset = " // [Addr: " + funcPtr + "]";
					}
				}

				file.write("\t// Flags: " + (flags.length > 0 ? flags.join("|") : "None") + "\n");
				file.write("\t" + retType + " " + funcName + "(" + params.join(", ") + ");" + funcOffset + " // NumParms: " + numParms + "\n");
			} catch (_) {}
		}
		funcChild = safePtr(funcChild.add(CONFIG.UField_NextOff));
		depth++;
	}

	file.write("};\n\n");
}

// ===================== MAIN ==========================================
function initGlobals() {
	var mod = Process.findModuleByName(CONFIG.moduleName);
	if (!mod) {
		send({ type: "error", msg: "Module not found" });
		return false;
	}
	gBase = mod.base;
	gModSize = mod.size;
	send({ type: "info", msg: "Base: " + gBase + " Size: 0x" + mod.size.toString(16) });

	gNamesArray = safePtr(gBase.add(CONFIG.GNames));
	if (gNamesArray.isNull()) {
		send({ type: "error", msg: "GNames NULL" });
		return false;
	}
	gNumNames = safeS32(gNamesArray.add(CONFIG.NumElementsOff));
	send({ type: "info", msg: "GNames: " + gNumNames + " names" });

	var c0 = safePtr(gNamesArray),
		e0 = c0.isNull() ? ptr(0) : safePtr(c0);
	if (!e0.isNull()) {
		try {
			var n = e0.add(CONFIG.NameEntryNameOff).readCString();
			send({ type: "info", msg: "Entry[0]='" + n + "'" + (n === "None" ? " OK" : " BAD") });
		} catch (_) {}
	}
	return true;
}

function ensureDir() {
	try {
		var libc = Process.findModuleByName("libc.so");
		var mk = libc.findExportByName("mkdir");
		if (mk) new NativeFunction(mk, "int", ["pointer", "int"])(Memory.allocUtf8String(CONFIG.OutputDir), 0x1ff);
	} catch (_) {}
}

function runSDKDump() {
	if (!initGlobals()) return;
	ensureDir();

	send({ type: "phase", msg: "=== SDK Dump v2: Collecting types ===" });

	var arrayBase = gBase.add(CONFIG.GUObjectArray);
	var numChunks = safeS32(arrayBase.add(CONFIG.ObjNumChunksOff));
	var totalNum = safeS32(arrayBase.add(CONFIG.ObjTotalNumOff));
	send({ type: "info", msg: "Objects: chunks=" + numChunks + " total=" + totalNum });

	// Collect all Class/ScriptStruct/Enum
	var targets = [];
	var globalIdx = 0;
	for (var ci = 0; ci < numChunks; ci++) {
		var chunkBase = safePtr(arrayBase.add(CONFIG.ObjChunkPtrsOff + ci * 8));
		var chunkCount = safeS32(arrayBase.add(CONFIG.ObjChunkCountsOff + ci * 4));
		if (chunkBase.isNull() || chunkCount <= 0) {
			globalIdx += chunkCount > 0 ? chunkCount : 0;
			continue;
		}

		for (var wi = 0; wi < chunkCount; wi++) {
			var objPtr = safePtr(chunkBase.add(wi * CONFIG.FUObjectItemSize));
			if (!objPtr.isNull()) {
				var c = cn(objPtr);
				if (c === "Class" || c === "ScriptStruct" || c === "Enum" || c === "UserDefinedEnum") {
					targets.push(objPtr);
				}
			}
			globalIdx++;
			if (globalIdx >= totalNum) break;
		}
		if (globalIdx >= totalNum) break;
	}

	send({ type: "info", msg: "Found " + targets.length + " types" });

	var filePath = CONFIG.OutputDir + "dump.cs";
	var file = new File(filePath, "w");
	file.write("// UE4 SDK Dump v2\n");
	file.write("// Generated by Frida UE4 Dumper\n");
	file.write("// Target: com.tencent.tmgp.pubgmhd\n");
	file.write("// Total: " + targets.length + " types\n\n");

	var count = 0;
	for (var i = 0; i < targets.length; i++) {
		try {
			dumpType(targets[i], file);
			count++;
		} catch (e) {
			// Write a closing brace if we crashed mid-type
			try {
				file.write("}; // ERROR: " + e.message + "\n\n");
			} catch (_) {}
		}
		if (count % 500 === 0 && count > 0) {
			file.flush();
			send({ type: "info", msg: "Progress: " + count + "/" + targets.length });
		}
	}

	file.close();
	send({ type: "info", msg: "SDK dump complete: " + count + " types -> " + filePath });
	send({ type: "done", msg: "Done." });
}

recv("start", function (_) {
	send({ type: "info", msg: "Starting SDK dump v2..." });
	runSDKDump();
});
send({ type: "ready", msg: "SDK dump v2 script loaded. Waiting for start." });
