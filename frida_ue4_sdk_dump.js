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
	UObj_FlagsOff: 0x08,
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
	UProp_RepIndexOff: 0x40,      // uint16 RepIndex (网络复制索引, 0xFFFF=不复制)
	UProp_OffsetOff: 0x44,
	UProp_RepNotifyFuncOff: 0x48, // FName RepNotifyFunc (属性变化通知函数名)
	UFunc_FuncFlagsOff: 0x88,
	UFunc_NumParmsOff: 0x8c,
	// UFunction::Func (FNativeFuncPtr / PMF) — IDA 反编译验证:
	//   sub_A55FF7C: a1[22] = +0xB0 (Func ptr), a1[23] = +0xB8 (PMF adj)
	//   对于 Native 函数, +0xB0 直接包含函数地址
	UFunc_FuncPtrOff: 0xb0,
	// UEnum: CppType(FString=0x10 bytes) starts at +0x30, Names(TArray) at +0x40
	UEnum_NamesOff: 0x40,
	// Verified from the target dump: Property/NumericProperty are 0x70 bytes,
	// ByteProperty is 0x78, and EnumProperty is 0x80.
	UByteProp_EnumOff: 0x70,
	UEnumProp_UnderlyingPropOff: 0x70,
	UEnumProp_EnumOff: 0x78,
	ObjChunkPtrsOff: 0xc8,
	ObjChunkCountsOff: 0xe8,
	ObjNumChunksOff: 0xf8,
	ObjTotalNumOff: 0x100,
	FUObjectItemSize: 24,
	RF_ClassDefaultObject: 0x10,
	ExpandInheritedMembers: true,
	AnnotateExpandedOwner: true,
	EnableVTableDump: true,
	// chain: output every valid slot together with the class that currently provides it.
	// diff: output only slots changed from the immediate parent class.
	VTableDumpMode: "chain",
	VTableMaxSlots: 768,
	VTableStopAfterInvalid: 32,
	AnnotateVTableUFunctions: true,
	MaxVTableUFunctionMatches: 4,
	OutputBufferBytes: 0x40000,
	UClassScanStartOff: 0x28,
	UClassScanMaxOff: 0x400,
	OutputDir: "/data/data/com.tencent.tmgp.pubgmhd/cache/ue4_dump/",
};

var gBase = null,
	gModSize = 0,
	gNamesArray = null,
	gNumNames = 0,
	nameCache = {},
	classDefaultObjectCache = {},
	typeHierarchyCache = {},
	classHierarchyCache = {},
	declaredFieldCache = {},
	declaredFunctionCache = {},
	nativeUFunctionMap = {},
	vtableInfoCache = {},
	outputBufferParts = [],
	outputBufferBytes = 0;

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

function isModulePtr(p) {
	if (p.isNull() || gBase === null) return false;
	try {
		var off = p.sub(gBase);
		return off.compare(0) >= 0 && off.compare(gModSize) < 0;
	} catch (_) {
		return false;
	}
}

function getModuleOffsetText(p) {
	try {
		return "0x" + p.sub(gBase).toString(16).toUpperCase();
	} catch (_) {
		return p.toString();
	}
}

function flushBuffered(file) {
	if (outputBufferParts.length === 0) return;
	file.write(outputBufferParts.join(""));
	outputBufferParts = [];
	outputBufferBytes = 0;
}

function bufferedWrite(file, text) {
	outputBufferParts.push(text);
	outputBufferBytes += text.length;
	if (outputBufferBytes >= CONFIG.OutputBufferBytes) flushBuffered(file);
}

function getObjectFlags(objPtr) {
	return safeU32(objPtr.add(CONFIG.UObj_FlagsOff));
}

function isClassDefaultObject(classPtr, objPtr) {
	if (objPtr.isNull()) return false;
	if ((getObjectFlags(objPtr) & CONFIG.RF_ClassDefaultObject) === 0) return false;
	var objClass = safePtr(objPtr.add(CONFIG.UObj_ClassOff));
	return !objClass.isNull() && objClass.compare(classPtr) === 0;
}

function findClassDefaultObject(classPtr) {
	var key = classPtr.toString();
	if (key in classDefaultObjectCache) return classDefaultObjectCache[key];

	var cdo = ptr(0);
	for (var off = CONFIG.UClassScanStartOff; off < CONFIG.UClassScanMaxOff; off += Process.pointerSize) {
		var candidate = safePtr(classPtr.add(off));
		if (isClassDefaultObject(classPtr, candidate)) {
			cdo = candidate;
			break;
		}
	}

	classDefaultObjectCache[key] = cdo;
	return cdo;
}

function buildTypeHierarchy(typePtr) {
	var key = typePtr.toString();
	if (key in typeHierarchyCache) return typeHierarchyCache[key];

	var chain = [];
	var seen = {};
	var cur = typePtr;
	var depth = 0;
	while (!cur.isNull() && depth < 256) {
		var curKey = cur.toString();
		if (curKey in seen) break;
		seen[curKey] = true;
		chain.unshift(cur);
		cur = safePtr(cur.add(CONFIG.UStruct_SuperOff));
		depth++;
	}

	var hierarchy = [];
	for (var i = 0; i < chain.length; i++) {
		hierarchy.push({
			ptr: chain[i],
			name: fn(chain[i]),
		});
	}

	typeHierarchyCache[key] = hierarchy;
	return hierarchy;
}

function getValidVTableTarget(vtable, slotOff) {
	if (vtable.isNull()) return ptr(0);
	var target = safePtr(vtable.add(slotOff));
	if (target.isNull() || !isModulePtr(target)) return ptr(0);
	return target;
}

function buildClassHierarchy(classPtr) {
	var key = classPtr.toString();
	if (key in classHierarchyCache) return classHierarchyCache[key];

	var typeHierarchy = buildTypeHierarchy(classPtr);
	var hierarchy = [];
	for (var i = 0; i < typeHierarchy.length; i++) {
		var cls = typeHierarchy[i].ptr;
		var cdo = findClassDefaultObject(cls);
		hierarchy.push({
			ptr: cls,
			name: typeHierarchy[i].name,
			cdo: cdo,
			vtable: cdo.isNull() ? ptr(0) : safePtr(cdo),
		});
	}

	classHierarchyCache[key] = hierarchy;
	return hierarchy;
}

function getHierarchyText(hierarchy) {
	var names = [];
	for (var i = 0; i < hierarchy.length; i++) names.push(hierarchy[i].name);
	return names.join(" -> ");
}

function getFunctionFlagsList(funcFlags) {
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
	return flags;
}

function getFunctionLocationSuffix(funcPtr) {
	if (funcPtr.isNull()) return "";
	var off = funcPtr.sub(gBase);
	if (off.compare(0) > 0 && off.compare(gModSize) < 0) {
		return " // [Offset: 0x" + off.toString(16).toUpperCase() + "]";
	}
	return " // [Addr: " + funcPtr + "]";
}

function collectDeclaredFields(typePtr) {
	var key = typePtr.toString();
	if (key in declaredFieldCache) return declaredFieldCache[key];

	var ownerName = fn(typePtr);
	var fields = [];
	var child = safePtr(typePtr.add(CONFIG.UStruct_ChildrenOff));
	var depth = 0;
	while (!child.isNull() && depth < 5000) {
		var cc = cn(child);
		if (cc.length > 8 && cc.substring(cc.length - 8) === "Property") {
			try {
				var fieldType = getFieldTypeInfo(child);
				fields.push({
					ownerName: ownerName,
					propName: fn(child),
					typeName: fieldType.typeName,
					enumPath: fieldType.enumPath,
					offset: safeS32(child.add(CONFIG.UProp_OffsetOff)),
					elemSize: safeS32(child.add(CONFIG.UProp_ElementSizeOff)),
					arrayDim: safeS32(child.add(CONFIG.UProp_ArrayDimOff)),
					repIndex: safeU32(child.add(CONFIG.UProp_RepIndexOff)) & 0xFFFF,
					repNotifyFunc: readFName(child.add(CONFIG.UProp_RepNotifyFuncOff)),
				});
			} catch (_) {}
		}
		child = safePtr(child.add(CONFIG.UField_NextOff));
		depth++;
	}

	declaredFieldCache[key] = fields;
	return fields;
}

function collectExpandedFields(typePtr) {
	if (!CONFIG.ExpandInheritedMembers) return collectDeclaredFields(typePtr);
	var hierarchy = buildTypeHierarchy(typePtr);
	var fields = [];
	for (var i = 0; i < hierarchy.length; i++) {
		var declared = collectDeclaredFields(hierarchy[i].ptr);
		for (var j = 0; j < declared.length; j++) fields.push(declared[j]);
	}
	return fields;
}

function collectDeclaredFunctions(typePtr) {
	var key = typePtr.toString();
	if (key in declaredFunctionCache) return declaredFunctionCache[key];

	var ownerName = fn(typePtr);
	var functions = [];
	var child = safePtr(typePtr.add(CONFIG.UStruct_ChildrenOff));
	var depth = 0;
	while (!child.isNull() && depth < 5000) {
		if (cn(child) === "Function") {
			try {
				var funcFlags = safeS32(child.add(CONFIG.UFunc_FuncFlagsOff));
				var numParms = safeS32(child.add(CONFIG.UFunc_NumParmsOff)) & 0xff;
				var params = [];
				var retType = "void";
				var fparam = safePtr(child.add(CONFIG.UStruct_ChildrenOff));
				var pd = 0;
				while (!fparam.isNull() && pd < 100) {
					var pc = cn(fparam);
					if (pc.length > 8 && pc.substring(pc.length - 8) === "Property") {
						var pn = fn(fparam);
						var pt = getPropType(fparam);
						var pf = readPropFlags(fparam);
						if (pf.lo & 0x400) {
							retType = pt;
						} else if (pf.lo & 0x80) {
							params.push((pf.lo & 0x100 ? "out " : "") + pt + " " + pn);
						}
					}
					fparam = safePtr(fparam.add(CONFIG.UField_NextOff));
					pd++;
				}

				var funcPtr = safePtr(child.add(CONFIG.UFunc_FuncPtrOff));
				functions.push({
					ownerName: ownerName,
					funcName: fn(child),
					funcFlags: funcFlags,
					flagNames: getFunctionFlagsList(funcFlags),
					numParms: numParms,
					params: params,
					retType: retType,
					funcPtr: funcPtr,
					locationSuffix: getFunctionLocationSuffix(funcPtr),
					qualifiedName: ownerName + "::" + fn(child),
				});
			} catch (_) {}
		}
		child = safePtr(child.add(CONFIG.UField_NextOff));
		depth++;
	}

	declaredFunctionCache[key] = functions;
	return functions;
}

function collectExpandedFunctions(typePtr) {
	if (!CONFIG.ExpandInheritedMembers) return collectDeclaredFunctions(typePtr);
	var hierarchy = buildTypeHierarchy(typePtr);
	var functions = [];
	for (var i = 0; i < hierarchy.length; i++) {
		var declared = collectDeclaredFunctions(hierarchy[i].ptr);
		for (var j = 0; j < declared.length; j++) functions.push(declared[j]);
	}
	return functions;
}

function registerNativeUFunction(funcInfo) {
	if (funcInfo.funcPtr.isNull() || !isModulePtr(funcInfo.funcPtr)) return;
	var key = funcInfo.funcPtr.toString();
	if (!(key in nativeUFunctionMap)) nativeUFunctionMap[key] = [];
	var list = nativeUFunctionMap[key];
	for (var i = 0; i < list.length; i++) {
		if (list[i] === funcInfo.qualifiedName) return;
	}
	list.push(funcInfo.qualifiedName);
}

function buildNativeUFunctionMap(targets) {
	nativeUFunctionMap = {};
	var totalFunctions = 0;
	var indexedFunctions = 0;
	for (var i = 0; i < targets.length; i++) {
		var declared = collectDeclaredFunctions(targets[i]);
		for (var j = 0; j < declared.length; j++) {
			totalFunctions++;
			var before = Object.prototype.hasOwnProperty.call(nativeUFunctionMap, declared[j].funcPtr.toString())
				? nativeUFunctionMap[declared[j].funcPtr.toString()].length
				: 0;
			registerNativeUFunction(declared[j]);
			if (!declared[j].funcPtr.isNull() && isModulePtr(declared[j].funcPtr)) {
				var after = nativeUFunctionMap[declared[j].funcPtr.toString()].length;
				if (after > before) indexedFunctions++;
			}
		}
	}
	send({ type: "info", msg: "Indexed " + indexedFunctions + " native UFunctions from " + totalFunctions + " reflected functions." });
}

function getVTableUFunctionAnnotation(target) {
	if (!CONFIG.AnnotateVTableUFunctions) return "";
	var key = target.toString();
	if (!(key in nativeUFunctionMap)) return "";
	var list = nativeUFunctionMap[key];
	if (!list || list.length === 0) return "";
	var shown = list.slice(0, CONFIG.MaxVTableUFunctionMatches);
	var text = " [UFunction: " + shown.join(" | ");
	if (list.length > shown.length) text += " | +" + (list.length - shown.length) + " more";
	text += "]";
	return text;
}

function dumpFieldEntries(file, fields, expanded) {
	if (fields.length === 0) return false;
	bufferedWrite(file, "\t// Fields" + (expanded ? " (Expanded Inheritance)" : "") + "\n");
	for (var i = 0; i < fields.length; i++) {
		var field = fields[i];
		var line = "\t" + field.typeName + " " + field.propName;
		if (field.arrayDim > 1) line += "[" + field.arrayDim + "]";
		line += "; // 0x" + (field.offset >>> 0).toString(16).toUpperCase();
		line += " (Size: 0x" + (field.elemSize >>> 0).toString(16).toUpperCase() + ")";
		if (field.enumPath) line += " [UEnum: " + field.enumPath + "]";
		if (field.repIndex !== 0xFFFF) line += " [RepIndex: " + field.repIndex + "]";
		if (field.repNotifyFunc && field.repNotifyFunc !== "None" && field.repNotifyFunc !== "<invalid>") line += " [RepNotify: " + field.repNotifyFunc + "]";
		if (expanded && CONFIG.AnnotateExpandedOwner) line += " [Owner: " + field.ownerName + "]";
		bufferedWrite(file, line + "\n");
	}
	return true;
}

function dumpFunctionEntries(file, functions, expanded) {
	if (functions.length === 0) return false;
	bufferedWrite(file, "\n\t// Functions" + (expanded ? " (Expanded Inheritance)" : "") + "\n");
	for (var i = 0; i < functions.length; i++) {
		var func = functions[i];
		var flagsText = func.flagNames.length > 0 ? func.flagNames.join("|") : "None";
		if (expanded && CONFIG.AnnotateExpandedOwner) flagsText += " [Owner: " + func.ownerName + "]";
		bufferedWrite(file, "\t// Flags: " + flagsText + "\n");
		bufferedWrite(file, "\t" + func.retType + " " + func.funcName + "(" + func.params.join(", ") + ");" + func.locationSuffix + " // NumParms: " + func.numParms + "\n");
	}
	return true;
}

function getImplementingClass(hierarchy, slotOff, currentTarget) {
	var provider = hierarchy[hierarchy.length - 1];
	for (var i = hierarchy.length - 2; i >= 0; i--) {
		var ancestorTarget = getValidVTableTarget(hierarchy[i].vtable, slotOff);
		if (ancestorTarget.isNull()) continue;
		if (ancestorTarget.compare(currentTarget) === 0) {
			provider = hierarchy[i];
			continue;
		}
		break;
	}
	return provider;
}

function collectVTableInfo(classPtr, superPtr) {
	var key = classPtr.toString();
	if (key in vtableInfoCache) return vtableInfoCache[key];

	var info = {
		cdo: ptr(0),
		vtable: ptr(0),
		hierarchy: [],
		entries: [],
	};

	if (!CONFIG.EnableVTableDump) {
		vtableInfoCache[key] = info;
		return info;
	}

	var hierarchy = buildClassHierarchy(classPtr);
	info.hierarchy = hierarchy;
	if (hierarchy.length === 0) {
		vtableInfoCache[key] = info;
		return info;
	}

	var cdo = findClassDefaultObject(classPtr);
	if (cdo.isNull()) {
		vtableInfoCache[key] = info;
		return info;
	}

	var vtable = safePtr(cdo);
	if (vtable.isNull()) {
		info.cdo = cdo;
		vtableInfoCache[key] = info;
		return info;
	}

	info.cdo = cdo;
	info.vtable = vtable;

	var superVTable = ptr(0);
	if (CONFIG.VTableDumpMode === "diff" && !superPtr.isNull()) {
		var superCDO = findClassDefaultObject(superPtr);
		if (!superCDO.isNull()) superVTable = safePtr(superCDO);
	}

	var sawModuleEntry = false;
	var invalidRun = 0;
	for (var slotIndex = 0; slotIndex < CONFIG.VTableMaxSlots; slotIndex++) {
		var slotOff = slotIndex * Process.pointerSize;
		var target = getValidVTableTarget(vtable, slotOff);

		if (target.isNull()) {
			if (sawModuleEntry) {
				invalidRun++;
				if (invalidRun >= CONFIG.VTableStopAfterInvalid) break;
			}
			continue;
		}

		sawModuleEntry = true;
		invalidRun = 0;

		if (CONFIG.VTableDumpMode === "diff" && !superVTable.isNull()) {
			var superTarget = getValidVTableTarget(superVTable, slotOff);
			if (!superTarget.isNull() && superTarget.compare(target) === 0) continue;
		}

		var provider = getImplementingClass(hierarchy, slotOff, target);

		info.entries.push({
			slotOff: slotOff,
			target: target,
			offsetText: getModuleOffsetText(target),
			implementorName: provider.name,
			inherited: provider.ptr.compare(classPtr) !== 0,
			uFunctionAnnotation: getVTableUFunctionAnnotation(target),
		});
	}

	vtableInfoCache[key] = info;
	return info;
}

function dumpClassVTable(classPtr, superPtr, file) {
	var info = collectVTableInfo(classPtr, superPtr);
	if (info.entries.length === 0) return false;

	bufferedWrite(file, "\n\t// C++ VTable Inheritance Chain (" + CONFIG.VTableDumpMode + " via CDO)\n");
	if (info.hierarchy.length > 0) {
		bufferedWrite(file, "\t// Inheritance: " + getHierarchyText(info.hierarchy) + "\n");
	}
	bufferedWrite(file, "\t// CDO: " + info.cdo + " VTable: " + info.vtable + "\n");
	for (var i = 0; i < info.entries.length; i++) {
		var entry = info.entries[i];
		bufferedWrite(
			file,
			"\t// [Slot: 0x" +
				entry.slotOff.toString(16).toUpperCase() +
				"] [ImplClass: " +
				entry.implementorName +
				(entry.inherited ? " inherited" : " override") +
				"] [Offset: " +
				entry.offsetText +
				"]" +
				entry.uFunctionAnnotation +
				"\n"
		);
	}
	return true;
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

function getObjectPath(p) {
	if (p.isNull()) return "";
	var outer = outerChain(p);
	var name = fn(p);
	return outer.length > 0 ? outer + "." + name : name;
}

function getBoundEnumPtr(propPtr) {
	var propClass = cn(propPtr);
	if (propClass === "EnumProperty") return safePtr(propPtr.add(CONFIG.UEnumProp_EnumOff));
	if (propClass === "ByteProperty") return safePtr(propPtr.add(CONFIG.UByteProp_EnumOff));
	return ptr(0);
}

function getBoundEnumPath(propPtr) {
	var enumPtr = getBoundEnumPtr(propPtr);
	if (enumPtr.isNull()) return "";
	var enumClass = cn(enumPtr);
	if (enumClass !== "Enum" && enumClass !== "UserDefinedEnum") return "";
	return getObjectPath(enumPtr);
}

function getFieldTypeInfo(propPtr) {
	var typeName = getPropType(propPtr);
	var enumPath = getBoundEnumPath(propPtr);
	if (typeName === "uint8" && enumPath) typeName = "enum";
	return {
		typeName: typeName,
		enumPath: enumPath,
	};
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
		bufferedWrite(file, "\t// (no enum values)\n");
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

		bufferedWrite(file, "\t" + enumName + " = " + value + ",\n");
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
		bufferedWrite(file, "// Enum " + outer + "." + objName + "\n");
		bufferedWrite(file, "enum " + objName + " {\n");
		try {
			dumpEnumValues(objPtr, file);
		} catch (_) {
			bufferedWrite(file, "\t// (error reading values)\n");
		}
		bufferedWrite(file, "};\n\n");
		return;
	}

	var superPtr = safePtr(objPtr.add(CONFIG.UStruct_SuperOff));
	var superName = superPtr.isNull() ? "" : fn(superPtr);
	var propSize = safeS32(objPtr.add(CONFIG.UStruct_PropSizeOff));
	var expandedMembers = CONFIG.ExpandInheritedMembers;

	bufferedWrite(file, "// " + (isClass ? "Class" : "ScriptStruct") + " " + pkg + "." + objName + "\n");
	bufferedWrite(file, "// Size: 0x" + (propSize >>> 0).toString(16).toUpperCase() + "\n");
	bufferedWrite(file, (isClass ? "class " : "struct ") + objName);
	if (superName) bufferedWrite(file, " : public " + superName);
	bufferedWrite(file, "\n{\n");

	dumpFieldEntries(file, collectExpandedFields(objPtr), expandedMembers);

	if (isClass) dumpClassVTable(objPtr, superPtr, file);

	dumpFunctionEntries(file, collectExpandedFunctions(objPtr), expandedMembers);

	bufferedWrite(file, "};\n\n");
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
	buildNativeUFunctionMap(targets);

	var filePath = CONFIG.OutputDir + "dump.cs";
	var file = new File(filePath, "w");
	bufferedWrite(file, "// UE4 SDK Dump v2\n");
	bufferedWrite(file, "// Generated by Frida UE4 Dumper\n");
	bufferedWrite(file, "// Target: com.tencent.tmgp.pubgmhd\n");
	var includeParts = [];
	includeParts.push(CONFIG.ExpandInheritedMembers ? "expanded inherited reflected fields/functions" : "reflected fields/functions");
	includeParts.push("UFunction addresses");
	if (CONFIG.EnableVTableDump) includeParts.push("C++ vtable inheritance chain (" + CONFIG.VTableDumpMode + ")");
	if (CONFIG.AnnotateVTableUFunctions) includeParts.push("vtable to UFunction reverse matches");
	bufferedWrite(file, "// Includes: " + includeParts.join(", ") + "\n");
	bufferedWrite(file, "// Total: " + targets.length + " types\n\n");

	var count = 0;
	for (var i = 0; i < targets.length; i++) {
		try {
			dumpType(targets[i], file);
			count++;
		} catch (e) {
			// Write a closing brace if we crashed mid-type
			try {
				bufferedWrite(file, "}; // ERROR: " + e.message + "\n\n");
			} catch (_) {}
		}
		if (count % 500 === 0 && count > 0) {
			flushBuffered(file);
			file.flush();
			send({ type: "info", msg: "Progress: " + count + "/" + targets.length });
		}
	}

	flushBuffered(file);
	file.close();
	send({ type: "info", msg: "SDK dump complete: " + count + " types -> " + filePath });
	send({ type: "done", msg: "Done." });
}

recv("start", function (_) {
	send({ type: "info", msg: "Starting SDK dump v2..." });
	runSDKDump();
});
send({ type: "ready", msg: "SDK dump v2 script loaded. Waiting for start." });
