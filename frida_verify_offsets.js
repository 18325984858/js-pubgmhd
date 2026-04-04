"use strict";
var CONFIG = {
	moduleName: "libUE4.so",
	GNames: 0x146f9f30,
	GUObjectArray: 0x14706480,
	ElementsPerChunk: 16384,
	NumElementsOff: 0x1400,
	NameEntryNameOff: 0x0c,
	NameEntryIndexOff: 0x08,
	ObjChunkPtrsOff: 0xc8,
	ObjChunkCountsOff: 0xe8,
	ObjTotalNumOff: 0x100,
	FUObjectItemSize: 24,
};
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
var gBase, gNamesArray, gNumNames;
function initN() {
	var m = Process.findModuleByName(CONFIG.moduleName);
	gBase = m.base;
	gNamesArray = safePtr(gBase.add(CONFIG.GNames));
	gNumNames = safeS32(gNamesArray.add(CONFIG.NumElementsOff));
}
function rn(i) {
	if (i < 0 || i >= gNumNames) return "<OOB>";
	var c = (i / CONFIG.ElementsPerChunk) >>> 0,
		w = i % CONFIG.ElementsPerChunk;
	var ck = safePtr(gNamesArray.add(c * 8));
	if (ck.isNull()) return "<NC>";
	var e = safePtr(ck.add(w * 8));
	if (e.isNull()) return "<NE>";
	try {
		return e.add(CONFIG.NameEntryNameOff).readCString();
	} catch (_) {
		return "<err>";
	}
}
function fn(p) {
	var i = safeS32(p.add(0x18)),
		n = safeS32(p.add(0x1c)),
		b = rn(i);
	return n ? b + "_" + (n - 1) : b;
}
function cn(p) {
	var c = safePtr(p.add(0x10));
	return c.isNull() ? "<NC>" : fn(c);
}
function dh(addr, len) {
	var lines = [];
	try {
		var buf = addr.readByteArray(len);
		var bytes = new Uint8Array(buf);
		for (var off = 0; off < bytes.length; off += 16) {
			var hex = "";
			for (var j = 0; j < 16 && off + j < bytes.length; j++) hex += ("0" + bytes[off + j].toString(16)).slice(-2) + " ";
			lines.push("  +0x" + off.toString(16).padStart(3, "0") + ": " + hex.trim());
		}
	} catch (e) {
		lines.push("  <unreadable>");
	}
	return lines.join("\n");
}

function run() {
	initN();
	send({ type: "info", msg: "Base:" + gBase + " Names:" + gNumNames });
	var ab = gBase.add(CONFIG.GUObjectArray);
	var c0 = safePtr(ab.add(CONFIG.ObjChunkPtrsOff));
	var tn = safeS32(ab.add(CONFIG.ObjTotalNumOff));
	send({ type: "info", msg: "Chunk0=" + c0 + " Total=" + tn });

	var classObj = null,
		funcObj = null,
		intProp = null;
	for (var i = 0; i < Math.min(tn, 500); i++) {
		var obj = safePtr(c0.add(i * CONFIG.FUObjectItemSize));
		if (obj.isNull()) continue;
		var cc = cn(obj),
			nm = fn(obj);
		if (cc === "Class" && !classObj) {
			classObj = obj;
			send({ type: "info", msg: "Class: " + nm + " @ " + obj });
		}
		if (cc === "Function" && !funcObj) {
			funcObj = obj;
			send({ type: "info", msg: "Func: " + nm + " @ " + obj });
		}
		if (cc === "IntProperty" && !intProp) {
			intProp = obj;
			send({ type: "info", msg: "IntProp: " + nm + " @ " + obj });
		}
		if (classObj && funcObj && intProp) break;
	}

	if (classObj) {
		send({ type: "info", msg: "\n=== UClass: " + fn(classObj) + " ===" });
		// scan 0x28-0x60 for valid pointers
		for (var off = 0x28; off <= 0x60; off += 8) {
			var v = safePtr(classObj.add(off));
			if (!v.isNull()) {
				try {
					send({ type: "info", msg: "  +0x" + off.toString(16) + ": " + cn(v) + " " + fn(v) });
				} catch (_) {
					send({ type: "info", msg: "  +0x" + off.toString(16) + ": " + v + " (not UObject)" });
				}
			} else {
				send({ type: "info", msg: "  +0x" + off.toString(16) + ": NULL" });
			}
		}

		// follow Children chain at +0x38
		var child = safePtr(classObj.add(0x38));
		if (!child.isNull()) {
			send({ type: "info", msg: "\nChildren chain from +0x38:" });
			var depth = 0;
			while (!child.isNull() && depth < 10) {
				send({ type: "info", msg: "  [" + depth + "] " + cn(child) + " " + fn(child) });
				// dump child 0x28-0x50
				send({ type: "info", msg: dh(child.add(0x28), 0x28) });
				// try next at 0x28, 0x30
				var n28 = safePtr(child.add(0x28));
				var n30 = safePtr(child.add(0x30));
				send({
					type: "info",
					msg:
						"    child+0x28: " +
						(n28.isNull() ? "NULL" : n28) +
						(!n28.isNull() ? " -> " + cn(n28) + " " + fn(n28) : ""),
				});
				send({
					type: "info",
					msg:
						"    child+0x30: " +
						(n30.isNull() ? "NULL" : n30) +
						(!n30.isNull() ? " -> " + cn(n30) + " " + fn(n30) : ""),
				});
				// use +0x28 as Next if valid, else try +0x30
				var next = n28;
				if (next.isNull()) next = n30;
				child = next;
				depth++;
			}
		}
	}

	// IntProperty verification
	if (intProp) {
		send({ type: "info", msg: "\n=== IntProperty: " + fn(intProp) + " ===" });
		send({ type: "info", msg: "Full dump 0x28-0x70:\n" + dh(intProp.add(0x28), 0x48) });
		// IntProperty: ArrayDim=1, ElementSize=4
		for (var off = 0x28; off <= 0x50; off += 4) {
			var v = safeS32(intProp.add(off));
			if (v >= 1 && v <= 8) send({ type: "info", msg: "  +0x" + off.toString(16) + " = " + v });
		}
	}

	// Function verification
	if (funcObj) {
		send({ type: "info", msg: "\n=== Function: " + fn(funcObj) + " ===" });
		send({ type: "info", msg: "Full dump 0x28-0xA0:\n" + dh(funcObj.add(0x28), 0x78) });
		// Check SuperStruct and Children on function
		for (var off = 0x28; off <= 0x48; off += 8) {
			var v = safePtr(funcObj.add(off));
			if (!v.isNull()) {
				try {
					send({ type: "info", msg: "  func+0x" + off.toString(16) + ": " + cn(v) + " " + fn(v) });
				} catch (_) {}
			}
		}
	}

	send({ type: "done", msg: "Done" });
}
recv("start", function (_) {
	send({ type: "info", msg: "Go" });
	run();
});
send({ type: "ready", msg: "Ready" });
