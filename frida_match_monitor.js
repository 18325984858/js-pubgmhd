"use strict";

// =====================================================================
//  UE4.18 对局状态实时监控 + 玩家坐标采集 — Frida Script
//  Target: com.tencent.tmgp.pubgmhd (ARM64 Android)
//  偏移经 dump.cs + IDA MCP 反编译验证
// =====================================================================

var CONFIG = {
	moduleName: "libUE4.so",

	// 全局变量偏移 (相对 libUE4.so 基址)
	GNames: 0x146f9f30,
	GWorld: 0x14988578,

	// TNameEntryArray
	ElementsPerChunk: 16384,
	NumElementsOff: 0x1400,
	NameEntryNameOff: 0x0c,
	NameEntryIndexOff: 0x08,

	// UWorld 成员偏移 (dump.cs: class World)
	UWorld_GameStateOff: 0xab8,
	UWorld_AuthGameModeOff: 0xab0,

	// GameState 偏移
	GameState_MatchStateOff: 0x620,
	GameStateBase_bHasBegunPlayOff: 0x5f0,
	GameStateBase_WorldTimeOff: 0x5f4,
	GameStateBase_PlayerArrayOff: 0x5e0,    // TArray<APlayerState*>
	UAEGameState_PlayerNumOff: 0xd34,
	UAEGameState_TotalPlayerNumOff: 0xd30,
	UAEGameState_GameTypeOff: 0xd84,

	// PlayerState 偏移 (PlayerState -> UAEPlayerState -> STExtraPlayerState)
	PS_PlayerNameOff: 0x5d0,          // FString PlayerName
	PS_PlayerKeyOff: 0x700,           // uint32 PlayerKey
	PS_bAIPlayerOff: 0x740,           // bool bAIPlayer
	PS_TeamIDOff: 0x7c4,              // int32 TeamID
	PS_KillsOff: 0x824,              // int32 Kills
	PS_LiveStateOff: 0x1588,          // uint8 LiveState
	PS_CharacterOwnerOff: 0x1600,     // UObject* CharacterOwner
	PS_PlayerHealthOff: 0x1610,       // float PlayerHealth
	PS_PlayerHealthMaxOff: 0x1614,    // float PlayerHealthMax
	PS_SelfLocAndRotOff: 0x1620,      // FRepLocAndRot (0x18, 含坐标)

	// Actor 位置偏移 (IDA K2_GetActorLocation 0xC764EF4 验证)
	Actor_RootComponentOff: 0x268,    // USceneComponent* RootComponent
	SceneComp_TranslationOff: 0x200,  // ComponentToWorld.Translation (FVector)

	// UWorld -> PlayerController 链路
	UWorld_OwningGameInstanceOff: 0xB00,
	GameInstance_LocalPlayersOff: 0x48, // TArray<ULocalPlayer*>
	LocalPlayer_PlayerControllerOff: 0x30, // UPlayer::PlayerController

	// UAEPlayerController 观战相关
	PC_bIsObserverOff: 0x10F8,         // bool bIsObserver
	PC_bIsObserverInBattleOff: 0x10F9, // bool bIsObserverInBattle
	PC_bIsObserverHostOff: 0x10FA,     // bool bIsObserverHost

	// 网络可见范围 (AActor)
	Actor_NetCullDistSqOff: 0x208,     // float NetCullDistanceSquared
	Actor_bAlwaysRelevantOff: 0x90,    // bool bAlwaysRelevant
	Char_CurrentNetCullDistSqOff: 0x4600, // float CurrentNetCullDistanceSquared (STExtraBaseCharacter)

	// Character 直读偏移 (用于 GUObjectArray 扫描)
	Char_HealthOff: 0xfd8,            // float Health (STExtraCharacter)
	Char_HealthMaxOff: 0xfe0,         // float HealthMax
	Char_TeamIDOff: 0xb68,            // int32 TeamID (UAECharacter)
	Char_PlayerKeyOff: 0xb08,         // uint32 PlayerKey (UAECharacter)
	Char_PlayerNameOff: 0xae8,        // FString PlayerName (UAECharacter)
	Char_bDeadOff: 0x1058,            // bool bDead (STExtraCharacter)

	// GUObjectArray (分块, PUBG 定制版)
	GUObjectArray: 0x14706480,
	ObjChunkPtrsOff: 0xc8,
	ObjChunkCountsOff: 0xe8,
	ObjNumChunksOff: 0xf8,
	ObjTotalNumOff: 0x100,
	FUObjectItemSize: 24,
	UStruct_SuperOff: 0x30,           // UStruct.SuperStruct

	// UObjectBase
	UObj_ClassOff: 0x10,
	UObj_NameIdxOff: 0x18,
	UObj_NameNumOff: 0x1c,
	UObj_OuterOff: 0x20,

	// 轮询间隔
	PollInterval: 2000,
	PlayerPollInterval: 1000,

	// 日志输出
	LogDir: "/data/data/com.tencent.tmgp.pubgmhd/cache/ue4_dump/",
	LogFile: "player_log.txt",
	EnableFileLog: true,
};

// =====================================================================
//  双向链表 — 存储玩家坐标和血量信息
// =====================================================================
function PlayerNode(playerKey) {
	this.playerKey = playerKey;
	this.teamID = 0;
	this.playerName = "";
	this.isAI = false;
	this.liveState = 0;
	this.health = 0.0;
	this.healthMax = 0.0;
	this.kills = 0;
	this.posX = 0.0;
	this.posY = 0.0;
	this.posZ = 0.0;
	this.prev = null;
	this.next = null;
}

function PlayerList() {
	this.head = null;
	this.tail = null;
	this.size = 0;
	this._map = {};
}

PlayerList.prototype.clear = function () {
	this.head = null;
	this.tail = null;
	this.size = 0;
	this._map = {};
};

PlayerList.prototype.findByKey = function (playerKey) {
	return this._map[playerKey] || null;
};

PlayerList.prototype.upsert = function (playerKey, data) {
	var node = this.findByKey(playerKey);
	if (node) {
		node.teamID = data.teamID;
		node.playerName = data.playerName;
		node.isAI = data.isAI;
		node.liveState = data.liveState;
		node.health = data.health;
		node.healthMax = data.healthMax;
		node.kills = data.kills;
		node.posX = data.posX;
		node.posY = data.posY;
		node.posZ = data.posZ;
		return node;
	}
	node = new PlayerNode(playerKey);
	node.teamID = data.teamID;
	node.playerName = data.playerName;
	node.isAI = data.isAI;
	node.liveState = data.liveState;
	node.health = data.health;
	node.healthMax = data.healthMax;
	node.kills = data.kills;
	node.posX = data.posX;
	node.posY = data.posY;
	node.posZ = data.posZ;
	if (!this.head) {
		this.head = node;
		this.tail = node;
	} else {
		node.prev = this.tail;
		this.tail.next = node;
		this.tail = node;
	}
	this.size++;
	this._map[playerKey] = node;
	return node;
};

PlayerList.prototype.remove = function (playerKey) {
	var node = this.findByKey(playerKey);
	if (!node) return;
	if (node.prev) node.prev.next = node.next;
	else this.head = node.next;
	if (node.next) node.next.prev = node.prev;
	else this.tail = node.prev;
	this.size--;
	delete this._map[playerKey];
};

PlayerList.prototype.toArray = function () {
	var arr = [];
	var cur = this.head;
	while (cur) { arr.push(cur); cur = cur.next; }
	return arr;
};

// ===================== 全局变量 ======================================
var gBase = null;
var gModSize = 0;
var gNamesArray = null;
var gNumNames = 0;
var nameCache = {};
var lastMatchState = "";
var isMonitoring = false;
var monitorTimer = null;
var playerTimer = null;
var playerList = new PlayerList();
var isInMatch = false;
var logFile = null;
var logLineCount = 0;
var characterClassSet = {};   // UClass* -> true, 缓存所有 Character 子类
var myTeamID = -1;
var lastReportedArrayNum = -1;
var lastReportedTotal = -1;

// ===================== 内存写入 ======================================
// addr: 目标地址 (NativePointer 或数字/字符串)
// size: 写入字节数 (1, 2, 4, 8 或任意长度)
// value: 要写入的值 (整数/浮点数/ArrayBuffer/数组)
function writeMemory(addr, size, value) {
	var target = (addr instanceof NativePointer) ? addr : ptr(addr);
	try {
		Memory.protect(target, size, "rwx");
	} catch (_) {}
	try {
		if (value instanceof ArrayBuffer || (Array.isArray(value))) {
			var bytes = Array.isArray(value) ? value : new Uint8Array(value);
			target.writeByteArray(Array.isArray(value) ? value : Array.from(bytes));
		} else if (typeof value === "number") {
			switch (size) {
				case 1: target.writeU8(value & 0xff); break;
				case 2: target.writeU16(value & 0xffff); break;
				case 4: target.writeU32(value >>> 0); break;
				case 8: target.writeU64(uint64(value)); break;
				default:
					var buf = [];
					for (var i = 0; i < size; i++) { buf.push((value >> (i * 8)) & 0xff); }
					target.writeByteArray(buf);
					break;
			}
		} else {
			send({ type: "error", msg: "writeMemory: unsupported value type" });
			return false;
		}
		return true;
	} catch (e) {
		send({ type: "error", msg: "writeMemory failed at " + target + ": " + e.message });
		return false;
	}
}

function writeFloat(addr, value) {
	var target = (addr instanceof NativePointer) ? addr : ptr(addr);
	try { Memory.protect(target, 4, "rwx"); } catch (_) {}
	try { target.writeFloat(value); return true; }
	catch (e) { send({ type: "error", msg: "writeFloat failed: " + e.message }); return false; }
}

// ===================== 安全读取 ======================================
function safePtr(addr) {
	try { return addr.readPointer(); } catch (_) { return ptr(0); }
}
function safeS32(addr) {
	try { return addr.readS32(); } catch (_) { return 0; }
}
function safeU32(addr) {
	try { return addr.readU32(); } catch (_) { return 0; }
}
function safeU8(addr) {
	try { return addr.readU8(); } catch (_) { return 0; }
}
function safeFloat(addr) {
	try { return addr.readFloat(); } catch (_) { return 0.0; }
}

// ===================== FName 解析 ====================================
function getNameByIndex(index) {
	if (index in nameCache) return nameCache[index];
	if (index < 0 || index >= gNumNames) return null;
	var ci = (index / CONFIG.ElementsPerChunk) >>> 0;
	var wi = index % CONFIG.ElementsPerChunk;
	var chk = safePtr(gNamesArray.add(ci * 8));
	if (chk.isNull()) return null;
	var ent = safePtr(chk.add(wi * 8));
	if (ent.isNull()) return null;
	var idx = safeS32(ent.add(CONFIG.NameEntryIndexOff));
	var name = null;
	if ((idx & 1) === 0) {
		try { name = ent.add(CONFIG.NameEntryNameOff).readCString(); } catch (_) {}
	} else {
		try {
			var r = "", a = ent.add(CONFIG.NameEntryNameOff);
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

function readFName(addr) {
	var idx = safeS32(addr);
	var num = safeS32(addr.add(4));
	var base = getNameByIndex(idx);
	if (!base) return "<invalid>";
	return num === 0 ? base : base + "_" + (num - 1);
}

function readObjName(objPtr) {
	return readFName(objPtr.add(CONFIG.UObj_NameIdxOff));
}

function readClassName(objPtr) {
	var cls = safePtr(objPtr.add(CONFIG.UObj_ClassOff));
	return cls.isNull() ? "<no_class>" : readObjName(cls);
}

// ===================== 日志工具 ======================================
function ensureLogDir() {
	try {
		var libc = Process.findModuleByName("libc.so");
		var mkdirAddr = libc.findExportByName("mkdir");
		if (mkdirAddr) {
			var mkdir = new NativeFunction(mkdirAddr, "int", ["pointer", "int"]);
			mkdir(Memory.allocUtf8String(CONFIG.LogDir), 0x1ff);
		}
	} catch (_) {}
}

function openLog() {
	if (!CONFIG.EnableFileLog) return;
	ensureLogDir();
	try {
		logFile = new File(CONFIG.LogDir + CONFIG.LogFile, "w");
		logLineCount = 0;
		writeLog("=== PUBG Mobile Player Log ===");
		writeLog("Started: " + new Date().toISOString());
		writeLog("");
	} catch (e) {
		send({ type: "error", msg: "Failed to open log: " + e.message });
		logFile = null;
	}
}

function writeLog(line) {
	if (!logFile) return;
	try {
		logFile.write(line + "\n");
		logLineCount++;
		if (logLineCount % 50 === 0) logFile.flush();
	} catch (_) {}
}

function closeLog() {
	if (!logFile) return;
	try {
		writeLog("");
		writeLog("=== Log ended: " + new Date().toISOString() + " ===");
		logFile.close();
		send({ type: "info", msg: "日志已保存: " + CONFIG.LogDir + CONFIG.LogFile + " (" + logLineCount + " lines)" });
	} catch (_) {}
	logFile = null;
	logLineCount = 0;
}

// ===================== FString 读取 (UE4 Android: UTF-16LE) ===========
function readFString(addr) {
	var dataPtr = safePtr(addr);
	var num = safeS32(addr.add(8));
	if (dataPtr.isNull() || num <= 0 || num > 256) return "";
	try { return dataPtr.readUtf16String(); } catch (_) { return ""; }
}

// ===================== 初始化 ========================================
function initGlobals() {
	var mod = Process.findModuleByName(CONFIG.moduleName);
	if (!mod) {
		send({ type: "error", msg: "Module not found: " + CONFIG.moduleName });
		return false;
	}
	gBase = mod.base;
	gModSize = mod.size;

	gNamesArray = safePtr(gBase.add(CONFIG.GNames));
	if (gNamesArray.isNull()) {
		send({ type: "error", msg: "GNames is NULL" });
		return false;
	}
	gNumNames = safeS32(gNamesArray.add(CONFIG.NumElementsOff));
	send({ type: "info", msg: "Base: " + gBase + " Names: " + gNumNames });

	// 验证 entry[0] == "None"
	var c0 = safePtr(gNamesArray);
	if (!c0.isNull()) {
		var e0 = safePtr(c0);
		if (!e0.isNull()) {
			try {
				var n = e0.add(CONFIG.NameEntryNameOff).readCString();
				send({ type: "info", msg: "Entry[0] = '" + n + "'" + (n === "None" ? " OK" : " BAD") });
			} catch (_) {}
		}
	}

	return true;
}

// ===================== 读取对局状态 ==================================
// 使用 World 名称判断: 大厅 = Editor_login/UImap, 对局 = 其他地图
function getMatchState() {
	var worldPtr = safePtr(gBase.add(CONFIG.GWorld));
	if (worldPtr.isNull()) return { state: "NO_WORLD", inMatch: false, gameStatePtr: ptr(0), worldName: "" };
	var worldName = readObjName(worldPtr);
	var gsPtr = safePtr(worldPtr.add(CONFIG.UWorld_GameStateOff));
	var matchState = "Unknown";
	if (!gsPtr.isNull()) matchState = readFName(gsPtr.add(CONFIG.GameState_MatchStateOff));
	// 判断是否在对局: 排除大厅/UI 地图
	var inMatch = worldName.indexOf("Editor_login") < 0
		&& worldName.indexOf("UImap") < 0
		&& worldName.indexOf("Lobby") < 0
		&& worldName !== "None"
		&& worldName.indexOf("invalid") < 0
		&& !gsPtr.isNull();
	return { state: matchState, inMatch: inMatch, gameStatePtr: gsPtr, worldName: worldName };
}

// ===================== 获取 Actor 精确位置 ============================
// 链路: Actor -> RootComponent(+0x268) -> ComponentToWorld.Translation(+0x200)
function getActorLocation(actorPtr) {
	if (actorPtr.isNull()) return null;
	var rootComp = safePtr(actorPtr.add(CONFIG.Actor_RootComponentOff));
	if (rootComp.isNull()) return null;
	var off = CONFIG.SceneComp_TranslationOff;
	var x = safeFloat(rootComp.add(off));
	var y = safeFloat(rootComp.add(off + 4));
	var z = safeFloat(rootComp.add(off + 8));
	if (x === 0 && y === 0 && z === 0) return null;
	if (Math.abs(x) > 1e8 || Math.abs(y) > 1e8) return null;
	return { x: x, y: y, z: z };
}

// ===================== 检查类继承链 =================================
function isSubclassOf(classPtr, targetName) {
	var cur = classPtr;
	var depth = 0;
	while (!cur.isNull() && depth < 20) {
		var name = readObjName(cur);
		if (name === targetName) return true;
		cur = safePtr(cur.add(CONFIG.UStruct_SuperOff));
		depth++;
	}
	return false;
}

// ===================== EObserverType 检测 =============================
var EObserverTypeNames = [
	"None",           // 0 — 普通玩家
	"InSpectating",   // 1 — 死亡后观战
	"GlobalObserver", // 2 — 全局观战
	"FriendObserver", // 3 — 好友观战
	"Spectator",      // 4 — 观众
];

function getLocalPlayerController() {
	var worldPtr = safePtr(gBase.add(CONFIG.GWorld));
	if (worldPtr.isNull()) return ptr(0);
	var gsPtr = safePtr(worldPtr.add(CONFIG.UWorld_GameStateOff));
	if (gsPtr.isNull()) return ptr(0);
	var arrayData = safePtr(gsPtr.add(CONFIG.GameStateBase_PlayerArrayOff));
	var arrayNum = safeS32(gsPtr.add(CONFIG.GameStateBase_PlayerArrayOff + 8));
	if (arrayData.isNull() || arrayNum <= 0) return ptr(0);
	var psPtr = safePtr(arrayData); // PlayerArray[0] = 本地玩家 PlayerState
	if (psPtr.isNull()) return ptr(0);
	return safePtr(psPtr.add(0x98)); // AActor::Owner = PlayerController
}

function detectObserverType() {
	var pc = getLocalPlayerController();
	if (pc.isNull()) {
		send({ type: "info", msg: "[ObserverType] 无法获取本地 PlayerController" });
		return;
	}
	var bIsObserver = safeU8(pc.add(CONFIG.PC_bIsObserverOff)) !== 0;
	var bInBattle = safeU8(pc.add(CONFIG.PC_bIsObserverInBattleOff)) !== 0;
	var bIsHost = safeU8(pc.add(CONFIG.PC_bIsObserverHostOff)) !== 0;

	var obsType = 0; // None
	if (bIsObserver) {
		if (bIsHost) obsType = 2;       // GlobalObserver
		else if (bInBattle) obsType = 1; // InSpectating
		else obsType = 4;                // Spectator
	}
	var typeName = EObserverTypeNames[obsType] || "Unknown";
	var detail = "bIsObserver=" + bIsObserver + " bInBattle=" + bInBattle + " bIsHost=" + bIsHost;
	var msg = "[ObserverType] 当前以 EObserverType_" + typeName + " (" + obsType + ") 进入对局 [" + detail + "]";
	send({ type: "info", msg: msg });
	writeLog(msg);
}

// 强制设置观战类型
// obsType: 0=None, 1=InSpectating, 2=GlobalObserver, 3=FriendObserver, 4=Spectator
function setObserverType(obsType) {
	var pc = getLocalPlayerController();
	if (pc.isNull()) {
		send({ type: "error", msg: "[SetObserver] 无法获取 PlayerController" });
		return false;
	}
	switch (obsType) {
		case 0: // None — 普通玩家
			writeMemory(pc.add(CONFIG.PC_bIsObserverOff), 1, 0);
			writeMemory(pc.add(CONFIG.PC_bIsObserverInBattleOff), 1, 0);
			writeMemory(pc.add(CONFIG.PC_bIsObserverHostOff), 1, 0);
			break;
		case 1: // InSpectating — 死亡后观战
			writeMemory(pc.add(CONFIG.PC_bIsObserverOff), 1, 1);
			writeMemory(pc.add(CONFIG.PC_bIsObserverInBattleOff), 1, 1);
			writeMemory(pc.add(CONFIG.PC_bIsObserverHostOff), 1, 0);
			break;
		case 2: // GlobalObserver — 全局观战
			writeMemory(pc.add(CONFIG.PC_bIsObserverOff), 1, 1);
			writeMemory(pc.add(CONFIG.PC_bIsObserverInBattleOff), 1, 0);
			writeMemory(pc.add(CONFIG.PC_bIsObserverHostOff), 1, 1);
			break;
		case 3: // FriendObserver — 好友观战
			writeMemory(pc.add(CONFIG.PC_bIsObserverOff), 1, 1);
			writeMemory(pc.add(CONFIG.PC_bIsObserverInBattleOff), 1, 0);
			writeMemory(pc.add(CONFIG.PC_bIsObserverHostOff), 1, 0);
			break;
		case 4: // Spectator — 观众
			writeMemory(pc.add(CONFIG.PC_bIsObserverOff), 1, 1);
			writeMemory(pc.add(CONFIG.PC_bIsObserverInBattleOff), 1, 0);
			writeMemory(pc.add(CONFIG.PC_bIsObserverHostOff), 1, 0);
			break;
		default:
			send({ type: "error", msg: "[SetObserver] 无效类型: " + obsType });
			return false;
	}
	var typeName = EObserverTypeNames[obsType] || "Unknown";
	send({ type: "info", msg: "[SetObserver] 已设置为 EObserverType_" + typeName + " (" + obsType + ")" });
	writeLog("[SetObserver] -> EObserverType_" + typeName + " (" + obsType + ")");
	return true;
}

// ===================== RPC 请求全部玩家信息 ===========================
// 通过 UFunction 调用 RPC_Server_RequestAllPlayerInfo 请求服务端发送全部玩家数据
// 服务端回传通过 RPC_Client_SyncAllPlayerInfo (Hook 捕获)

function findUFunctionByName(classPtr, funcName) {
	var child = safePtr(classPtr.add(0x38)); // UStruct::Children
	var depth = 0;
	while (!child.isNull() && depth < 2000) {
		var name = readObjName(child);
		if (name === funcName) return child;
		child = safePtr(child.add(0x28)); // UField::Next
		depth++;
	}
	// 搜索父类
	var superClass = safePtr(classPtr.add(CONFIG.UStruct_SuperOff));
	if (!superClass.isNull()) return findUFunctionByName(superClass, funcName);
	return ptr(0);
}

function callRequestAllPlayerInfo() {
	var pc = getLocalPlayerController();
	if (pc.isNull()) {
		send({ type: "error", msg: "[RPC] 无法获取 PlayerController" });
		return false;
	}

	var classPtr = safePtr(pc.add(CONFIG.UObj_ClassOff));
	if (classPtr.isNull()) {
		send({ type: "error", msg: "[RPC] PlayerController class is NULL" });
		return false;
	}

	var uFunc = findUFunctionByName(classPtr, "RPC_Server_RequestAllPlayerInfo");
	if (uFunc.isNull()) {
		send({ type: "error", msg: "[RPC] UFunction 'RPC_Server_RequestAllPlayerInfo' not found" });
		return false;
	}

	// 获取 UFunction 的 native 函数指针 (+0xB0)
	var nativeFunc = safePtr(uFunc.add(0xB0));
	send({ type: "info", msg: "[RPC] Found UFunction at " + uFunc + " native=" + nativeFunc });

	// 调用: 在客户端执行时走 RPC 发送路径 (sub_A5653FC "R")
	var callRPC = new NativeFunction(nativeFunc, 'void', ['pointer', 'pointer']);
	try {
		callRPC(pc, uFunc);
		send({ type: "info", msg: "[RPC] RPC_Server_RequestAllPlayerInfo 已发送!" });
		return true;
	} catch (e) {
		send({ type: "error", msg: "[RPC] 调用失败: " + e.message });
		return false;
	}
}

// Hook RPC_Client_SyncAllPlayerInfo 接收服务端回传的全部玩家数据
var syncHooked = false;
function hookSyncAllPlayerInfo() {
	if (syncHooked) return;
	var addr = gBase.add(0x6E898E0); // sub_6E898E0 = RPC_Client_SyncAllPlayerInfo impl
	Interceptor.attach(addr, {
		onEnter: function (args) {
			var pcPtr = args[0];
			var dataPtr = args[1];
			send({ type: "info", msg: "[RPC-Recv] RPC_Client_SyncAllPlayerInfo 被调用! PC=" + pcPtr });
			// 读取 TArray 数据: dataPtr 是 TArray<FAllPlayerInfo> 引用
			if (!dataPtr.isNull()) {
				var arrData = safePtr(dataPtr);
				var arrNum = safeS32(dataPtr.add(8));
				send({ type: "info", msg: "[RPC-Recv] InfoDataList: data=" + arrData + " num=" + arrNum });
				if (arrNum > 0) {
					send({ type: "info", msg: "[RPC-Recv] ★★★ 收到 " + arrNum + " 个玩家信息! ★★★" });
				}
			}
		}
	});
	syncHooked = true;
	send({ type: "info", msg: "[RPC] Hook RPC_Client_SyncAllPlayerInfo 已安装" });
}

// ===================== 修改网络可见范围 ==============================
// 将角色的 NetCullDistanceSquared 设为极大值, 使服务器复制全地图玩家
var MAX_CULL_DIST_SQ = 1.0e18; // ~316km 范围, 覆盖任何地图

function patchActorNetCull(actorPtr) {
	writeFloat(actorPtr.add(CONFIG.Actor_NetCullDistSqOff), MAX_CULL_DIST_SQ);
	// STExtraBaseCharacter.CurrentNetCullDistanceSquared
	writeFloat(actorPtr.add(CONFIG.Char_CurrentNetCullDistSqOff), MAX_CULL_DIST_SQ);
}

// ===================== GUObjectArray 扫描所有 Character ===============
function scanCharacters() {
	var arrayBase = gBase.add(CONFIG.GUObjectArray);
	var numChunks = safeS32(arrayBase.add(CONFIG.ObjNumChunksOff));
	var totalNum = safeS32(arrayBase.add(CONFIG.ObjTotalNumOff));
	if (numChunks <= 0 || totalNum <= 0) return 0;

	var globalIdx = 0;
	var newCharsFound = 0;

	for (var ci = 0; ci < numChunks; ci++) {
		var chunkBase = safePtr(arrayBase.add(CONFIG.ObjChunkPtrsOff + ci * 8));
		var chunkCount = safeS32(arrayBase.add(CONFIG.ObjChunkCountsOff + ci * 4));
		if (chunkBase.isNull() || chunkCount <= 0) {
			globalIdx += chunkCount > 0 ? chunkCount : 0;
			continue;
		}

		var remaining = totalNum - globalIdx;
		var readCount = Math.min(chunkCount, remaining);
		if (readCount <= 0) break;

		// 分批读取, 每批最多 4096 个以避免内存读取失败
		var BATCH = 4096;
		for (var bStart = 0; bStart < readCount; bStart += BATCH) {
			var bEnd = Math.min(bStart + BATCH, readCount);
			var bCount = bEnd - bStart;
			var buf;
			try {
				buf = chunkBase.add(bStart * CONFIG.FUObjectItemSize).readByteArray(bCount * CONFIG.FUObjectItemSize);
			} catch (_) {
				continue;
			}
			var view = new DataView(buf);

			for (var wi = 0; wi < bCount; wi++) {
				var itemOff = wi * CONFIG.FUObjectItemSize;
				var lo = view.getUint32(itemOff, true);
				var hi = view.getUint32(itemOff + 4, true);
				if (lo === 0 && hi === 0) continue;
				var objPtr = ptr(hi).shl(32).or(lo);
				if (objPtr.isNull()) continue;

				var classPtr = safePtr(objPtr.add(CONFIG.UObj_ClassOff));
				if (classPtr.isNull()) continue;

				var classKey = classPtr.toString();
				if (classKey in characterClassSet) {
					if (!characterClassSet[classKey]) continue;
				} else {
					var isChar = isSubclassOf(classPtr, "STExtraBaseCharacter");
					characterClassSet[classKey] = isChar;
					if (!isChar) continue;
				}

				var playerKey = safeU32(objPtr.add(CONFIG.Char_PlayerKeyOff));
				if (playerKey === 0) continue;

				var teamID = safeS32(objPtr.add(CONFIG.Char_TeamIDOff));
				var health = safeFloat(objPtr.add(CONFIG.Char_HealthOff));
				var healthMax = safeFloat(objPtr.add(CONFIG.Char_HealthMaxOff));
				var bDead = (safeU8(objPtr.add(CONFIG.Char_bDeadOff)) & 1) !== 0;
				var playerName = readFString(objPtr.add(CONFIG.Char_PlayerNameOff));

				var loc = getActorLocation(objPtr);
				var posX = loc ? loc.x : 0;
				var posY = loc ? loc.y : 0;
				var posZ = loc ? loc.z : 0;

				if (healthMax <= 0) continue; // 无效对象

				// 修改每个 Character 的网络可见范围为全地图
				patchActorNetCull(objPtr);

				playerList.upsert(playerKey, {
					teamID: teamID, playerName: playerName, isAI: false,
					liveState: bDead ? 1 : 0,
					health: health, healthMax: healthMax,
					kills: 0, posX: posX, posY: posY, posZ: posZ,
				});
				newCharsFound++;
			}
		}
		globalIdx += chunkCount;
		if (globalIdx >= totalNum) break;
	}
	return newCharsFound;
}

// ===================== 遍历 PlayerArray, 更新双向链表 =================
function updatePlayerList(gameStatePtr) {
	var arrayData = safePtr(gameStatePtr.add(CONFIG.GameStateBase_PlayerArrayOff));
	var arrayNum = safeS32(gameStatePtr.add(CONFIG.GameStateBase_PlayerArrayOff + 8));

	// 读取 GameState 的全局玩家计数
	var totalPlayerNum = safeS32(gameStatePtr.add(CONFIG.UAEGameState_TotalPlayerNumOff));
	var playerNum = safeS32(gameStatePtr.add(CONFIG.UAEGameState_PlayerNumOff));
	var aliveNum = safeS32(gameStatePtr.add(0x129C));    // AlivePlayerNum
	var aliveRealNum = safeS32(gameStatePtr.add(0x12A0)); // AliveRealPlayerNum

	if (arrayNum !== lastReportedArrayNum || totalPlayerNum !== lastReportedTotal) {
		send({ type: "info", msg: "[PlayerCount] PlayerArray=" + arrayNum
			+ " TotalPlayerNum=" + totalPlayerNum
			+ " PlayerNum=" + playerNum
			+ " AlivePlayerNum=" + aliveNum
			+ " AliveRealPlayerNum=" + aliveRealNum });
		lastReportedArrayNum = arrayNum;
		lastReportedTotal = totalPlayerNum;
	}

	if (arrayData.isNull() || arrayNum <= 0 || arrayNum > 500) return 0;

	var seenKeys = {};
	var updated = 0;

	for (var i = 0; i < arrayNum; i++) {
		var psPtr = safePtr(arrayData.add(i * 8));
		if (psPtr.isNull()) continue;

		var playerKey = safeU32(psPtr.add(CONFIG.PS_PlayerKeyOff));
		if (playerKey === 0) continue;

		var teamID = safeS32(psPtr.add(CONFIG.PS_TeamIDOff));
		var isAI = safeU8(psPtr.add(CONFIG.PS_bAIPlayerOff)) !== 0;
		var liveState = safeU8(psPtr.add(CONFIG.PS_LiveStateOff));
		var health = safeFloat(psPtr.add(CONFIG.PS_PlayerHealthOff));
		var healthMax = safeFloat(psPtr.add(CONFIG.PS_PlayerHealthMaxOff));
		var kills = safeS32(psPtr.add(CONFIG.PS_KillsOff));
		var playerName = readFString(psPtr.add(CONFIG.PS_PlayerNameOff));

		// 优先通过 CharacterOwner -> RootComponent 获取精确位置
		var posX = 0, posY = 0, posZ = 0;
		var charOwner = safePtr(psPtr.add(CONFIG.PS_CharacterOwnerOff));
		if (!charOwner.isNull()) {
			var loc = getActorLocation(charOwner);
			if (loc) { posX = loc.x; posY = loc.y; posZ = loc.z; }
			patchActorNetCull(charOwner);
		}
		// 退回读 SelfLocAndRot
		if (posX === 0 && posY === 0 && posZ === 0) {
			posX = safeFloat(psPtr.add(CONFIG.PS_SelfLocAndRotOff));
			posY = safeFloat(psPtr.add(CONFIG.PS_SelfLocAndRotOff + 4));
			posZ = safeFloat(psPtr.add(CONFIG.PS_SelfLocAndRotOff + 8));
		}

		playerList.upsert(playerKey, {
			teamID: teamID, playerName: playerName, isAI: isAI,
			liveState: liveState, health: health, healthMax: healthMax,
			kills: kills, posX: posX, posY: posY, posZ: posZ,
		});
		seenKeys[playerKey] = true;
		updated++;

		// 记录自己的 TeamID
		if (i === 0 && teamID > 0) myTeamID = teamID;
	}

	// 移除已退出的玩家
	var allNodes = playerList.toArray();
	for (var j = 0; j < allNodes.length; j++) {
		if (!seenKeys[allNodes[j].playerKey]) playerList.remove(allNodes[j].playerKey);
	}

	// 扫描 GUObjectArray 获取附近的所有 Character (包括敌人)
	try { scanCharacters(); } catch (_) {}

	return updated;
}

// ===================== 玩家数据轮询 ==================================
function pollPlayers() {
	try {
		gNumNames = safeS32(gNamesArray.add(CONFIG.NumElementsOff));
		var ms = getMatchState();
		if (!ms.inMatch) return;

		// 每次轮询都尝试请求全部玩家数据
		//callRequestAllPlayerInfo();

		var count = updatePlayerList(ms.gameStatePtr);
		if (count <= 0) return;

		var alive = [], dead = 0;
		var aliveTeam = [], aliveEnemy = [];
		var cur = playerList.head;
		while (cur) {
			if (cur.liveState === 0 && cur.health > 0) {
				alive.push(cur);
				if (myTeamID > 0 && cur.teamID === myTeamID) aliveTeam.push(cur);
				else aliveEnemy.push(cur);
			} else {
				dead++;
			}
			cur = cur.next;
		}

		var lines = [];
		lines.push("=== 玩家坐标 [" + alive.length + " alive (" + aliveTeam.length + " team + " + aliveEnemy.length + " enemy) / " + playerList.size + " total] ===");
		// 先显示敌人
		for (var i = 0; i < aliveEnemy.length && i < 40; i++) {
			var p = aliveEnemy[i];
			var hp = p.health.toFixed(0) + "/" + p.healthMax.toFixed(0);
			var pos = "(" + p.posX.toFixed(0) + ", " + p.posY.toFixed(0) + ", " + p.posZ.toFixed(0) + ")";
			lines.push(" ★ T" + p.teamID + " " + hp + "HP " + pos + " " + p.playerName);
		}
		// 再显示队友
		for (var i = 0; i < aliveTeam.length; i++) {
			var p = aliveTeam[i];
			var hp = p.health.toFixed(0) + "/" + p.healthMax.toFixed(0);
			var pos = "(" + p.posX.toFixed(0) + ", " + p.posY.toFixed(0) + ", " + p.posZ.toFixed(0) + ")";
			lines.push(" ○ T" + p.teamID + " " + hp + "HP " + pos + " " + p.playerName);
		}

		var output = lines.join("\n");
		send({ type: "players", msg: output, data: {
			aliveCount: alive.length, deadCount: dead, totalCount: playerList.size,
		}});

		// 写入文件日志
		writeLog("[" + new Date().toISOString() + "] " + lines[0]);
		for (var k = 1; k < lines.length; k++) writeLog(lines[k]);
		writeLog("");
	} catch (e) {
		send({ type: "error", msg: "Player poll error: " + e.message });
	}
}

// ===================== 对局状态轮询 ==================================
function pollMatchState() {
	try {
		gNumNames = safeS32(gNamesArray.add(CONFIG.NumElementsOff));
		var ms = getMatchState();
		var stateChanged = (ms.state !== lastMatchState);

		if (stateChanged) {
			var msg = "[状态变化] " + lastMatchState + " -> " + ms.state + " World=" + ms.worldName;
			var wasInMatch = isInMatch;
			isInMatch = ms.inMatch;

			if (isInMatch && !wasInMatch) {
				msg += " ★ 进入对局!";
				playerList.clear();
				characterClassSet = {};
				myTeamID = -1;
				lastReportedArrayNum = -1;
				lastReportedTotal = -1;
				openLog();
				writeLog(">>> " + msg);
				writeLog("World: " + ms.worldName);
				writeLog("");
				detectObserverType();
				//setObserverType(2); // 强制切换为 GlobalObserver
				//detectObserverType(); // 验证修改结果
				
				//callRequestAllPlayerInfo(); // 发送 RPC 请求全部玩家数据
				if (!playerTimer) {
					playerTimer = setInterval(pollPlayers, CONFIG.PlayerPollInterval);
					send({ type: "info", msg: "玩家坐标采集已启动 (每" + CONFIG.PlayerPollInterval + "ms)" });
				}
			} else if (!isInMatch && wasInMatch) {
				msg += " ★ 离开对局!";
				writeLog(">>> " + msg);
				if (playerTimer) { clearInterval(playerTimer); playerTimer = null; }
				send({ type: "info", msg: "玩家坐标采集已停止, 共追踪 " + playerList.size + " 名玩家" });
				closeLog();
				playerList.clear();
			}
			send({ type: "state_change", msg: msg, data: { matchState: ms.state, worldName: ms.worldName }});
			lastMatchState = ms.state;
		}

		var status = isInMatch ? "★ 对局中" : "○ 非对局";
		var extra = isInMatch ? (" Players=" + playerList.size) : "";
		send({ type: "heartbeat", msg: "[" + status + "] State=" + ms.state + " World=" + ms.worldName + extra });
	} catch (e) {
		send({ type: "error", msg: "Monitor error: " + e.message });
	}
}

function startMonitor() {
	if (isMonitoring) { send({ type: "info", msg: "Monitor already running" }); return; }
	if (!initGlobals()) return;

	isMonitoring = true;
	lastMatchState = "";
	isInMatch = false;
	playerList.clear();

	// Patch: MOV W0, WZR -> MOV W0, #2 at libUE4+0x9A49BF4
	//writeMemory(gBase.add(0x9A49BF4), 4, [0x40, 0x00, 0x80, 0x52]);
	//hookSyncAllPlayerInfo(); // Hook 接收回调
	send({ type: "info", msg: "=== 对局监控+玩家采集已启动 (状态" + (CONFIG.PollInterval / 1000) + "s, 玩家" + CONFIG.PlayerPollInterval + "ms) ===" });

	pollMatchState();
	if (isInMatch && !playerTimer) {
		playerTimer = setInterval(pollPlayers, CONFIG.PlayerPollInterval);
		send({ type: "info", msg: "检测到已在对局中,玩家坐标采集已启动" });
	}
	monitorTimer = setInterval(pollMatchState, CONFIG.PollInterval);
}

function stopMonitor() {
	if (monitorTimer) { clearInterval(monitorTimer); monitorTimer = null; }
	if (playerTimer) { clearInterval(playerTimer); playerTimer = null; }
	closeLog();
	isMonitoring = false;
	isInMatch = false;
	send({ type: "info", msg: "=== 监控已停止 ===" });
}

// ===================== 消息处理 ======================================
recv("start", function (_) {
	send({ type: "info", msg: "Starting match monitor + player tracker..." });
	startMonitor();
});

recv("stop", function (_) {
	stopMonitor();
});

send({ type: "ready", msg: "Match monitor + player tracker loaded. Send 'start' to begin." });
