"use strict";

// =====================================================================
//  UE4.18 对局状态实时监控 — Frida Script
//  Target: com.tencent.tmgp.pubgmhd (ARM64 Android)
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

	// UWorld 成员偏移 (dump.cs 验证)
	UWorld_GameStateOff: 0xab8,     // UObject* GameState
	UWorld_AuthGameModeOff: 0xab0,  // UObject* AuthorityGameMode

	// GameState (继承链: GameStateBase -> GameState)
	GameState_MatchStateOff: 0x620, // FName MatchState

	// GameStateBase
	GameStateBase_bHasBegunPlayOff: 0x5f0,  // bool bReplicatedHasBegunPlay
	GameStateBase_WorldTimeOff: 0x5f4,      // float ReplicatedWorldTimeSeconds
	GameStateBase_PlayerArrayOff: 0x5e0,    // TArray PlayerArray

	// UAEGameState
	UAEGameState_PlayerNumOff: 0xd34,     // int32 PlayerNum (STExtraGameStateBase)
	UAEGameState_TotalPlayerNumOff: 0xd30, // int32 TotalPlayerNum
	UAEGameState_GameTypeOff: 0xd84,       // int32 GameType

	// UObjectBase
	UObj_ClassOff: 0x10,
	UObj_NameIdxOff: 0x18,
	UObj_NameNumOff: 0x1c,
	UObj_OuterOff: 0x20,

	// 轮询间隔 (毫秒)
	PollInterval: 2000,
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

// ===================== 安全读取 ======================================
function safePtr(addr) {
	try { return addr.readPointer(); } catch (_) { return ptr(0); }
}
function safeS32(addr) {
	try { return addr.readS32(); } catch (_) { return 0; }
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
function getMatchInfo() {
	var info = {
		worldPtr: ptr(0),
		gameStatePtr: ptr(0),
		matchState: "N/A",
		isInMatch: false,
		hasBegunPlay: false,
		worldTime: 0.0,
		playerCount: 0,
		totalPlayers: 0,
		gameType: 0,
		worldName: "",
		gameStateName: "",
	};

	// 1. 读取 GWorld -> UWorld*
	var worldPtr = safePtr(gBase.add(CONFIG.GWorld));
	if (worldPtr.isNull()) {
		info.matchState = "NO_WORLD";
		return info;
	}
	info.worldPtr = worldPtr;
	info.worldName = readObjName(worldPtr);

	// 2. 读取 UWorld -> GameState
	var gameStatePtr = safePtr(worldPtr.add(CONFIG.UWorld_GameStateOff));
	if (gameStatePtr.isNull()) {
		info.matchState = "NO_GAMESTATE";
		return info;
	}
	info.gameStatePtr = gameStatePtr;
	info.gameStateName = readClassName(gameStatePtr);

	// 3. 读取 GameState.MatchState (FName @ +0x620)
	var matchState = readFName(gameStatePtr.add(CONFIG.GameState_MatchStateOff));
	info.matchState = matchState;
	info.isInMatch = (matchState === "InProgress");

	// 4. 读取辅助信息
	info.hasBegunPlay = safeU8(gameStatePtr.add(CONFIG.GameStateBase_bHasBegunPlayOff)) !== 0;
	info.worldTime = safeFloat(gameStatePtr.add(CONFIG.GameStateBase_WorldTimeOff));

	// 5. 读取 STExtraGameStateBase 扩展信息 (如果是该类型)
	try {
		info.totalPlayers = safeS32(gameStatePtr.add(CONFIG.UAEGameState_TotalPlayerNumOff));
		info.playerCount = safeS32(gameStatePtr.add(CONFIG.UAEGameState_PlayerNumOff));
		info.gameType = safeS32(gameStatePtr.add(CONFIG.UAEGameState_GameTypeOff));
	} catch (_) {}

	return info;
}

// ===================== 监控循环 ======================================
function pollMatchState() {
	try {
		// 刷新 GNumNames (可能有新名字注册)
		gNumNames = safeS32(gNamesArray.add(CONFIG.NumElementsOff));

		var info = getMatchInfo();
		var stateChanged = (info.matchState !== lastMatchState);

		if (stateChanged) {
			var msg = "[状态变化] " + lastMatchState + " -> " + info.matchState;
			if (info.isInMatch) {
				msg += " ★ 进入对局!";
			} else if (lastMatchState === "InProgress") {
				msg += " ★ 离开对局!";
			}
			send({ type: "state_change", msg: msg, data: {
				matchState: info.matchState,
				isInMatch: info.isInMatch,
				worldName: info.worldName,
				gameStateName: info.gameStateName,
				totalPlayers: info.totalPlayers,
				playerCount: info.playerCount,
				gameType: info.gameType,
			}});
			lastMatchState = info.matchState;
		}

		// 常规心跳日志（每次都打印）
		var status = info.isInMatch ? "★ 对局中" : "○ 非对局";
		var log = "[" + status + "] "
			+ "State=" + info.matchState
			+ " World=" + info.worldName
			+ " Time=" + info.worldTime.toFixed(1) + "s"
			+ " Players=" + info.playerCount + "/" + info.totalPlayers
			+ " GameType=" + info.gameType
			+ " BegunPlay=" + info.hasBegunPlay;
		send({ type: "heartbeat", msg: log });

	} catch (e) {
		send({ type: "error", msg: "Monitor error: " + e.message });
	}
}

function startMonitor() {
	if (isMonitoring) {
		send({ type: "info", msg: "Monitor already running" });
		return;
	}
	if (!initGlobals()) return;

	isMonitoring = true;
	lastMatchState = "";
	send({ type: "info", msg: "=== 对局状态监控已启动 (每" + (CONFIG.PollInterval / 1000) + "秒) ===" });

	// 立即执行一次
	pollMatchState();

	// 定时轮询
	monitorTimer = setInterval(pollMatchState, CONFIG.PollInterval);
}

function stopMonitor() {
	if (monitorTimer) {
		clearInterval(monitorTimer);
		monitorTimer = null;
	}
	isMonitoring = false;
	send({ type: "info", msg: "=== 对局状态监控已停止 ===" });
}

// ===================== 消息处理 ======================================
recv("start", function (_) {
	send({ type: "info", msg: "Starting match monitor..." });
	startMonitor();
});

recv("stop", function (_) {
	stopMonitor();
});

send({ type: "ready", msg: "Match monitor script loaded. Send 'start' to begin." });
