package com.umbra.scanner

import com.umbra.scanner.i18n.AppLanguage
import com.umbra.scanner.i18n.EnglishStrings
import com.umbra.scanner.i18n.PersianStrings
import org.junit.Test

/**
 * Guards the bilingual system: every field of AppStrings must be populated in
 * BOTH languages — a missing Persian translation would render as a blank
 * label in the UI, so parity is enforced at the unit level. (Deliberately
 * reflection-free: no kotlin-reflect dependency needed.)
 */
class StringsTest {

    /** (label, en, fa) triples for every string field of AppStrings. */
    private val fields: List<Triple<String, String, String>> = listOf(
        Triple("brandTagline", EnglishStrings.brandTagline, PersianStrings.brandTagline),
        Triple("live", EnglishStrings.live, PersianStrings.live),
        Triple("done", EnglishStrings.done, PersianStrings.done),
        Triple("idle", EnglishStrings.idle, PersianStrings.idle),
        Triple("navScan", EnglishStrings.navScan, PersianStrings.navScan),
        Triple("navResults", EnglishStrings.navResults, PersianStrings.navResults),
        Triple("navVless", EnglishStrings.navVless, PersianStrings.navVless),
        Triple("navSystem", EnglishStrings.navSystem, PersianStrings.navSystem),
        Triple("tested", EnglishStrings.tested, PersianStrings.tested),
        Triple("alive", EnglishStrings.alive, PersianStrings.alive),
        Triple("rate", EnglishStrings.rate, PersianStrings.rate),
        Triple("active", EnglishStrings.active, PersianStrings.active),
        Triple("elapsed", EnglishStrings.elapsed, PersianStrings.elapsed),
        Triple("eta", EnglishStrings.eta, PersianStrings.eta),
        Triple("liveTopEndpoints", EnglishStrings.liveTopEndpoints, PersianStrings.liveTopEndpoints),
        Triple("warmingUp", EnglishStrings.warmingUp, PersianStrings.warmingUp),
        Triple("stopScan", EnglishStrings.stopScan, PersianStrings.stopScan),
        Triple("scanComplete", EnglishStrings.scanComplete, PersianStrings.scanComplete),
        Triple("scanStopped", EnglishStrings.scanStopped, PersianStrings.scanStopped),
        Triple("time", EnglishStrings.time, PersianStrings.time),
        Triple("bestEndpoint", EnglishStrings.bestEndpoint, PersianStrings.bestEndpoint),
        Triple("lat", EnglishStrings.lat, PersianStrings.lat),
        Triple("jit", EnglishStrings.jit, PersianStrings.jit),
        Triple("loss", EnglishStrings.loss, PersianStrings.loss),
        Triple("speed", EnglishStrings.speed, PersianStrings.speed),
        Triple("viewResults", EnglishStrings.viewResults, PersianStrings.viewResults),
        Triple("configureNewScan", EnglishStrings.configureNewScan, PersianStrings.configureNewScan),
        Triple("mode", EnglishStrings.mode, PersianStrings.mode),
        Triple("taglineCfEdge", EnglishStrings.taglineCfEdge, PersianStrings.taglineCfEdge),
        Triple("taglineWarp", EnglishStrings.taglineWarp, PersianStrings.taglineWarp),
        Triple("taglineCustom", EnglishStrings.taglineCustom, PersianStrings.taglineCustom),
        Triple("flavor", EnglishStrings.flavor, PersianStrings.flavor),
        Triple("family", EnglishStrings.family, PersianStrings.family),
        Triple("cidrList", EnglishStrings.cidrList, PersianStrings.cidrList),
        Triple("addCfSet", EnglishStrings.addCfSet, PersianStrings.addCfSet),
        Triple("addWarpSet", EnglishStrings.addWarpSet, PersianStrings.addWarpSet),
        Triple("autoTune", EnglishStrings.autoTune, PersianStrings.autoTune),
        Triple("autoTuneHint", EnglishStrings.autoTuneHint, PersianStrings.autoTuneHint),
        Triple("calibrating", EnglishStrings.calibrating, PersianStrings.calibrating),
        Triple("pickBestSettings", EnglishStrings.pickBestSettings, PersianStrings.pickBestSettings),
        Triple("autoTuneReport", EnglishStrings.autoTuneReport, PersianStrings.autoTuneReport),
        Triple("dismiss", EnglishStrings.dismiss, PersianStrings.dismiss),
        Triple("port", EnglishStrings.port, PersianStrings.port),
        Triple("udpNoise", EnglishStrings.udpNoise, PersianStrings.udpNoise),
        Triple("udpNoiseHint", EnglishStrings.udpNoiseHint, PersianStrings.udpNoiseHint),
        Triple("warpSingleHint", EnglishStrings.warpSingleHint, PersianStrings.warpSingleHint),
        Triple("engine", EnglishStrings.engine, PersianStrings.engine),
        Triple("advancedEngine", EnglishStrings.advancedEngine, PersianStrings.advancedEngine),
        Triple("hideAdvanced", EnglishStrings.hideAdvanced, PersianStrings.hideAdvanced),
        Triple("samplesPerPrefix", EnglishStrings.samplesPerPrefix, PersianStrings.samplesPerPrefix),
        Triple("wgRetries", EnglishStrings.wgRetries, PersianStrings.wgRetries),
        Triple("tcpAttempts", EnglishStrings.tcpAttempts, PersianStrings.tcpAttempts),
        Triple("timeout", EnglishStrings.timeout, PersianStrings.timeout),
        Triple("concurrency", EnglishStrings.concurrency, PersianStrings.concurrency),
        Triple("tlsVerifyBudget", EnglishStrings.tlsVerifyBudget, PersianStrings.tlsVerifyBudget),
        Triple("speedTopN", EnglishStrings.speedTopN, PersianStrings.speedTopN),
        Triple("speedLanes", EnglishStrings.speedLanes, PersianStrings.speedLanes),
        Triple("tlsVerify", EnglishStrings.tlsVerify, PersianStrings.tlsVerify),
        Triple("tlsVerifyHint", EnglishStrings.tlsVerifyHint, PersianStrings.tlsVerifyHint),
        Triple("speedTest", EnglishStrings.speedTest, PersianStrings.speedTest),
        Triple("speedTestHintWarp", EnglishStrings.speedTestHintWarp, PersianStrings.speedTestHintWarp),
        Triple("speedTestHintEdge", EnglishStrings.speedTestHintEdge, PersianStrings.speedTestHintEdge),
        Triple("downloadSize", EnglishStrings.downloadSize, PersianStrings.downloadSize),
        Triple("initiateDeepScan", EnglishStrings.initiateDeepScan, PersianStrings.initiateDeepScan),
        Triple("dnsNeverUsed", EnglishStrings.dnsNeverUsed, PersianStrings.dnsNeverUsed),
        Triple("scanResults", EnglishStrings.scanResults, PersianStrings.scanResults),
        Triple("noScanDataYet", EnglishStrings.noScanDataYet, PersianStrings.noScanDataYet),
        Triple("emptyResultsHint", EnglishStrings.emptyResultsHint, PersianStrings.emptyResultsHint),
        Triple("runAScan", EnglishStrings.runAScan, PersianStrings.runAScan),
        Triple("bestLat", EnglishStrings.bestLat, PersianStrings.bestLat),
        Triple("median", EnglishStrings.median, PersianStrings.median),
        Triple("topSpeed", EnglishStrings.topSpeed, PersianStrings.topSpeed),
        Triple("all", EnglishStrings.all, PersianStrings.all),
        Triple("tlsOk", EnglishStrings.tlsOk, PersianStrings.tlsOk),
        Triple("share", EnglishStrings.share, PersianStrings.share),
        Triple("warpProfile", EnglishStrings.warpProfile, PersianStrings.warpProfile),
        Triple("edgeProfile", EnglishStrings.edgeProfile, PersianStrings.edgeProfile),
        Triple("latency", EnglishStrings.latency, PersianStrings.latency),
        Triple("jitter", EnglishStrings.jitter, PersianStrings.jitter),
        Triple("wgHs", EnglishStrings.wgHs, PersianStrings.wgHs),
        Triple("inTunnelPing", EnglishStrings.inTunnelPing, PersianStrings.inTunnelPing),
        Triple("attempts", EnglishStrings.attempts, PersianStrings.attempts),
        Triple("http", EnglishStrings.http, PersianStrings.http),
        Triple("data", EnglishStrings.data, PersianStrings.data),
        Triple("score", EnglishStrings.score, PersianStrings.score),
        Triple("tlsTime", EnglishStrings.tlsTime, PersianStrings.tlsTime),
        Triple("warpValidatedNote", EnglishStrings.warpValidatedNote, PersianStrings.warpValidatedNote),
        Triple("copyIp", EnglishStrings.copyIp, PersianStrings.copyIp),
        Triple("copyIpPort", EnglishStrings.copyIpPort, PersianStrings.copyIpPort),
        Triple("copyWgEndpoint", EnglishStrings.copyWgEndpoint, PersianStrings.copyWgEndpoint),
        Triple("createVless", EnglishStrings.createVless, PersianStrings.createVless),
        Triple("shareEndpoint", EnglishStrings.shareEndpoint, PersianStrings.shareEndpoint),
        Triple("vlessForge", EnglishStrings.vlessForge, PersianStrings.vlessForge),
        Triple("vlessTagline", EnglishStrings.vlessTagline, PersianStrings.vlessTagline),
        Triple("identity", EnglishStrings.identity, PersianStrings.identity),
        Triple("uuidField", EnglishStrings.uuidField, PersianStrings.uuidField),
        Triple("hostPlaceholder", EnglishStrings.hostPlaceholder, PersianStrings.hostPlaceholder),
        Triple("portField", EnglishStrings.portField, PersianStrings.portField),
        Triple("wsPathField", EnglishStrings.wsPathField, PersianStrings.wsPathField),
        Triple("remarkField", EnglishStrings.remarkField, PersianStrings.remarkField),
        Triple("sniPlaceholder", EnglishStrings.sniPlaceholder, PersianStrings.sniPlaceholder),
        Triple("sniTestOnlyWarning", EnglishStrings.sniTestOnlyWarning, PersianStrings.sniTestOnlyWarning),
        Triple("generatedLink", EnglishStrings.generatedLink, PersianStrings.generatedLink),
        Triple("fillToForge", EnglishStrings.fillToForge, PersianStrings.fillToForge),
        Triple("copyLink", EnglishStrings.copyLink, PersianStrings.copyLink),
        Triple("shareLink", EnglishStrings.shareLink, PersianStrings.shareLink),
        Triple("qrHint", EnglishStrings.qrHint, PersianStrings.qrHint),
        Triple("vlessUsageNote", EnglishStrings.vlessUsageNote, PersianStrings.vlessUsageNote),
        Triple("system", EnglishStrings.system, PersianStrings.system),
        Triple("systemTagline", EnglishStrings.systemTagline, PersianStrings.systemTagline),
        Triple("signalPalette", EnglishStrings.signalPalette, PersianStrings.signalPalette),
        Triple("paletteHint", EnglishStrings.paletteHint, PersianStrings.paletteHint),
        Triple("language", EnglishStrings.language, PersianStrings.language),
        Triple("languageHint", EnglishStrings.languageHint, PersianStrings.languageHint),
        Triple("performance", EnglishStrings.performance, PersianStrings.performance),
        Triple("maxRefreshRate", EnglishStrings.maxRefreshRate, PersianStrings.maxRefreshRate),
        Triple("lightweightFx", EnglishStrings.lightweightFx, PersianStrings.lightweightFx),
        Triple("lightweightFxHint", EnglishStrings.lightweightFxHint, PersianStrings.lightweightFxHint),
        Triple("amoledVoid", EnglishStrings.amoledVoid, PersianStrings.amoledVoid),
        Triple("amoledVoidHint", EnglishStrings.amoledVoidHint, PersianStrings.amoledVoidHint),
        Triple("hapticSignals", EnglishStrings.hapticSignals, PersianStrings.hapticSignals),
        Triple("hapticSignalsHint", EnglishStrings.hapticSignalsHint, PersianStrings.hapticSignalsHint),
        Triple("updateChannel", EnglishStrings.updateChannel, PersianStrings.updateChannel),
        Triple("autoCheck", EnglishStrings.autoCheck, PersianStrings.autoCheck),
        Triple("autoCheckHint", EnglishStrings.autoCheckHint, PersianStrings.autoCheckHint),
        Triple("contactingGithub", EnglishStrings.contactingGithub, PersianStrings.contactingGithub),
        Triple("githubUnreachable", EnglishStrings.githubUnreachable, PersianStrings.githubUnreachable),
        Triple("updateIdle", EnglishStrings.updateIdle, PersianStrings.updateIdle),
        Triple("checkNow", EnglishStrings.checkNow, PersianStrings.checkNow),
        Triple("aboutUmbra", EnglishStrings.aboutUmbra, PersianStrings.aboutUmbra),
        Triple("version", EnglishStrings.version, PersianStrings.version),
        Triple("engineLabel", EnglishStrings.engineLabel, PersianStrings.engineLabel),
        Triple("engineValue", EnglishStrings.engineValue, PersianStrings.engineValue),
        Triple("dnsLabel", EnglishStrings.dnsLabel, PersianStrings.dnsLabel),
        Triple("dnsValue", EnglishStrings.dnsValue, PersianStrings.dnsValue),
        Triple("aboutNote", EnglishStrings.aboutNote, PersianStrings.aboutNote),
        Triple("project", EnglishStrings.project, PersianStrings.project),
        Triple("creatorRole", EnglishStrings.creatorRole, PersianStrings.creatorRole),
        Triple("source", EnglishStrings.source, PersianStrings.source),
        Triple("license", EnglishStrings.license, PersianStrings.license),
        Triple("licenseValue", EnglishStrings.licenseValue, PersianStrings.licenseValue),
        Triple("openOnGithub", EnglishStrings.openOnGithub, PersianStrings.openOnGithub),
        Triple("incomingTransmission", EnglishStrings.incomingTransmission, PersianStrings.incomingTransmission),
        Triple("newVersionAvailable", EnglishStrings.newVersionAvailable, PersianStrings.newVersionAvailable),
        Triple("downloadFromGithub", EnglishStrings.downloadFromGithub, PersianStrings.downloadFromGithub),
        Triple("later", EnglishStrings.later, PersianStrings.later),
    )

    @Test
    fun `every string is populated in both languages`() {
        fields.forEach { (name, en, fa) ->
            check(en.isNotBlank()) { "english field '$name' is blank" }
            check(fa.isNotBlank()) { "persian field '$name' is blank" }
        }
    }

    @Test
    fun `persian body text actually contains arabic-script glyphs`() {
        val samples = listOf(
            PersianStrings.initiateDeepScan,
            PersianStrings.stopScan,
            PersianStrings.scanComplete,
            PersianStrings.vlessForge,
            PersianStrings.aboutUmbra,
            PersianStrings.dnsNeverUsed,
        )
        samples.forEach { text ->
            check(text.any { it.code in 0x0600..0x06FF || it.code in 0xFB50..0xFEFF }) {
                "'$text' contains no arabic-script glyphs — stale copy?"
            }
        }
    }

    @Test
    fun `parameterized strings render their arguments`() {
        check("SWEEP ×12" == EnglishStrings.sweepLabel(12)) { "en sweep label broke" }
        check("×3" == EnglishStrings.retryLabel(3))
        check("REVEAL 150 MORE · 9 HIDDEN" == EnglishStrings.revealMore(9))
        check("≈ 2400 PROBES · 14 PREFIXES" == EnglishStrings.probesEstimate(2400, 14))
        check(" · ×3 PORTS" == EnglishStrings.portsFactor(3))
        check("last error · boom" == EnglishStrings.lastError("boom"))
        check("[2606:4700::1]" in EnglishStrings.ipv6Detected("2606:4700::1"))
        check("v3.0.0 ready — you are on 2.5.0" == EnglishStrings.updateReady("3.0.0", "2.5.0"))
        check("GET v3.0.0" == EnglishStrings.getVersion("3.0.0"))
        check("CLEAR RESULT BOARD (12)" == EnglishStrings.clearResultBoard(12))
        check("unlocks 90 / 120 / 144 Hz — display: 120 Hz" == EnglishStrings.maxRefreshHint("120"))
        check("جارو ×12" == PersianStrings.sweepLabel(12))
        check("۱۵۰ مورد بیشتر · 9 مخفی" == PersianStrings.revealMore(9))
        check("آخرین خطا · x" == PersianStrings.lastError("x"))
    }

    @Test
    fun `language mapping and defaults are sane`() {
        check(AppLanguage.stringsFor(AppLanguage.ENGLISH) === EnglishStrings)
        check(AppLanguage.stringsFor(AppLanguage.PERSIAN) === PersianStrings)
        check(AppLanguage.defaultFor("fa") == AppLanguage.PERSIAN)
        check(AppLanguage.defaultFor("fa_IR") == AppLanguage.PERSIAN)
        check(AppLanguage.defaultFor("en") == AppLanguage.ENGLISH)
        check(AppLanguage.defaultFor("de") == AppLanguage.ENGLISH)
        check(AppLanguage.defaultFor(null) == AppLanguage.ENGLISH)
    }
}
