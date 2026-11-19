package com.fc.fcaevpn

import android.content.Context
import org.json.JSONArray
import java.io.File
import java.nio.charset.StandardCharsets

internal object ImGuiSettingsMigration {
    private val aliases = mapOf(
        "protocol" to "protocol",
        "backend" to "backend",
        "mode" to "mode",
        "tun_engine" to "tunEngine",
        "scan_mode" to "scan",
        "h2_enabled" to "h2",
        "ech_enabled" to "ech",
        "fragment_enabled" to "fragment",
        "quick_reconnect" to "quick",
        "lan_sharing" to "lan",
        "logging_enabled" to "logging",
        "auto_update_check" to "autoUpdate",
        "check_prereleases" to "checkPreReleases",
        "socks_enabled" to "socks",
        "aether_http_unified" to "aetherHttpUnified",
        "firefox_socks_enabled" to "firefoxSocks",
        "firefox_http_unified" to "firefoxHttpUnified",
        "tor_socks_enabled" to "torSocks",
        "psiphon_socks_enabled" to "psiphonSocks",
        "psiphon_http_enabled" to "psiphonHttp",
        "tor_http_enabled" to "torHttp",
        "tor_http_port" to "torHttpPort",
        "tor_socks_port" to "torSocksPort",
        "xray_socks_enabled" to "xraySocks",
        "xray_http_enabled" to "xrayHttp",
        "singbox_socks_enabled" to "singBoxSocks",
        "singbox_http_enabled" to "singBoxHttp",
        "singbox_socks_port" to "singBoxSocksPort",
        "singbox_http_port" to "singBoxHttpPort",
        "tun_mtu" to "tunMtu",
        "tun_tcp_sndbuf" to "tunTcpSndbuf",
        "tun_tcp_rcvbuf" to "tunTcpRcvbuf",
        "tun_tcp_auto_tuning" to "tunTcpAutoTuning",
        "tun_exclude_private" to "tunExcludePrivate",
        "tun_dns4" to "tunDnsV4",
        "tun_dns6" to "tunDnsV6",
        "sys_profile" to "sysprofile",
        "engine_log" to "engineLog",
        "core_log" to "coreLog",
        "tun2socks_log" to "t2sLog",
        "tor_bridges" to "torBridges",
        "tor_bridge_lines" to "torBridgeLines",
        "team_name" to "team",
        "access_token" to "accessToken",
        "access_email" to "accessEmail",
        "firefox_account_id" to "firefoxAccountId",
        "firefox_location" to "firefoxLocation",
        "firefox_server" to "firefoxServer",
        "psiphon_region" to "psiphonRegion",
        "psiphon_region_list" to "psiphonRegionList",
        "psiphon_transport" to "psiphonTransport",
        "core_selected" to "coreSelected",
        "chain_transports" to "chainTransports",
        "tor_mode" to "tor",
        "frag_min_size" to "fragMinSize",
        "frag_max_size" to "fragMaxSize",
        "frag_min_delay" to "fragMinDelay",
        "frag_max_delay" to "fragMaxDelay",
        "socks_port" to "socksPort",
        "http_port" to "httpPort",
        "xray_socks_port" to "xraySocksPort",
        "xray_http_port" to "xrayHttpPort",
        "firefox_socks_port" to "firefoxSocksPort",
        "firefox_http_port" to "firefoxHttpPort",
        "psiphon_socks_port" to "psiphonSocksPort",
        "psiphon_http_port" to "psiphonHttpPort",
        "sni" to "sni",
        "ech_dns" to "echDns",
        "ech_domain" to "echDomain",
        "gool_inner" to "goolInner",
        "tls_ciphers" to "tlsCiphers",
        "api_address" to "apiAddress",
        "api_host" to "apiHost",
        "api_sni" to "apiSni",
        "exit_loc" to "exitLoc",
        "tls13_ciphers" to "tls13Ciphers",
        "tls_groups" to "tlsGroups",
        "tls_key_shares" to "tlsKeyShares",
        "tls_sigalgs" to "tlsSigalgs",
        "tls_cert_compression" to "tlsCertCompression",
        "tls_alps" to "tlsAlps",
        "tls_trust_anchors" to "tlsTrustAnchors",
        "tls_server_padding" to "tlsServerPadding",
        "tls_verify" to "tlsVerify",
        "disable_grease" to "disableGrease",
        "enable_grease_sigalgs" to "enableGreaseSigalgs",
        "enable_ech_grease" to "enableEchGrease",
        "disable_ocsp_stapling" to "disableOcspStapling",
        "disable_sct" to "disableSct",
        "disable_session_ticket" to "disableSessionTicket",
        "disable_extension_permutation" to "disableExtensionPermutation",
        "fragment_sni" to "fragmentSni",
        "force_peer" to "forcePeer",
        "upstream_proxy" to "upstreamProxy"
    )

    fun migrate(context: Context) {
        val destination = File(context.filesDir, "FCAE_VPN.cfg")
        if (destination.exists()) return
        val prefs = context.getSharedPreferences("fcae_vpn", Context.MODE_PRIVATE)
        val previous = prefs.all
        val result = StringBuilder()
        fun line(key: String, value: Any?) {
            if (value == null) return
            val text = when (value) {
                is Boolean -> if (value) "1" else "0"
                else -> value.toString()
            }
            result.append(key).append('=').append(text.replace("\r", "").replace("\n", ";")).append('\n')
        }
        for ((native, legacy) in aliases) line(native, previous[legacy])
        if (previous.containsKey("ipVersion"))
            line("ip_version", when (previous["ipVersion"]) { 1 -> 6; 2 -> 10; else -> 4 })
        if (previous.containsKey("noize"))
            line("noize_profile", arrayOf("off", "light", "balanced", "aggressive", "firewall", "gfw")
                .getOrElse((previous["noize"] as? Int) ?: 2) { "balanced" })
        if (previous.containsKey("firefoxTransport"))
            line("firefox_transport", when (previous["firefoxTransport"]) { "h2" -> 1; "h1" -> 2; else -> 0 })
        val routes = previous["routesInline"] as? String
        if (routes != null) line("routes_inline_hex", routes.toByteArray(StandardCharsets.UTF_8)
            .joinToString("") { "%02x".format(it.toInt() and 255) })
        val cores = JSONArray((previous["coreConfigs"] as? String).orEmpty().ifBlank { "[]" })
        for (index in 0 until cores.length()) {
            val core = cores.getJSONObject(index)
            line("core_config${index}_name", core.getString("name"))
            line("core_config${index}_backend", if (core.optString("backend") == "sing-box") 1 else 0)
            val config = core.get("config").toString()
                .replace("\\", "\\\\").replace("\n", "\\n").replace("\r", "\\r")
            line("core_config${index}_text", config)
        }
        if (!previous.containsKey("chainTransports")) {
            line("chain_count", previous["chainCount"])
            for (index in 0..2) line("chain_exit_$index", previous["chainExit$index"])
        }
        line("config_path", "aether.toml")
        val temporary = File(context.filesDir, "FCAE_VPN.cfg.migrate")
        temporary.outputStream().use { output ->
            output.write(result.toString().toByteArray(StandardCharsets.UTF_8))
            output.fd.sync()
        }
        check(temporary.renameTo(destination)) { "Could not migrate Android settings" }
    }
}
