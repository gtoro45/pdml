@load base/frameworks/logging    # ensures logging API is available

# ---- CONFIGURE: set where you want the log files written. ----
# Replace the path below with your desired directory. Must exist & be writable.
redef Log::default_logdir = "/tmp/zeek-sample-logs";

# ---- Module and stream definitions ----
module GenerateAllSampleLogs;

export {
    # One record type that we will reuse for many sample streams.
    type Info: record {
        ts: time        &log;           # timestamp
        note: string    &log &optional; # short sample text
    };

    # Create many distinct Log::ID entries (one per sample output).
    # We prefix with S_ to avoid name collisions with built-in stream IDs.
    redef enum Log::ID += {
        S_ANALYZER, S_CONN, S_DNS, S_HTTP, S_FILES, S_FTP, S_SSL, S_X509,
        S_SMTP, S_SSH, S_PE, S_DHCP, S_NTP, S_DCE_RPC, S_KERBEROS, S_SMB_MAPPING,
        S_SMB_FILES, S_IRC, S_LDAP, S_POSTGRESQL, S_QUIC, S_RDP, S_TRACEROUTE,
        S_TUNNEL, S_KNOWN_SOFTWARE, S_SOFTWARE, S_WEIRD, S_NOTICE, S_INTEL,
        S_CAPTURE_LOSS
    };
}

# ---- Create streams on startup ----
event zeek_init()
    {
    # For each stream we create a sample path name "sample_<name>".
    # Doing them explicitly keeps things readable.
    Log::create_stream(GenerateAllSampleLogs::S_ANALYZER, [$columns=GenerateAllSampleLogs::Info, $path="sample_analyzer"]);
    Log::create_stream(GenerateAllSampleLogs::S_CONN,     [$columns=GenerateAllSampleLogs::Info, $path="sample_conn"]);
    Log::create_stream(GenerateAllSampleLogs::S_DNS,      [$columns=GenerateAllSampleLogs::Info, $path="sample_dns"]);
    Log::create_stream(GenerateAllSampleLogs::S_HTTP,     [$columns=GenerateAllSampleLogs::Info, $path="sample_http"]);
    Log::create_stream(GenerateAllSampleLogs::S_FILES,    [$columns=GenerateAllSampleLogs::Info, $path="sample_files"]);
    Log::create_stream(GenerateAllSampleLogs::S_FTP,      [$columns=GenerateAllSampleLogs::Info, $path="sample_ftp"]);
    Log::create_stream(GenerateAllSampleLogs::S_SSL,      [$columns=GenerateAllSampleLogs::Info, $path="sample_ssl"]);
    Log::create_stream(GenerateAllSampleLogs::S_X509,     [$columns=GenerateAllSampleLogs::Info, $path="sample_x509"]);
    Log::create_stream(GenerateAllSampleLogs::S_SMTP,     [$columns=GenerateAllSampleLogs::Info, $path="sample_smtp"]);
    Log::create_stream(GenerateAllSampleLogs::S_SSH,      [$columns=GenerateAllSampleLogs::Info, $path="sample_ssh"]);
    Log::create_stream(GenerateAllSampleLogs::S_PE,       [$columns=GenerateAllSampleLogs::Info, $path="sample_pe"]);
    Log::create_stream(GenerateAllSampleLogs::S_DHCP,     [$columns=GenerateAllSampleLogs::Info, $path="sample_dhcp"]);
    Log::create_stream(GenerateAllSampleLogs::S_NTP,      [$columns=GenerateAllSampleLogs::Info, $path="sample_ntp"]);
    Log::create_stream(GenerateAllSampleLogs::S_DCE_RPC,  [$columns=GenerateAllSampleLogs::Info, $path="sample_dce_rpc"]);
    Log::create_stream(GenerateAllSampleLogs::S_KERBEROS, [$columns=GenerateAllSampleLogs::Info, $path="sample_kerberos"]);
    Log::create_stream(GenerateAllSampleLogs::S_SMB_MAPPING,[$columns=GenerateAllSampleLogs::Info, $path="sample_smb_mapping"]);
    Log::create_stream(GenerateAllSampleLogs::S_SMB_FILES,[$columns=GenerateAllSampleLogs::Info, $path="sample_smb_files"]);
    Log::create_stream(GenerateAllSampleLogs::S_IRC,      [$columns=GenerateAllSampleLogs::Info, $path="sample_irc"]);
    Log::create_stream(GenerateAllSampleLogs::S_LDAP,     [$columns=GenerateAllSampleLogs::Info, $path="sample_ldap"]);
    Log::create_stream(GenerateAllSampleLogs::S_POSTGRESQL,[$columns=GenerateAllSampleLogs::Info, $path="sample_postgresql"]);
    Log::create_stream(GenerateAllSampleLogs::S_QUIC,     [$columns=GenerateAllSampleLogs::Info, $path="sample_quic"]);
    Log::create_stream(GenerateAllSampleLogs::S_RDP,      [$columns=GenerateAllSampleLogs::Info, $path="sample_rdp"]);
    Log::create_stream(GenerateAllSampleLogs::S_TRACEROUTE,[$columns=GenerateAllSampleLogs::Info, $path="sample_traceroute"]);
    Log::create_stream(GenerateAllSampleLogs::S_TUNNEL,   [$columns=GenerateAllSampleLogs::Info, $path="sample_tunnel"]);
    Log::create_stream(GenerateAllSampleLogs::S_KNOWN_SOFTWARE,[$columns=GenerateAllSampleLogs::Info, $path="sample_known_software"]);
    Log::create_stream(GenerateAllSampleLogs::S_SOFTWARE, [$columns=GenerateAllSampleLogs::Info, $path="sample_software"]);
    Log::create_stream(GenerateAllSampleLogs::S_WEIRD,    [$columns=GenerateAllSampleLogs::Info, $path="sample_weird"]);
    Log::create_stream(GenerateAllSampleLogs::S_NOTICE,   [$columns=GenerateAllSampleLogs::Info, $path="sample_notice"]);
    Log::create_stream(GenerateAllSampleLogs::S_INTEL,    [$columns=GenerateAllSampleLogs::Info, $path="sample_intel"]);
    Log::create_stream(GenerateAllSampleLogs::S_CAPTURE_LOSS,[$columns=GenerateAllSampleLogs::Info, $path="sample_capture_loss"]);
    }

# ---- Write one sample entry per stream when Zeek finishes (ensures files get created) ----
event zeek_done()
    {
    local rec: GenerateAllSampleLogs::Info = [$ts=network_time(), $note="sample entry - created by generate_all_sample_logs.zeek"];

    Log::write(GenerateAllSampleLogs::S_ANALYZER, rec);
    Log::write(GenerateAllSampleLogs::S_CONN,     rec);
    Log::write(GenerateAllSampleLogs::S_DNS,      rec);
    Log::write(GenerateAllSampleLogs::S_HTTP,     rec);
    Log::write(GenerateAllSampleLogs::S_FILES,    rec);
    Log::write(GenerateAllSampleLogs::S_FTP,      rec);
    Log::write(GenerateAllSampleLogs::S_SSL,      rec);
    Log::write(GenerateAllSampleLogs::S_X509,     rec);
    Log::write(GenerateAllSampleLogs::S_SMTP,     rec);
    Log::write(GenerateAllSampleLogs::S_SSH,      rec);
    Log::write(GenerateAllSampleLogs::S_PE,       rec);
    Log::write(GenerateAllSampleLogs::S_DHCP,     rec);
    Log::write(GenerateAllSampleLogs::S_NTP,      rec);
    Log::write(GenerateAllSampleLogs::S_DCE_RPC,  rec);
    Log::write(GenerateAllSampleLogs::S_KERBEROS, rec);
    Log::write(GenerateAllSampleLogs::S_SMB_MAPPING, rec);
    Log::write(GenerateAllSampleLogs::S_SMB_FILES, rec);
    Log::write(GenerateAllSampleLogs::S_IRC,      rec);
    Log::write(GenerateAllSampleLogs::S_LDAP,     rec);
    Log::write(GenerateAllSampleLogs::S_POSTGRESQL, rec);
    Log::write(GenerateAllSampleLogs::S_QUIC,     rec);
    Log::write(GenerateAllSampleLogs::S_RDP,      rec);
    Log::write(GenerateAllSampleLogs::S_TRACEROUTE, rec);
    Log::write(GenerateAllSampleLogs::S_TUNNEL,   rec);
    Log::write(GenerateAllSampleLogs::S_KNOWN_SOFTWARE, rec);
    Log::write(GenerateAllSampleLogs::S_SOFTWARE, rec);
    Log::write(GenerateAllSampleLogs::S_WEIRD,    rec);
    Log::write(GenerateAllSampleLogs::S_NOTICE,   rec);
    Log::write(GenerateAllSampleLogs::S_INTEL,    rec);
    Log::write(GenerateAllSampleLogs::S_CAPTURE_LOSS, rec);
    }
