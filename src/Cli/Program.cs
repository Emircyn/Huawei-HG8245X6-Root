using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using HekzOntRace.Core;
using Renci.SshNet;

namespace HekzOntRace.Cli;

internal static class Program
{
    internal static readonly JsonSerializerOptions Json = new() { IncludeFields = true, WriteIndented = true };
    private static readonly Dictionary<string, string> Commands = new()
    {
        ["help"] = "",
        ["self-test"] = "",
        ["info"] = "",
        ["wifi get"] = "",
        ["wifi set"] = "band ssid hidden psk-env",
        ["wifi security"] = "band encryption",
        ["wifi split"] = "",
        ["dns get"] = "",
        ["dns set"] = "primary secondary side domain",
        ["wan get"] = "",
        ["wan set"] = "file domain",
        ["firewall get"] = "",
        ["firewall set"] = "level",
        ["alg get"] = "",
        ["alg set"] = "file",
        ["tr069 get"] = "",
        ["tr069 set"] = "enabled periodic",
        ["backup config"] = "output",
        ["backup profile"] = "output",
        ["restore config"] = "file",
        ["restore profile"] = "file",
        ["http get"] = "path",
        ["http post"] = "path file referer",
        ["config edit"] = "file xpath attribute value-env output",
        ["config get"] = "file xpath",
        ["config decrypt"] = "file output",
        ["credentials get"] = "",
        ["credentials recover"] = "python output-dir",
        ["access password"] = "new-password-env enable-shell method python output-dir",
        ["ssh exec"] = "command-file port host-key",
    };
    private const string Global = "host user password-file timeout show-secrets";

    public static async Task<int> Main(string[] args)
    {
        Console.OutputEncoding = new UTF8Encoding(false);
        try
        {
            var (command, o) = Parse(args);
            if (command == "help")
            {
                Print(new { ok = true, version = "0.1.0", commands = Commands, globalOptions = Global,
                    authentication = "--password-file > HUAWEI_PASSWORD > application default; default user=admin, host=192.168.1.1",
                    output = "stdout=JSON, stderr=logs; states: read, verified, submitted, partial; exit 5=unverified/partial",
                    rawOutput = "http, ssh and backup files can contain secrets",
                    writes = "Explicit commands execute immediately; no interactive prompts. Firmware support requires device testing." });
                return 0;
            }
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(Number(o, "timeout", 180, 1, 3600)));
            Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); };
            object result;
            if (command == "self-test") result = SelfTest();
            else if (command.StartsWith("config ")) result = await Offline(command, o, cts.Token);
            else
            {
                string host = Get(o, "host", "192.168.1.1");
                ValidateHost(host);
                string password = o.ContainsKey("password-file")
                    ? (await File.ReadAllTextAsync(Required(o, "password-file"), cts.Token)).TrimEnd('\r', '\n')
                    : Environment.GetEnvironmentVariable("HUAWEI_PASSWORD");
                if (!o.ContainsKey("password-file") && string.IsNullOrWhiteSpace(password)) password = "superonline";
                if (string.IsNullOrWhiteSpace(password)) throw new ArgumentException("Password file is empty.");
                LogMaskeleyici.GizliDegerEkle(password);
                string user = Get(o, "user", "admin");
                if (command == "ssh exec") result = await Ssh(o, host, user, password, cts.Token);
                else if (command is "credentials recover" or "access password")
                    result = await EngineCommand(command, o, host, user, password, cts.Token);
                else
                {
                    // Validate files before authentication or any device write.
                    if (command == "restore config") ValidateConfig(await File.ReadAllBytesAsync(Required(o, "file"), cts.Token));
                    if (command == "restore profile") ReadProfile(Required(o, "file"));
                    using var web = new OntWeb(host);
                    var login = await web.HttpLoginAsync(user, password, cts.Token);
                    if (!login.OK) throw new UnauthorizedAccessException("Web login failed: " + login.Detay);
                    var page = await web.GetPageExAsync(ModemInfoReader.PDeviceInfo, cts.Token);
                    if (page.Status != 200 || page.Body.Contains("txt_Username") || page.Body.Contains("login.asp") ||
                        !Regex.IsMatch(page.Body, @"new\s+stDeviceInfo\s*\("))
                        throw new UnauthorizedAccessException("Device page did not confirm an authenticated session.");
                    result = await WebCommand(command, o, web, cts.Token);
                }
            }
            var node = JsonSerializer.SerializeToNode(result, Json);
            if (!Bool(o, "show-secrets", false)) Redact(node);
            Print(node);
            string state = node?["state"]?.GetValue<string>();
            return state is "submitted" or "partial" ? 5 : 0;
        }
        catch (Exception ex)
        {
            int code = ex switch { ArgumentException or InvalidDataException or JsonException or XmlException => 2,
                UnauthorizedAccessException => 3, OperationCanceledException => 130, _ => 4 };
            Print(new { ok = false, error = new { type = ex.GetType().Name, message = LogMaskeleyici.Temizle(ex.Message) }, exitCode = code });
            return code;
        }
    }

    internal static (string Command, Dictionary<string, string> Options) Parse(string[] args)
    {
        if (args.Length == 0 || args.SequenceEqual(new[] { "--help" })) return ("help", new());
        int n = Array.FindIndex(args, x => x.StartsWith("--", StringComparison.Ordinal));
        if (n < 0) n = args.Length;
        string command = string.Join(" ", args.Take(n));
        if (!Commands.TryGetValue(command, out string specific)) throw new ArgumentException("Unknown command; run huawei help.");
        var allowed = (Global + " " + specific).Split(' ', StringSplitOptions.RemoveEmptyEntries).ToHashSet();
        var o = new Dictionary<string, string>();
        for (int i = n; i < args.Length; i++)
        {
            string key = args[i];
            if (!key.StartsWith("--") || !allowed.Contains(key[2..])) throw new ArgumentException("Unknown option: " + key);
            key = key[2..];
            string value = key == "show-secrets" ? "true" : ++i < args.Length && !args[i].StartsWith("--")
                ? args[i] : throw new ArgumentException("Missing value for --" + key);
            if (!o.TryAdd(key, value)) throw new ArgumentException("Duplicate option: --" + key);
        }
        return (command, o);
    }

    private static async Task<object> WebCommand(string command, Dictionary<string, string> o, OntWeb web, CancellationToken ct)
    {
        switch (command)
        {
            case "http get":
            {
                string path = LocalPath(Required(o, "path"));
                var r = await web.GetPageExAsync(path, ct);
                if (r.Status != 200) throw new IOException("HTTP " + r.Status);
                return Read(new { path, body = r.Body });
            }
            case "http post":
            {
                string path = LocalPath(Required(o, "path"));
                var fields = JsonSerializer.Deserialize<Dictionary<string, string>>(await File.ReadAllTextAsync(Required(o, "file"), ct))
                    ?? throw new InvalidDataException("Expected a JSON object of form fields (string values).");
                fields["x.X_HW_Token"] = await web.TokenAsync(ct);
                if (string.IsNullOrEmpty(fields["x.X_HW_Token"])) throw new IOException("No session token.");
                if (fields.Any(x => string.IsNullOrEmpty(x.Key) || x.Value == null)) throw new InvalidDataException("Invalid form fields.");
                foreach (var f in fields.Where(x => Regex.IsMatch(x.Key, "password|preshared|secret", RegexOptions.IgnoreCase)))
                    LogMaskeleyici.GizliDegerEkle(f.Value);
                string body = string.Join("&", fields.Select(x => Uri.EscapeDataString(x.Key) + "=" + Uri.EscapeDataString(x.Value)));
                var r = await web.PostFormAsync(path, body, web.Base + "/" + LocalPath(Get(o, "referer", ModemInfoReader.PDeviceInfo)), ct);
                if (r.Status < 200 || r.Status >= 400) throw new IOException("HTTP " + r.Status);
                return Submitted(new { status = r.Status, body = r.Body }, "Request sent; read the affected page to verify device state.");
            }
            case "backup config":
            {
                var bytes = await web.DownloadConfigBackupAsync(ct) ?? throw new IOException("Configuration download failed.");
                ValidateConfig(bytes);
                await Save(Required(o, "output"), bytes, ct);
                return Read(new { path = Path.GetFullPath(o["output"]), bytes = bytes.Length });
            }
            case "credentials get":
            {
                var bytes = await web.DownloadConfigBackupAsync(ct) ?? throw new IOException("Configuration download failed.");
                return Read(Credentials(ParseConfig(bytes)));
            }
            case "restore config":
            {
                string file = Required(o, "file");
                byte[] bytes = await File.ReadAllBytesAsync(file, ct);
                ValidateConfig(bytes);
                string backup = await BackupBeforeWrite(web, ct);
                var r = await web.UploadConfigRestoreAsync(bytes, Path.GetFileName(file), ct);
                if (!r.ok) throw new IOException(r.detay);
                return Submitted(new { backup, response = r.detay }, "Upload accepted; reboot and post-restore state have not been verified.");
            }
        }

        ModemInfo mi = await ModemInfoReader.FetchAllAsync(web, ct, Log);
        ct.ThrowIfCancellationRequested();
        if (command is "info" or "wifi get" or "dns get" or "wan get" or "firewall get" or "alg get" or "tr069 get")
        {
            object data = command switch
            {
                "wifi get" => mi.Bands,
                "dns get" => new { primary = mi.DnsPrimary, secondary = mi.DnsSecondary, fromLan = mi.DnsFromLan },
                "wan get" => new { domain = mi.WanDomain, name = mi.WanName, ip = mi.WanIp, status = mi.WanStatus, mtu = mi.WanMtu, pppoeUser = mi.PppoeUser },
                "firewall get" => new { level = mi.FirewallLevel },
                "alg get" => mi.Alg,
                "tr069 get" => new { enabled = mi.CwmpEnabled, periodic = mi.CwmpPeriodicInform, acsUrl = mi.AcsUrl },
                _ => mi
            };
            return new { ok = true, state = mi.Notes.Count == 0 ? "read" : "partial", data, warnings = mi.Notes };
        }
        if (command == "backup profile")
        {
            RequireComplete(mi);
            var p = BackupYardimci.ProfilOlustur(mi, new BackupKapsam(), web.Base);
            await Save(Required(o, "output"), Encoding.UTF8.GetBytes(JsonSerializer.Serialize(p, Json)), ct);
            return Read(new { path = Path.GetFullPath(o["output"]) });
        }
        if (command == "restore profile")
        {
            RequireComplete(mi);
            var p = ReadProfile(Required(o, "file"));
            if (!string.IsNullOrEmpty(p.SeriNo) && p.SeriNo != mi.Serial) throw new InvalidDataException("Backup serial number differs from device.");
            string backup = await BackupBeforeWrite(web, ct);
            var results = await ProfilGeriYukleme.UygulaAsync(web, p, p.Kapsam, ct);
            // shortcut: upstream profile restore has mixed verification, report submitted until every restored field is checked.
            return Submitted(new { backup, steps = results.Select(x => new { ok = x.ok, message = x.msg }) }, "Profile steps completed; inspect each affected setting. Partial changes are possible.");
        }
        (bool ok, string msg) r2;
        switch (command)
        {
            case "wan set":
            {
                string domain = Get(o, "domain", mi.WanDomain);
                ValidateDomain(domain);
                if (!domain.Contains("WANPPPConnection.") && !domain.Contains("WANIPConnection.")) throw new ArgumentException("Expected a WAN connection domain.");
                var rawOptions = new Dictionary<string, string>(o)
                {
                    ["path"] = "set.cgi?x=" + Uri.EscapeDataString(domain) + "&RequestFile=" + ModemInfoReader.PWanCache,
                    ["referer"] = ModemInfoReader.PWanCache
                };
                return await WebCommand("http post", rawOptions, web, ct);
            }
            case "wifi set":
            {
                var band = mi.Bands.SingleOrDefault(x => x.Instance == Required(o, "band")) ?? throw new ArgumentException("Unknown Wi-Fi band instance.");
                string ssid = Get(o, "ssid", band.Ssid);
                if (Encoding.UTF8.GetByteCount(ssid) is < 1 or > 32 || ssid.Any(char.IsControl)) throw new ArgumentException("SSID must be 1..32 UTF-8 bytes without controls.");
                string psk = o.ContainsKey("psk-env") ? Secret(o, "psk-env") : null;
                if (psk != null && !(psk.Length is >= 8 and <= 63 && psk.All(c => c is >= ' ' and <= '~') || Regex.IsMatch(psk, "^[a-fA-F0-9]{64}$")))
                    throw new ArgumentException("PSK must be 8..63 printable ASCII characters or 64 hexadecimal characters.");
                r2 = await ModemInfoWriter.SetSsidAsync(web, band, ssid, !Bool(o, "hidden", band.Hidden), psk, ct);
                // upstream only checks SSID and PSK by substring; visibility and band identity require structured readback.
                return Submitted(new { response = r2.msg, upstreamCheck = r2.ok }, "Wi-Fi write attempted; verify SSID, PSK, enabled and hidden state for this band.");
            }
            case "wifi security":
            {
                var band = mi.Bands.SingleOrDefault(x => x.Instance == Required(o, "band")) ?? throw new ArgumentException("Unknown Wi-Fi band instance.");
                string enc = Required(o, "encryption").ToLowerInvariant() switch
                {
                    "aes"  => "AESEncryption",
                    "tkip" => "TKIPEncryption",
                    "both" => "TKIPandAESEncryption",
                    _ => throw new ArgumentException("--encryption must be aes, tkip or both."),
                };
                r2 = await ModemInfoWriter.SetWifiEncryptionAsync(web, band, enc, ct);
                if (!r2.ok) throw new IOException(r2.msg);
                var after = await ModemInfoReader.FetchAllAsync(web, ct, Log);
                var ab = after.Bands.FirstOrDefault(x => x.Instance == band.Instance);
                if (ab == null || !string.Equals(ab.Encryption, enc, StringComparison.OrdinalIgnoreCase))
                    return Submitted(new { requested = enc, actual = ab?.Encryption }, "Wi-Fi encryption readback did not confirm the requested mode.");
                break;
            }
            case "wifi split":
                r2 = await ModemInfoWriter.EnableDualSsidAsync(web, mi, ct);
                return Submitted(new { response = r2.msg, upstreamCheck = r2.ok }, "Both writes attempted; verify both bands. Partial changes are possible.");
            case "dns set":
            {
                string primary = Required(o, "primary"), secondary = Get(o, "secondary", "");
                if (!IPAddress.TryParse(primary, out _) || secondary.Length > 0 && !IPAddress.TryParse(secondary, out _)) throw new ArgumentException("Invalid DNS address.");
                string side = Choice(o, "side", "lan", "lan", "wan");
                r2 = side == "lan" ? await ModemInfoWriter.SetLanDnsAsync(web, primary, secondary, ct)
                    : await ModemInfoWriter.SetWanDnsAsync(web, Get(o, "domain", mi.WanDomain), primary, secondary, ct);
                break;
            }
            case "firewall set":
            {
                string level = Choice(o, "level", null, "disable", "low", "high", "strict");
                r2 = await ModemInfoWriter.SetFirewallLevelAsync(web, level, ct);
                if (!r2.ok) throw new IOException(r2.msg);
                var after = await ModemInfoReader.FetchAllAsync(web, ct, Log);
                if (!after.FirewallLevel.Contains(level, StringComparison.OrdinalIgnoreCase))
                    return Submitted(new { requested = level, actual = after.FirewallLevel }, "Firewall readback did not confirm the requested level.");
                break;
            }
            case "alg set":
            {
                var values = JsonSerializer.Deserialize<Dictionary<string, bool>>(await File.ReadAllTextAsync(Required(o, "file"), ct));
                if (values == null || values.Count == 0 || values.Keys.Any(k => !mi.Alg.ContainsKey(k))) throw new ArgumentException("Unknown ALG key or empty input; use alg get for supported keys.");
                r2 = await ModemInfoWriter.SetAlgAsync(web, values, ct);
                // Upstream may report success when the response is missing fields.
                var after = await ModemInfoReader.FetchAllAsync(web, ct, Log);
                if (values.Any(x => !after.Alg.TryGetValue(x.Key, out bool v) || v != x.Value))
                    return Submitted(new { response = r2.msg, actual = after.Alg }, "ALG readback did not confirm all requested fields.");
                break;
            }
            case "tr069 set":
                r2 = await ModemInfoWriter.SetTr069Async(web, Bool(o, "enabled"), Bool(o, "periodic", mi.CwmpPeriodicInform), ct);
                break;
            default: throw new ArgumentException("Unsupported command.");
        }
        ct.ThrowIfCancellationRequested();
        return r2.ok ? new { ok = true, state = "verified", data = new { message = r2.msg } }
            : Submitted(new { message = r2.msg }, "Write attempted but readback did not confirm success; inspect device state before retrying.");
    }

    private static async Task<object> EngineCommand(string command, Dictionary<string, string> o, string host, string user, string password, CancellationToken ct)
    {
        if (host.Contains(':')) throw new ArgumentException("Engine commands require a host without a port.");
        var engine = new Engine(host, password, Log, Log, ct)
        {
            LoginUser = user, PythonPath = Get(o, "python", "python3"),
            TelnetSshAc = Bool(o, "enable-shell", false), HesapTemizle = true
        };
        string newPassword = null;
        string method = "web";
        if (command == "access password")
        {
            newPassword = Secret(o, "new-password-env");
            var validation = Engine.DogrulaYeniSuserSifresi(newPassword);
            if (!validation.isValid) throw new ArgumentException(validation.error);
            newPassword = validation.finalPassword;
            method = Choice(o, "method", "web", "web", "race");
            if (method == "web" && user != "sUser") throw new ArgumentException("Web password changes require --user sUser and its current password.");
        }
        string root = Path.GetFullPath(Get(o, "output-dir", Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share", "huawei", "backups")));
        Directory.CreateDirectory(root);
        string runDir = Path.Combine(root, "run-" + Guid.NewGuid().ToString("N"));
        if (OperatingSystem.IsWindows()) Directory.CreateDirectory(runDir);
        else Directory.CreateDirectory(runDir, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);
        Engine.OutputRoot = runDir;
        if (command == "credentials recover")
        {
            await engine.RunAsync();
            ct.ThrowIfCancellationRequested();
            if (!engine.HmacValid) throw new InvalidDataException("Recovered factory data failed HMAC verification.");
            await Save(Path.Combine(runDir, "factory.bin"), engine.EncryptedBlob, ct);
            await Save(Path.Combine(runDir, "factory.txt"), Encoding.UTF8.GetBytes(engine.PlainText), ct);
            object credentials = null;
            if (engine.CfgXml.Length > 0)
            {
                await Save(Path.Combine(runDir, "config.xml"), Encoding.UTF8.GetBytes(engine.CfgXml), ct);
                credentials = Credentials(ParseConfig(Encoding.UTF8.GetBytes(engine.CfgXml)));
            }
            return new { ok = true, state = credentials == null ? "partial" : "read", data = new { outputDirectory = runDir, factoryParameters = engine.PlainText, credentials },
                warnings = new[] { "Recovery changes SFTP/SMB services and creates temporary accounts; inspect service settings after completion.", "Factory passwords may differ from current passwords." } };
        }
        string changed = method == "web" ? await engine.SuserYazWebAsync(password, newPassword) : await engine.SuserYazAsync(newPassword);
        ct.ThrowIfCancellationRequested();
        if (changed == null) throw new IOException("Password write failed; inspect device state before retrying. Backups: " + runDir);
        return Submitted(new { outputDirectory = runDir, method, shellRequested = engine.TelnetSshAc }, "Write flow completed; reboot and authenticate with the new password to verify. Race mode needs physical power timing.");
    }

    private static async Task<object> Ssh(Dictionary<string, string> o, string host, string user, string password, CancellationToken ct)
    {
        string fingerprint = Required(o, "host-key");
        string command = await File.ReadAllTextAsync(Required(o, "command-file"), ct);
        if (string.IsNullOrWhiteSpace(command)) throw new ArgumentException("Empty SSH command file.");
        var connection = new PasswordConnectionInfo(host, Number(o, "port", 22, 1, 65535), user, password) { Timeout = TimeSpan.FromSeconds(15) };
        using var client = new SshClient(connection);
        client.HostKeyReceived += (_, e) =>
        {
            string actual = "SHA256:" + Convert.ToBase64String(SHA256.HashData(e.HostKey)).TrimEnd('=');
            e.CanTrust = actual == fingerprint;
            if (!e.CanTrust) Log("SSH host key mismatch; observed " + actual);
        };
        await client.ConnectAsync(ct);
        using var cmd = client.CreateCommand(command);
        cmd.CommandTimeout = TimeSpan.FromSeconds(Number(o, "timeout", 180, 1, 3600));
        await cmd.ExecuteAsync(ct);
        if (cmd.ExitStatus != 0) throw new IOException("SSH command failed (exit " + cmd.ExitStatus + "): " + cmd.Error);
        return Read(new { stdout = cmd.Result, stderr = cmd.Error, exitCode = cmd.ExitStatus });
    }

    private static async Task<object> Offline(string command, Dictionary<string, string> o, CancellationToken ct)
    {
        byte[] bytes = await File.ReadAllBytesAsync(Required(o, "file"), ct);
        if (command == "config get")
        {
            var doc = ParseConfig(bytes);
            var elements = System.Xml.XPath.Extensions.XPathSelectElements(doc, Required(o, "xpath"));
            return Read(elements.Select(e => new { element = e.Name.LocalName, attributes = e.Attributes().ToDictionary(a => a.Name.LocalName, a => a.Value) }));
        }
        if (command == "config decrypt")
        {
            var plain = HuaweiCrypto.Decrypt(bytes);
            if (!plain.HmacValid) throw new InvalidDataException("HMAC verification failed; refusing output.");
            bytes = plain.Plain;
            if (bytes.Length >= 2 && bytes[0] == 31 && bytes[1] == 139)
            {
                using var gz = new System.IO.Compression.GZipStream(new MemoryStream(bytes), System.IO.Compression.CompressionMode.Decompress);
                using var ms = new MemoryStream();
                var buffer = new byte[8192];
                int n;
                while ((n = await gz.ReadAsync(buffer, ct)) > 0)
                {
                    if (ms.Length + n > 16 * 1024 * 1024) throw new InvalidDataException("Decompressed configuration exceeds 16 MiB.");
                    ms.Write(buffer, 0, n);
                }
                bytes = ms.ToArray();
            }
        }
        else
        {
            var doc = ParseConfig(bytes);
            string xpath = Required(o, "xpath");
            var nodes = System.Xml.XPath.Extensions.XPathSelectElements(doc, xpath).ToList();
            if (nodes.Count != 1) throw new ArgumentException("XPath must select exactly one element; selected " + nodes.Count);
            var attr = nodes[0].Attribute(Required(o, "attribute")) ?? throw new ArgumentException("Attribute does not exist.");
            attr.Value = Secret(o, "value-env");
            bytes = Encoding.UTF8.GetBytes(doc.ToString(SaveOptions.DisableFormatting));
        }
        ValidateConfig(bytes);
        await Save(Required(o, "output"), bytes, ct);
        return Read(new { path = Path.GetFullPath(o["output"]), bytes = bytes.Length, deviceChanged = false });
    }

    internal static XDocument ParseConfig(byte[] bytes)
    {
        using var reader = XmlReader.Create(new MemoryStream(bytes), new XmlReaderSettings
        { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null, MaxCharactersInDocument = 16 * 1024 * 1024 });
        var doc = XDocument.Load(reader, LoadOptions.PreserveWhitespace);
        if (doc.Root?.Name.LocalName != "InternetGatewayDevice") throw new InvalidDataException("Expected InternetGatewayDevice XML root.");
        return doc;
    }

    internal static void ValidateConfig(byte[] bytes)
    {
        if (bytes.Length is < 56 or > 16 * 1024 * 1024) throw new InvalidDataException("Configuration size is invalid.");
        if (bytes[0] == 1)
        {
            if (!HuaweiCrypto.Decrypt(bytes).HmacValid) throw new InvalidDataException("Configuration HMAC failed.");
        }
        else ParseConfig(bytes);
    }

    private static YedekProfili ReadProfile(string path)
    {
        var p = BackupYardimci.ProfilOku(path, out string error) ?? throw new InvalidDataException(error);
        if (p.Surum != 1 || p.Kapsam == null || p.Wifi == null || p.Alg == null || p.Wifi.Any(x => x == null || x.Ssid == null || x.Domain == null || x.Instance == null))
            throw new InvalidDataException("Invalid profile structure/version.");
        if (p.Kapsam.HicBiriSecili) throw new InvalidDataException("Profile has no selected categories.");
        foreach (var b in p.Wifi)
        {
            ValidateDomain(b.Domain);
            if (Encoding.UTF8.GetByteCount(b.Ssid) is < 1 or > 32 || b.Ssid.Any(char.IsControl)) throw new InvalidDataException("Invalid profile SSID.");
            if (!string.IsNullOrEmpty(b.Psk) && !(b.Psk.Length is >= 8 and <= 63 && b.Psk.All(c => c is >= ' ' and <= '~') || Regex.IsMatch(b.Psk, "^[a-fA-F0-9]{64}$")))
                throw new InvalidDataException("Invalid profile Wi-Fi key.");
        }
        if (!string.IsNullOrEmpty(p.WanDomain)) ValidateDomain(p.WanDomain);
        foreach (var dns in new[] { p.DnsBirincil, p.DnsIkincil })
            if (!string.IsNullOrEmpty(dns) && !IPAddress.TryParse(dns, out _)) throw new InvalidDataException("Invalid profile DNS.");
        return p;
    }

    private static object Credentials(XDocument doc)
    {
        string Decode(string value) => value.StartsWith("$2") ? Engine.Dollar2.Decrypt(value) : value;
        var accounts = Engine.WebHesaplariCek(doc.ToString());
        return new
        {
            accounts = accounts.Select(x => new { user = x.User, enabled = x.Enable, level = x.Level,
                factoryPassword = x.FactoryPass, factoryPasswordVerified = Engine.SifreDogrula(x, x.FactoryPass) }),
            pppoe = doc.Descendants("WANPPPConnectionInstance").Select(e => new
            {
                user = (string)e.Attribute("Username") ?? (string)e.Attribute("UserName"),
                password = Decode((string)e.Attribute("Password") ?? "")
            })
        };
    }

    private static void ValidateDomain(string domain)
    {
        if (domain == null || !Regex.IsMatch(domain, @"^InternetGatewayDevice\.[A-Za-z0-9_.]+$")) throw new ArgumentException("Invalid device data-model domain.");
    }

    private static void RequireComplete(ModemInfo mi)
    {
        if (mi.Notes.Count > 0) throw new IOException("Device information is incomplete: " + string.Join("; ", mi.Notes));
    }

    private static async Task<string> BackupBeforeWrite(OntWeb web, CancellationToken ct)
    {
        var bytes = await web.DownloadConfigBackupAsync(ct) ?? throw new IOException("Cannot create safety backup; restore was not sent.");
        ValidateConfig(bytes);
        string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share", "huawei", "backups");
        string path = Path.Combine(dir, "before-restore-" + Guid.NewGuid().ToString("N") + ".cfg");
        await Save(path, bytes, ct);
        return path;
    }

    internal static async Task Save(string path, byte[] bytes, CancellationToken ct)
    {
        path = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(path));
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };
        if (!OperatingSystem.IsWindows()) options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;
        await using var stream = new FileStream(path, options);
        await stream.WriteAsync(bytes, ct);
    }

    internal static void ValidateHost(string host)
    {
        if (!Uri.TryCreate("http://" + host, UriKind.Absolute, out var uri) || uri.Authority != host ||
            uri.UserInfo.Length > 0 || uri.HostNameType is UriHostNameType.Unknown || host.Any(char.IsWhiteSpace))
            throw new ArgumentException("Host must be a hostname or IP, optionally with a port; no URL, path or credentials.");
    }

    internal static string LocalPath(string path)
    {
        if (path.StartsWith("//") || path.Contains('\\') || path.Contains('#') || path.Any(char.IsControl) ||
            Uri.TryCreate(path, UriKind.Absolute, out _)) throw new ArgumentException("Expected a device-relative path.");
        return path.TrimStart('/');
    }

    internal static void Redact(JsonNode node)
    {
        if (node is JsonObject obj)
        {
            foreach (var pair in obj.ToArray())
                if (Regex.IsMatch(pair.Key, @"^(psk|pppoePassword|factoryPassword|factoryParameters|password)$", RegexOptions.IgnoreCase)) obj[pair.Key] = "***";
                else Redact(pair.Value);
        }
        else if (node is JsonArray array) foreach (var item in array) Redact(item);
    }

    private static string Get(Dictionary<string, string> o, string key, string fallback) => o.TryGetValue(key, out var value) ? value : fallback;
    private static string Required(Dictionary<string, string> o, string key) => o.TryGetValue(key, out var value) && value.Length > 0 ? value : throw new ArgumentException("Required option: --" + key);
    private static string Secret(Dictionary<string, string> o, string key)
    {
        string value = Environment.GetEnvironmentVariable(Required(o, key));
        if (string.IsNullOrEmpty(value)) throw new ArgumentException("Secret environment variable is missing/empty: " + o[key]);
        LogMaskeleyici.GizliDegerEkle(value);
        return value;
    }
    private static bool Bool(Dictionary<string, string> o, string key, bool? fallback = null) => o.TryGetValue(key, out string value)
        ? bool.TryParse(value, out bool b) ? b : throw new ArgumentException("--" + key + " must be true or false.")
        : fallback ?? throw new ArgumentException("Required option: --" + key);
    private static int Number(Dictionary<string, string> o, string key, int fallback, int min, int max) => !o.ContainsKey(key) ? fallback
        : int.TryParse(o[key], out int n) && n >= min && n <= max ? n : throw new ArgumentException("Invalid --" + key);
    private static string Choice(Dictionary<string, string> o, string key, string fallback, params string[] choices)
    {
        string value = Get(o, key, fallback);
        return choices.Contains(value) ? value : throw new ArgumentException("--" + key + ": " + string.Join("|", choices));
    }
    private static object Read(object data) => new { ok = true, state = "read", data };
    private static object Submitted(object data, string warning) => new { ok = true, state = "submitted", data, warning };
    private static void Print(object value) => Console.WriteLine(JsonSerializer.Serialize(value, Json));
    private static void Log(string message) => Console.Error.WriteLine(LogMaskeleyici.Temizle(message));

    private static object SelfTest()
    {
        static void Check(bool value, string name) { if (!value) throw new InvalidOperationException("Self-test failed: " + name); }
        var plain = Encoding.UTF8.GetBytes("roundtrip-password-123");
        var cipher = HuaweiCrypto.Encrypt(plain, new byte[] { 1, 0, 0, 0, 0, 0, 0, 0 });
        var decoded = HuaweiCrypto.Decrypt(cipher);
        Check(decoded.HmacValid && decoded.Plain.SequenceEqual(plain), "configuration roundtrip");
        cipher[^1] ^= 1;
        Check(!HuaweiCrypto.Decrypt(cipher).HmacValid, "tamper detection");
        Check(Engine.Dollar2.Decrypt(Engine.Dollar2.Encrypt("Test1234")) == "Test1234", "Dollar2 roundtrip");
        Check(!Engine.DogrulaYeniSuserSifresi("short").isValid && Engine.DogrulaYeniSuserSifresi("Valid1234").isValid, "password validation");
        var redacted = JsonNode.Parse("{\"Bands\":[{\"Psk\":\"hidden\"}],\"factoryParameters\":\"hidden\"}");
        Redact(redacted);
        Check(!redacted.ToJsonString().Contains("hidden"), "secret redaction");
        Check(Parse(new[] { "dns", "set", "--primary", "1.1.1.1" }).Command == "dns set", "command parser");
        var ws = Parse(new[] { "wifi", "security", "--band", "1", "--encryption", "aes" });
        Check(ws.Command == "wifi security" && ws.Options["band"] == "1" && ws.Options["encryption"] == "aes", "wifi security parser");
        return Read(new { tests = 7, passed = true });
    }
}
