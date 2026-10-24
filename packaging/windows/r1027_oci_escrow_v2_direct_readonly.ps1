# R1027: paste once in Windows PowerShell 5.1. No arguments.
# The encrypted backup must already be in Downloads, Desktop, or the current folder.
# No backup/key is read by development tests. Runtime performs ONE fixed SSH inspection.
Set-StrictMode -Version 2.0

function Initialize-R1027 {
    if (-not ('FlopR1036.Guards' -as [type])) {
        Add-Type -ReferencedAssemblies 'System.dll','System.Core.dll','System.Security.dll','System.Web.Extensions.dll' -TypeDefinition @'
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace FlopR1036 {
    public sealed class Captured {
        public int ExitCode;
        public byte[] Output;
    }
    public static class Guards {
        public const string EXPECTED_SHA256 = "8dae15bf339e54ece1a23b7c78fdcb43a5adb0534b01064fe44d5713c9d96301";
        public const string GuestCommit = "1983c9893f05a7b7769d04ba5c5d321428c7ea3d";
        public const string GuestBlob = "937039a7c136b409f46573abcc1982ba5023ae66";
        public const string GuestRouteBlob = "4921bfca59abed4cb744d0a0ca1c05c31291f877";
        public const string OriginalHead = "ec4bc4892d40cdd2a03e102faa44d72c89e01b99";
        static void Need(bool ok) { if (!ok) throw new InvalidOperationException("R1027_GUARD"); }
        public static void Clear(byte[] value) { if (value != null) Array.Clear(value, 0, value.Length); }
        public static string Sha256(byte[] data) {
            using (var hash = SHA256.Create()) return BitConverter.ToString(hash.ComputeHash(data)).Replace("-", "").ToLowerInvariant();
        }
        public static void VerifySource(byte[] source, string expected = GuestBlob) {
            Need(source != null && source.Length > 0 && source.Length <= 32768);
            byte[] prefix = Encoding.ASCII.GetBytes("blob " + source.Length + "\0");
            using (var hash = SHA1.Create()) {
                hash.TransformBlock(prefix, 0, prefix.Length, prefix, 0);
                hash.TransformFinalBlock(source, 0, source.Length);
                Need(BitConverter.ToString(hash.Hash).Replace("-", "").ToLowerInvariant() == expected);
            }
        }
        static byte[] Derive(byte[] password, byte[] salt) {
            byte[] result = new byte[48], input = new byte[salt.Length + 4], u = null, block = null;
            Buffer.BlockCopy(salt, 0, input, 0, salt.Length);
            try {
                using (var hmac = new HMACSHA256(password)) {
                    for (int number = 1; number <= 2; number++) {
                        input[input.Length - 1] = (byte)number;
                        u = hmac.ComputeHash(input);
                        block = (byte[])u.Clone();
                        for (int iteration = 1; iteration < 600000; iteration++) {
                            byte[] next = hmac.ComputeHash(u);
                            Clear(u); u = next;
                            for (int i = 0; i < block.Length; i++) block[i] ^= u[i];
                        }
                        int count = number == 1 ? 32 : 16;
                        Buffer.BlockCopy(block, 0, result, (number - 1) * 32, count);
                        Clear(u); u = null; Clear(block); block = null;
                    }
                }
                return result;
            } catch { Clear(result); throw; }
            finally { Clear(input); Clear(u); Clear(block); }
        }
        public static byte[] Decrypt(byte[] encrypted, string expectedHash, SecureString password) {
            // Authenticate the exact escrow bytes BEFORE reading the SecureString.
            Need(encrypted != null && encrypted.Length >= 32 && encrypted.Length <= 65536);
            Need(Sha256(encrypted) == expectedHash);
            Need(Encoding.ASCII.GetString(encrypted, 0, 8) == "Salted__");
            // OpenSSL's 8/16-byte salt formats are unambiguous from CBC block alignment.
            int saltLength = encrypted.Length % 16 == 0 ? 8 : (encrypted.Length % 16 == 8 ? 16 : 0);
            Need(saltLength != 0 && (encrypted.Length - 8 - saltLength) >= 16);
            byte[] salt = new byte[saltLength], bytes = null, material = null, key = new byte[32],
                   iv = new byte[16], plain = null;
            char[] chars = null;
            IntPtr pointer = IntPtr.Zero;
            Buffer.BlockCopy(encrypted, 8, salt, 0, saltLength);
            try {
                Need(password != null && password.Length > 0 && password.Length <= 1024);
                pointer = Marshal.SecureStringToGlobalAllocUnicode(password);
                chars = new char[password.Length];
                for (int i = 0; i < chars.Length; i++) chars[i] = (char)Marshal.ReadInt16(pointer, i * 2);
                bytes = new UTF8Encoding(false, true).GetBytes(chars);
                material = Derive(bytes, salt);
                Buffer.BlockCopy(material, 0, key, 0, 32);
                Buffer.BlockCopy(material, 32, iv, 0, 16);
                using (var aes = Aes.Create()) {
                    aes.KeySize = 256; aes.Mode = CipherMode.CBC; aes.Padding = PaddingMode.PKCS7;
                    aes.Key = key; aes.IV = iv;
                    using (var decryptor = aes.CreateDecryptor())
                        plain = decryptor.TransformFinalBlock(encrypted, 8 + saltLength, encrypted.Length - 8 - saltLength);
                }
                Need(plain.Length > 80 && plain.Length <= 32768);
                // Accept only one direct, unencrypted OpenSSH key envelope, never an archive/commands.
                // Parsing is deliberately byte-based: no immutable plaintext key string is created.
                byte[] begin = Encoding.ASCII.GetBytes("-----BEGIN OPENSSH PRIVATE KEY-----\n");
                Need(plain.Length >= begin.Length);
                for (int i = 0; i < begin.Length; i++) Need(plain[i] == begin[i]);
                byte[] end = Encoding.ASCII.GetBytes("-----END OPENSSH PRIVATE KEY-----\n");
                for (int i = 0; i < end.Length; i++) Need(plain[plain.Length - end.Length + i] == end[i]);
                for (int i = begin.Length; i < plain.Length - end.Length; i++) {
                    byte c = plain[i];
                    Need((c >= 65 && c <= 90) || (c >= 97 && c <= 122) ||
                         (c >= 48 && c <= 57) || c == 43 || c == 47 || c == 61 || c == 10);
                }
                byte[] output = plain; plain = null; return output;
            } finally {
                if (pointer != IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(pointer);
                if (chars != null) Array.Clear(chars, 0, chars.Length);
                Clear(bytes); Clear(material); Clear(key); Clear(iv); Clear(salt); Clear(plain);
            }
        }
        public static string Quote(string value) {
            Need(value != null && value.IndexOf('\0') < 0 && value.IndexOf('\r') < 0 && value.IndexOf('\n') < 0);
            var result = new StringBuilder("\""); int slashes = 0;
            foreach (char c in value) {
                if (c == '\\') { slashes++; continue; }
                if (c == '"') result.Append('\\', slashes * 2 + 1);
                else result.Append('\\', slashes);
                result.Append(c); slashes = 0;
            }
            return result.Append('\\', slashes * 2).Append('"').ToString();
        }
        public static Captured Run(string executable, string[] args, byte[] input, int timeoutMs, int maximum) {
            Need(timeoutMs > 0 && timeoutMs <= 60000 && maximum > 0 && maximum <= 65536);
            var joined = new List<string>(); foreach (string arg in args) joined.Add(Quote(arg));
            var info = new ProcessStartInfo(executable, String.Join(" ", joined.ToArray()));
            info.UseShellExecute = false; info.CreateNoWindow = true;
            info.RedirectStandardInput = info.RedirectStandardOutput = info.RedirectStandardError = true;
            using (var process = new Process()) using (var output = new MemoryStream()) {
                process.StartInfo = info;
                int failed = 0;
                Thread writer = null, reader = null, errors = null;
                try {
                    Need(process.Start());
                    writer = new Thread(delegate() {
                        try { process.StandardInput.BaseStream.Write(input, 0, input.Length); process.StandardInput.Close(); }
                        catch { Interlocked.Exchange(ref failed, 1); }
                    });
                    reader = new Thread(delegate() {
                        byte[] buffer = new byte[2048];
                        try {
                            int count;
                            while ((count = process.StandardOutput.BaseStream.Read(buffer, 0, buffer.Length)) > 0) {
                                if (output.Length + count > maximum) {
                                    Interlocked.Exchange(ref failed, 1); process.Kill(); return;
                                }
                                output.Write(buffer, 0, count);
                            }
                        } catch { Interlocked.Exchange(ref failed, 1); }
                        finally { Clear(buffer); }
                    });
                    errors = new Thread(delegate() {
                        byte[] buffer = new byte[2048];
                        try { while (process.StandardError.BaseStream.Read(buffer, 0, buffer.Length) > 0) {} }
                        catch { Interlocked.Exchange(ref failed, 1); }
                        finally { Clear(buffer); }
                    });
                    writer.IsBackground = reader.IsBackground = errors.IsBackground = true;
                    writer.Start(); reader.Start(); errors.Start();
                    Need(process.WaitForExit(timeoutMs));
                    Need(writer.Join(2000) && reader.Join(2000) && errors.Join(2000));
                    Need(failed == 0);
                    return new Captured { ExitCode = process.ExitCode, Output = output.ToArray() };
                } finally {
                    if (!process.HasExited) { process.Kill(); Need(process.WaitForExit(3000)); }
                    if (writer != null && writer.IsAlive) Need(writer.Join(3000));
                    if (reader != null && reader.IsAlive) Need(reader.Join(3000));
                    if (errors != null && errors.IsAlive) Need(errors.Join(3000));
                }
            }
        }
        static readonly string[] Names = {
            "airdrop-monitor.service","airdrop-monitor.timer","airdrop-notifier.service","airdrop-notifier.timer",
            "discord.service","lobby-capture.service","resident.service","close1-approved-trade.service",
            "close1-auto-resident.service","close1-batch-trade.service","close1-standalone-watch.service",
            "metadata-block.service","precontest-supervisor.service","precontest-supervisor.timer","signer.service",
            "tclk-accept@.service","tclk-lock-watcher.service","tclk-lock-watcher.timer","tclk-preparer.service",
            "tclk-preparer.timer","tclk-reveal-preparer.service","tclk-reveal-preparer.timer","tclk-reveal@.service",
            "tclk-stager.service","tclk-stager.timer","tclk-work-watcher.service","tclk-work-watcher.timer"
        };
        const string Prefix = "technocore-safe-agent-";
        static readonly HashSet<string> Signers = new HashSet<string>(new string[] {
            Prefix+"signer.service",Prefix+"tclk-accept@.service",Prefix+"tclk-reveal@.service",
            Prefix+"close1-approved-trade.service",Prefix+"close1-batch-trade.service" }, StringComparer.Ordinal);
        static readonly HashSet<string> FileStates = new HashSet<string>(new string[] {
            "enabled","enabled-runtime","linked","linked-runtime","alias","masked","masked-runtime","static",
            "disabled","indirect","generated","transient","bad" }, StringComparer.Ordinal);
        static readonly HashSet<string> ActiveStates = new HashSet<string>(new string[] {
            "active","reloading","inactive","failed","activating","deactivating","maintenance","refreshing" }, StringComparer.Ordinal);
        static readonly HashSet<string> Active = new HashSet<string>(new string[] {
            "active","activating","reloading","refreshing" }, StringComparer.Ordinal);
        static Dictionary<string,object> Dict(object value, string[] keys) {
            var map = value as Dictionary<string,object>; Need(map != null && map.Count == keys.Length);
            foreach (string key in keys) Need(map.ContainsKey(key)); return map;
        }
        static List<string> Strings(object value) {
            var array = value as object[]; Need(array != null && array.Length <= 128);
            var result = new List<string>(); string previous = null;
            foreach (object item in array) {
                Need(item is string); string text = (string)item;
                Need(previous == null || StringComparer.Ordinal.Compare(previous, text) < 0);
                result.Add(text); previous = text;
            }
            return result;
        }
        static bool Same(List<string> a, List<string> b) {
            if (a.Count != b.Count) return false;
            for (int i = 0; i < a.Count; i++) if (a[i] != b[i]) return false;
            return true;
        }
        static object Ordered(object value) {
            var dictionary = value as Dictionary<string,object>;
            if (dictionary != null) {
                var result = new SortedDictionary<string,object>(StringComparer.Ordinal);
                foreach (var pair in dictionary) result.Add(pair.Key, Ordered(pair.Value)); return result;
            }
            var array = value as object[];
            if (array != null) { var result = new object[array.Length];
                for (int i = 0; i < array.Length; i++) result[i] = Ordered(array[i]); return result; }
            return value;
        }
        public static string ValidateRoutes(byte[] raw) {
            Need(raw != null && raw.Length > 0 && raw.Length <= 16384);
            foreach (byte b in raw) Need((b >= 32 && b <= 126) || b == 10);
            string txt = Encoding.ASCII.GetString(raw);
            var serial = new JavaScriptSerializer { MaxJsonLength = 16384, RecursionLimit = 8 };
            var doc = Dict(serial.DeserializeObject(txt),
                new string[] { "schema_version", "original_head", "units", "cron", "processes", "flags" });
            Need(doc["schema_version"] is int && (int)doc["schema_version"] == 2);
            Need(doc["original_head"] is string && (string)doc["original_head"] == OriginalHead);
            string[] names = new string[] {
                "technocore-safe-agent-close1-discord-activation.service",
                "technocore-safe-agent-close1-discord-activation.timer",
                "technocore-safe-agent-close1-standalone-watch.timer",
                "technocore-safe-agent-postreboot-check.service" };
            var units = doc["units"] as object[]; Need(units != null && units.Length == 4);
            for (int i = 0; i < units.Length; i++) {
                var row = Dict(units[i], new string[] {
                    "identity", "active", "installed", "load", "command_kind", "fragment_origin" });
                Need(row["identity"] is string && (string)row["identity"] == names[i]);
                Need(row["active"] is string && new string[] {
                    "active","inactive","activating","deactivating","failed","reloading"
                }.Contains((string)row["active"]));
                Need(row["load"] is string && new string[] {
                    "loaded","not-found","masked","error","bad-setting"
                }.Contains((string)row["load"]));
                Need(row["installed"] is string && new string[] {
                    "enabled","enabled-runtime","disabled","indirect","static","masked",
                    "masked-runtime","linked","linked-runtime","generated","alias","bad","transient",""
                }.Contains((string)row["installed"]));
                Need(row["command_kind"] is string && new string[] {
                    "NO_EXEC","FLOP_PYTHON","SHELL","OTHER_UNVERIFIED"
                }.Contains((string)row["command_kind"]));
                Need(row["fragment_origin"] is string && new string[] {
                    "ETC_SYSTEMD","NO_FRAGMENT","OTHER_UNVERIFIED"
                }.Contains((string)row["fragment_origin"]));
            }
            var cron = Dict(doc["cron"], new string[] {
                "cron_regular_files_read", "cron_flop_matching_lines",
                "cron_unverified_entries", "cron_scan_complete" });
            foreach (string key in new string[] { "cron_regular_files_read",
                        "cron_flop_matching_lines", "cron_unverified_entries" }) {
                Need(cron[key] is int && (int)cron[key] >= 0 && (int)cron[key] <= 8192);
            }
            Need(cron["cron_scan_complete"] is bool && !(bool)cron["cron_scan_complete"]);
            var proc = Dict(doc["processes"], new string[] {
                "matching_processes", "cgroup_inspected_candidates",
                "unknown_or_raced_processes", "process_scan_complete" });
            foreach (string key in new string[] { "matching_processes",
                        "cgroup_inspected_candidates", "unknown_or_raced_processes" }) {
                Need(proc[key] is int && (int)proc[key] >= 0 && (int)proc[key] <= 4096);
            }
            Need((int)proc["cgroup_inspected_candidates"] <= (int)proc["matching_processes"]);
            Need(proc["process_scan_complete"] is bool && !(bool)proc["process_scan_complete"]);
            var flags = Dict(doc["flags"], new string[] {
                "original_source_pin", "no_service_or_state_modification",
                "process_and_cron_discovery_complete", "all_writers_fenced",
                "signer_inflight_post_resolved", "capture_common_epoch_proven", "oci_retirement" });
            foreach (string key in flags.Keys) {
                string expected = key == "original_source_pin" ? "PASS" :
                    (key == "no_service_or_state_modification" ? "YES" :
                    (key == "oci_retirement" ? "STRICT_NO_GO" : "NO"));
                Need(flags[key] is string && (string)flags[key] == expected);
            }
            string canonical = serial.Serialize(Ordered(doc)) + "\n";
            Need(txt == canonical);
            return canonical.TrimEnd('\n');
        }

        public static string ValidateReport(byte[] raw) {
            Need(raw != null && raw.Length > 0 && raw.Length <= 65536);
            foreach (byte b in raw) Need(b >= 32 && b <= 126 || b == 10);
            string text = Encoding.ASCII.GetString(raw);
            var serializer = new JavaScriptSerializer { MaxJsonLength = 65536, RecursionLimit = 12 };
            var report = Dict(serializer.DeserializeObject(text), new string[] { "schema_version","original_head",
                "static_service_count","static_timer_count","missing_known","units","active_known",
                "active_signer_candidates","flags" });
            Need(report["schema_version"] is int && (int)report["schema_version"] == 1);
            Need(report["original_head"] is string && (string)report["original_head"] == OriginalHead);
            Need(report["static_service_count"] is int && (int)report["static_service_count"] == 19);
            Need(report["static_timer_count"] is int && (int)report["static_timer_count"] == 8);
            var flags = Dict(report["flags"], new string[] { "original_source_pin","no_source_or_unit_modification",
                "process_enumeration_complete","all_writers_fenced","signer_inflight_post_resolved",
                "capture_common_epoch_proven","writer_epoch_proven","oci_retirement" });
            foreach (string key in flags.Keys) {
                string expected = key == "original_source_pin" ? "PASS" : (key == "no_source_or_unit_modification" ?
                    "YES" : (key == "oci_retirement" ? "STRICT_NO_GO" : "NO"));
                Need(flags[key] is string && (string)flags[key] == expected);
            }
            var expectedNames = new HashSet<string>(StringComparer.Ordinal);
            foreach (string name in Names) expectedNames.Add(Prefix + name);
            var units = report["units"] as object[]; Need(units != null && units.Length <= 128);
            var installed = new HashSet<string>(StringComparer.Ordinal);
            var activeKnown = new List<string>(); var activeSigners = new List<string>();
            string previous = null;
            foreach (object value in units) {
                var row = Dict(value, new string[] { "identity","known","installed_states","active_states","signer_candidate" });
                Need(row["identity"] is string); string name = (string)row["identity"];
                Need(name.Length <= 128 && (expectedNames.Contains(name) ||
                    System.Text.RegularExpressions.Regex.IsMatch(name, @"\Atechnocore-safe-agent-[a-z][a-z0-9-]{0,79}\.(service|timer)\z") ||
                    System.Text.RegularExpressions.Regex.IsMatch(name, @"\Aredacted-sha256-[a-f0-9]{64}\z")));
                Need(previous == null || StringComparer.Ordinal.Compare(previous, name) < 0); previous = name;
                bool known = expectedNames.Contains(name), signer = Signers.Contains(name);
                Need(row["known"] is bool && (bool)row["known"] == known);
                Need(row["signer_candidate"] is bool && (bool)row["signer_candidate"] == signer);
                var files = Strings(row["installed_states"]); var states = Strings(row["active_states"]);
                Need(files.Count + states.Count > 0);
                foreach (string state in files) Need(FileStates.Contains(state));
                bool active = false; foreach (string state in states) { Need(ActiveStates.Contains(state)); active |= Active.Contains(state); }
                if (known && files.Count > 0) installed.Add(name);
                if (known && active) activeKnown.Add(name);
                if (signer && active) activeSigners.Add(name);
            }
            var missing = new List<string>(); foreach (string name in expectedNames) if (!installed.Contains(name)) missing.Add(name);
            missing.Sort(StringComparer.Ordinal);
            Need(Same(Strings(report["missing_known"]), missing));
            Need(Same(Strings(report["active_known"]), activeKnown));
            Need(Same(Strings(report["active_signer_candidates"]), activeSigners));
            string canonical = serializer.Serialize(Ordered(report)) + "\n";
            Need(text == canonical); // Reject duplicate keys, trailing data and noncanonical encodings.
            return canonical.TrimEnd('\n');
        }
    }
}
'@
    }
}

function Assert-R1027LocalPath([string]$Path) {
    $full = [IO.Path]::GetFullPath($Path)
    if ($full.StartsWith('\\') -or [IO.Path]::GetPathRoot($full).Length -ne 3) { throw 'LOCAL_PATH_STOP' }
    $cursor = $full
    while ($cursor -and ([IO.Directory]::Exists($cursor) -or [IO.File]::Exists($cursor))) {
        if (([IO.File]::GetAttributes($cursor) -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'REPARSE_STOP' }
        $parent = [IO.Path]::GetDirectoryName($cursor)
        if ($parent -eq $cursor) { break }
        $cursor = $parent
    }
}

function New-R1027Custody([string]$Directory) {
    Assert-R1027LocalPath ([IO.Path]::GetDirectoryName($Directory))
    if ([IO.Directory]::Exists($Directory) -or [IO.File]::Exists($Directory)) { throw 'CUSTODY_EXISTS_STOP' }
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
    $null = [IO.Directory]::CreateDirectory($Directory, $acl)
    # On elevated Windows tokens the initial owner can be Administrators
    # even when the requested DACL is private. Explicitly normalize the
    # owner to the CURRENT user before any key bytes are ever written.
    [IO.Directory]::SetAccessControl($Directory, $acl)
    Assert-R1027Acl $Directory
}

function Assert-R1027Acl([string]$Path) {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    if ([IO.Directory]::Exists($Path)) { $acl = [IO.Directory]::GetAccessControl($Path) }
    else { $acl = [IO.File]::GetAccessControl($Path) }
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -ne $sid.Value) { throw 'ACL_STOP' }
    # Windows normalizes effective FullControl masks and may split same-user
    # ACEs. Reject ANY other principal/deny ACE, not legitimate mask variations.
    # The directory itself must remain protected from parent ACL inheritance.
    if ([IO.Directory]::Exists($Path) -and -not $acl.AreAccessRulesProtected) { throw 'ACL_STOP' }
    $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -lt 1) { throw 'ACL_STOP' }
    $allowRead = $false
    $allowWrite = $false
    foreach ($rule in $rules) {
        if ($rule.IdentityReference.Value -ne $sid.Value -or
            $rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow) {
            throw 'ACL_STOP'
        }
        $rights = [int]$rule.FileSystemRights
        if (($rights -band [int][Security.AccessControl.FileSystemRights]::ReadData) -ne 0) { $allowRead = $true }
        if (($rights -band [int][Security.AccessControl.FileSystemRights]::WriteData) -ne 0) { $allowWrite = $true }
    }
    if (-not ($allowRead -and $allowWrite)) { throw 'ACL_STOP' }
}

function Write-R1027Key([string]$Directory, [byte[]]$Bytes) {
    Assert-R1027Acl $Directory
    $path = Join-Path $Directory 'recovered-v2'
    $stream = New-Object IO.FileStream($path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($Bytes, 0, $Bytes.Length); $stream.Flush($true) } finally { $stream.Dispose() }
    # A child file can also acquire the token's default owner. Keep the
    # inherited single-user DACL while enforcing explicit file ownership.
    $fileAcl = [IO.File]::GetAccessControl($path)
    $fileAcl.SetOwner([Security.Principal.WindowsIdentity]::GetCurrent().User)
    [IO.File]::SetAccessControl($path, $fileAcl)
    Assert-R1027Acl $path
    return $path
}

function Remove-R1027Custody([string]$Directory) {
    if ([IO.File]::Exists($Directory)) { throw 'CLEANUP_STOP' }
    if (-not [IO.Directory]::Exists($Directory)) { return }
    Assert-R1027LocalPath $Directory
    Assert-R1027Acl $Directory
    $key = Join-Path $Directory 'recovered-v2'
    if ([IO.File]::Exists($key)) { [IO.File]::Delete($key) }
    [IO.Directory]::Delete($Directory, $false)
    if ([IO.Directory]::Exists($Directory) -or [IO.File]::Exists($key)) { throw 'CLEANUP_STOP' }
}

function Get-R1027SshArguments([string]$Key, [string]$KnownHosts) {
    return @('-F', 'NUL', '-T', '-i', $Key,
        '-o', ('UserKnownHostsFile="' + $KnownHosts.Replace('\', '/') + '"'), '-o', 'GlobalKnownHostsFile=NUL',
        '-o', 'StrictHostKeyChecking=yes', '-o', 'HostKeyAlgorithms=ecdsa-sha2-nistp256',
        '-o', 'PasswordAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
        '-o', 'PreferredAuthentications=publickey', '-o', 'HostbasedAuthentication=no',
        '-o', 'GSSAPIAuthentication=no', '-o', 'UpdateHostKeys=no',
        '-o', 'BatchMode=yes', '-o', 'IdentitiesOnly=yes', '-o', 'IdentityAgent=none',
        '-o', 'ClearAllForwardings=yes', '-o', 'ForwardAgent=no', '-o', 'ForwardX11=no',
        '-o', 'PermitLocalCommand=no', '-o', 'KnownHostsCommand=none',
        '-o', 'ProxyCommand=none', '-o', 'ProxyJump=none', '-o', 'CanonicalizeHostname=no',
        '-o', 'ConnectionAttempts=1', '-o', 'ConnectTimeout=7',
        '-o', 'ServerAliveInterval=10', '-o', 'ServerAliveCountMax=2',
        'ubuntu@140.238.55.171', 'sudo -n /usr/bin/python3 -')
}

function Get-R1027Source([bool]$RouteProbe = $false) {
    $url = if ($RouteProbe) {
        'https://raw.githubusercontent.com/hanamaru777/technocore-safe-agent/6ffa7641e5644e1fa5b1d20e3dffadaa949f8f36/packaging/oracle/r1036_writer_routes_readonly.py'
    } else {
        'https://raw.githubusercontent.com/hanamaru777/technocore-safe-agent/1983c9893f05a7b7769d04ba5c5d321428c7ea3d/packaging/oracle/r1023_unit_identity_readonly.py'
    }
    $priorTls = [Net.ServicePointManager]::SecurityProtocol
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $request = [Net.HttpWebRequest]::Create($url)
    $request.Method = 'GET'
    $request.AllowAutoRedirect = $false
    $request.Timeout = 15000
    $request.ReadWriteTimeout = 15000
    $response = $null; $stream = $null; $memory = New-Object IO.MemoryStream
    try {
        $response = $request.GetResponse()
        if ([int]$response.StatusCode -ne 200) { throw 'SOURCE_STOP' }
        $stream = $response.GetResponseStream()
        $buffer = New-Object byte[] 2048
        $watch = [Diagnostics.Stopwatch]::StartNew()
        while (($count = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            if ($memory.Length + $count -gt 32768 -or $watch.ElapsedMilliseconds -gt 20000) { throw 'SOURCE_STOP' }
            $memory.Write($buffer, 0, $count)
        }
        $bytes = $memory.ToArray()
        if ($RouteProbe) { [FlopR1036.Guards]::VerifySource($bytes, [FlopR1036.Guards]::GuestRouteBlob) }
        else { [FlopR1036.Guards]::VerifySource($bytes) }
        return ,$bytes
    } finally {
        if ($stream) { $stream.Dispose() }
        if ($response) { $response.Dispose() }
        $memory.Dispose()
        [Net.ServicePointManager]::SecurityProtocol = $priorTls
    }
}

function Find-R1027Backup {
    $profile = [Environment]::GetFolderPath('UserProfile')
    $filename = 'FLOP_NEW_SSH_20261018_AES256_V2.enc'
    $paths = @((Join-Path (Join-Path $profile 'Downloads') $filename),
               (Join-Path ([Environment]::GetFolderPath('DesktopDirectory')) $filename),
               (Join-Path (Get-Location).Path $filename)) | Select-Object -Unique
    $found = @($paths | Where-Object { [IO.File]::Exists($_) })
    if ($found.Count -ne 1) { throw 'BACKUP_LOCATION_STOP' }
    return $found[0]
}

function Get-R1027Prerequisites {
    $ssh = Join-Path ([Environment]::GetFolderPath('System')) 'OpenSSH\ssh.exe'
    $hosts = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.ssh\known_hosts'
    if (-not [IO.File]::Exists($ssh) -or -not [IO.File]::Exists($hosts)) { throw 'PREREQUISITE_STOP' }
    Assert-R1027LocalPath $ssh
    Assert-R1027LocalPath $hosts
    return @{ Ssh = $ssh; Hosts = $hosts }
}

function Read-R1027Backup {
    $backup = Find-R1027Backup
    # Deny concurrent writes and bound the allocation before reading ciphertext.
    $stream = [IO.File]::Open($backup, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $length = $stream.Length
        if ($length -lt 32 -or $length -gt 65536) { throw 'BACKUP_BOUND_STOP' }
        $encrypted = New-Object byte[] ([int]$length)
        $offset = 0
        while ($offset -lt $length) {
            $count = $stream.Read($encrypted, $offset, [int]($length - $offset))
            if ($count -le 0) { throw 'BACKUP_BOUND_STOP' }
            $offset += $count
        }
    } finally { $stream.Dispose() }
    if ([FlopR1036.Guards]::Sha256($encrypted) -cne [FlopR1036.Guards]::EXPECTED_SHA256) { throw 'BACKUP_HASH_STOP' }
    return ,$encrypted
}

function Unprotect-R1027([byte[]]$Encrypted, [Security.SecureString]$Code) {
    return ,([FlopR1036.Guards]::Decrypt($Encrypted, [FlopR1036.Guards]::EXPECTED_SHA256, $Code))
}

function Invoke-R1027Ssh([string]$Ssh, [string[]]$Arguments, [byte[]]$Source) {
    return [FlopR1036.Guards]::Run($Ssh, $Arguments, $Source, 58000, 65536)
}

# Fixed public stage codes only; no native stderr, raw stdout, key, or path.
function Get-R1027SshFailure([int]$ExitCode, [byte[]]$Output) {
    if ($ExitCode -eq 255) { return 'SSH_TRANSPORT_OR_AUTH_STOP' }
    if ($ExitCode -ne 42) { return 'SSH_REMOTE_EXIT_STOP' }
    if ($null -eq $Output -or $Output.Length -lt 15 -or $Output.Length -gt 160) {
        return 'GUEST_UNRECOGNIZED_STOP'
    }
    foreach ($b in $Output) {
        if ($b -ne 10 -and ($b -lt 32 -or $b -gt 126)) { return 'GUEST_UNRECOGNIZED_STOP' }
    }
    $line = [Text.Encoding]::ASCII.GetString($Output)
    $match = [Text.RegularExpressions.Regex]::Match(
        $line, '\AFLOP_R1023_STOP=([A-Z0-9_]{3,90})\n\z',
        [Text.RegularExpressions.RegexOptions]::CultureInvariant)
    if (-not $match.Success) { return 'GUEST_UNRECOGNIZED_STOP' }
    $reason = $match.Groups[1].Value
    $other = @('ORIGINAL_ROOT_OPERATOR_REQUIRED', 'WRONG_GUEST_SCOPE',
        'ROOT_TYPE_STOP', 'ORIGINAL_HEAD_MISMATCH_STOP', 'METADATA_BOUND_STOP',
        'METADATA_ROW_STOP', 'METADATA_NAME_STOP', 'METADATA_DUPLICATE_STOP',
        'METADATA_STATE_STOP', 'UNIT_COUNT_BOUND_STOP', 'REPORT_BOUND_STOP',
        'READONLY_STAGE_INVALID_STOP', 'LOCAL_GUARD_STOP')
    if ($other -ccontains $reason -or
        $reason -cmatch '\AREADONLY_(HEAD|UNIT_FILES|LIVE_UNITS)_(TIMEOUT|EXEC|EXIT|OUTPUT_BOUND|ENCODING)_STOP\z') {
        return ('GUEST_' + $reason)
    }
    return 'GUEST_UNRECOGNIZED_STOP'
}

function Invoke-R1027([bool]$RouteProbe = $false) {
    $ErrorActionPreference = 'Stop'
    $stage = 'PREFLIGHT_STOP'; $directory = $null; $plain = $null; $code = $null
    $encrypted = $null; $result = $null; $summary = $null; $ok = $false; $clean = $true
    try {
        if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -lt 1) { throw 'VERSION_STOP' }
        Initialize-R1027
        $context = Get-R1027Prerequisites
        $stage = 'BACKUP_HASH_STOP'
        $encrypted = Read-R1027Backup
        $stage = 'SOURCE_PIN_STOP'
        $source = Get-R1027Source $RouteProbe
        $stage = 'DECRYPT_STOP'
        $code = Read-Host 'R987 V2 recovery code' -AsSecureString
        try { $plain = Unprotect-R1027 $encrypted $code }
        finally { if ($code) { $code.Dispose(); $code = $null } }
        $stage = 'CUSTODY_STOP'
        $directory = Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) ('Temp\flop-r1027-' + [Guid]::NewGuid().ToString('N'))
        New-R1027Custody $directory
        try { $key = Write-R1027Key $directory $plain }
        finally { [FlopR1036.Guards]::Clear($plain); $plain = $null }
        $stage = 'SSH_INVOKE_STOP'
        $arguments = Get-R1027SshArguments $key $context.Hosts
        $result = Invoke-R1027Ssh $context.Ssh $arguments $source
        if ($result.ExitCode -ne 0) {
            if ($RouteProbe -and $result.ExitCode -eq 42) { $stage = 'GUEST_ROUTE_GUARD_STOP' }
            else { $stage = Get-R1027SshFailure $result.ExitCode $result.Output }
            throw 'REMOTE_NONZERO_STOP'
        }
        $stage = 'RESPONSE_STOP'
        $summary = if ($RouteProbe) {
            [FlopR1036.Guards]::ValidateRoutes($result.Output)
        } else { [FlopR1036.Guards]::ValidateReport($result.Output) }
        $ok = $true
    } catch {
        # Never format the exception, native output, code, key, paths, or environment.
        $ok = $false
    } finally {
        if ($code) { $code.Dispose() }
        if ('FlopR1036.Guards' -as [type]) {
            [FlopR1036.Guards]::Clear($plain)
            [FlopR1036.Guards]::Clear($encrypted)
            if ($result) { [FlopR1036.Guards]::Clear($result.Output) }
        }
        if ($directory) {
            try { Remove-R1027Custody $directory }
            catch { $clean = $false }
        }
    }
    if (-not $clean) { [Console]::WriteLine('FLOP_R1027_STOP=CLEANUP_STOP'); return }
    if (-not $ok) { [Console]::WriteLine('FLOP_R1027_STOP=' + $stage); return }
    [Console]::WriteLine($summary)
    if ($RouteProbe) {
        [Console]::WriteLine('FLOP_R1036_ALL_WRITERS_FENCED=NO')
        [Console]::WriteLine('FLOP_R1036_OCI_RETIREMENT=STRICT_NO_GO')
        [Console]::WriteLine('FLOP_R1036_READONLY=PASS')
    } else {
        [Console]::WriteLine('FLOP_R1027_ALL_WRITERS_FENCED=NO')
        [Console]::WriteLine('FLOP_R1027_OCI_RETIREMENT=STRICT_NO_GO')
        [Console]::WriteLine('FLOP_R1027_READONLY=PASS')
    }
}

if ($args.Count -eq 0) { Invoke-R1027 }
elseif ($args.Count -eq 1 -and $args[0] -ceq '-R1036') { Invoke-R1027 $true }
else { [Console]::WriteLine('FLOP_R1027_STOP=ARGUMENTS_STOP') }
