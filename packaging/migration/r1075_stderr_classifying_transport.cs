// R1075 Windows PowerShell 5.1 read-only SSH carrier with redacted stderr classes.
// Different namespace from R1073 to prevent stale PowerShell 5.1 Add-Type reuse.
// Unlike R1066, when the child exits nonzero before consuming stdin,
// preserve the child's bounded exit code; do NOT recast it as a generic I/O error.
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;
namespace FlopR1075 {
    public sealed class Result {
        public int ExitCode; public byte[] Output;
        // Only a fixed taxonomy; no native stderr text or key path escapes.
        public string FailureKind;
    }
    public static class Transport {
        private static readonly object LaunchLock = new object();
        private static bool Contains(byte[] data, string literal) {
            var value = Encoding.ASCII.GetBytes(literal.ToLowerInvariant());
            try {
                for (int i = 0; i <= data.Length - value.Length; i++) {
                    bool found = true;
                    for (int j = 0; j < value.Length; j++) {
                        int b = data[i + j];
                        if (b >= 65 && b <= 90) b += 32;
                        if (b != value[j]) { found = false; break; }
                    }
                    if (found) return true;
                }
                return false;
            } finally { Array.Clear(value, 0, value.Length); }
        }
        public static string Classify(byte[] stderr) {
            if (stderr == null || stderr.Length == 0 || stderr.Length > 8192)
                return "SSH_UNKNOWN";
            if (Contains(stderr, "bad configuration option") ||
                Contains(stderr, "unsupported option") ||
                Contains(stderr, "bad ssh2") ||
                Contains(stderr, "keyword ") && Contains(stderr, "unknown"))
                return "SSH_OPTION_REJECTED";
            if (Contains(stderr, "host key verification failed") ||
                Contains(stderr, "remote host identification has changed") ||
                Contains(stderr, "no matching host key") ||
                Contains(stderr, "host key is not cached"))
                return "SSH_HOSTKEY_REJECTED";
            if (Contains(stderr, "unprotected private key file") ||
                Contains(stderr, "bad permissions") ||
                Contains(stderr, "invalid format") ||
                Contains(stderr, "error in libcrypto") ||
                Contains(stderr, "identity file") && Contains(stderr, "not accessible") ||
                Contains(stderr, "load key") && Contains(stderr, "invalid"))
                return "SSH_IDENTITY_UNREADABLE";
            if (Contains(stderr, "permission denied (publickey") ||
                Contains(stderr, "no more authentication methods"))
                return "SSH_PUBLIC_KEY_REJECTED";
            if (Contains(stderr, "timed out") ||
                Contains(stderr, "connection refused") ||
                Contains(stderr, "network is unreachable") ||
                Contains(stderr, "no route to host") ||
                Contains(stderr, "could not resolve hostname"))
                return "SSH_CONNECTIVITY_REJECTED";
            if (Contains(stderr, "connection closed") ||
                Contains(stderr, "connection reset") ||
                Contains(stderr, "kex_exchange_identification"))
                return "SSH_REMOTE_CLOSED";
            return "SSH_UNKNOWN";
        }
        // No shell, inherited credentials, unbounded ReadToEnd, stderr disclosure
        // or automatic retries. Caller pins executable, arguments and source.
        public static Result Run(string executable, string arguments, byte[] input, int timeout) {
            if (input.Length > 32768 || timeout < 1 || timeout > 58000) throw new Exception("BOUND");
            var start = new ProcessStartInfo(executable, arguments);
            start.UseShellExecute = false; start.CreateNoWindow = true;
            start.RedirectStandardInput = start.RedirectStandardOutput = start.RedirectStandardError = true;
            start.EnvironmentVariables.Clear();
            start.EnvironmentVariables["SystemRoot"] = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            using (var p = new Process()) using (var output = new MemoryStream()) using (var stderr = new MemoryStream()) {
                p.StartInfo = start;
                int failed = 0, writerFailed = 0; bool started = false;
                Thread writer = null, reader = null, errors = null;
                try {
                    // .NET Framework lacks StandardInputEncoding. Process.Start
                    // initializes an AutoFlush StreamWriter using Console.InputEncoding
                    // and can emit its BOM BEFORE any BaseStream write. Scope a no-BOM
                    // encoding to this one-shot launch and always restore the caller.
                    lock (LaunchLock) {
                        var original = Console.InputEncoding;
                        try { Console.InputEncoding = new UTF8Encoding(false); started = p.Start(); }
                        finally { Console.InputEncoding = original; }
                    }
                    if (!started) throw new Exception("START");
                    writer = new Thread(delegate() {
                        // Close the byte stream, NOT StreamWriter: Close() on
                        // the latter can append a BOM under Windows UTF-8 locale.
                        try { p.StandardInput.BaseStream.Write(input, 0, input.Length); p.StandardInput.BaseStream.Close(); }
                        catch { Interlocked.Exchange(ref writerFailed, 1); }
                    });
                    reader = new Thread(delegate() {
                        byte[] b = new byte[2048]; int n;
                        try { while ((n = p.StandardOutput.BaseStream.Read(b, 0, b.Length)) > 0) {
                            if (output.Length + n > 16384) { Interlocked.Exchange(ref failed, 1); p.Kill(); return; }
                            output.Write(b, 0, n);
                        }} catch { Interlocked.Exchange(ref failed, 1); }
                        finally { Array.Clear(b, 0, b.Length); }
                    });
                    errors = new Thread(delegate() {
                        byte[] b = new byte[2048]; int n, total = 0;
                        try { while ((n = p.StandardError.BaseStream.Read(b, 0, b.Length)) > 0) {
                            total += n; if (total > 65536) { Interlocked.Exchange(ref failed, 1); p.Kill(); return; }
                            if (stderr.Length < 8192) {
                                int available = (int)(8192 - stderr.Length);
                                stderr.Write(b, 0, Math.Min(n, available));
                            }
                        }} catch { Interlocked.Exchange(ref failed, 1); }
                        finally { Array.Clear(b, 0, b.Length); }
                    });
                    writer.IsBackground = reader.IsBackground = errors.IsBackground = true;
                    writer.Start(); reader.Start(); errors.Start();
                    if (!p.WaitForExit(timeout)) throw new Exception("TIMEOUT");
                    if (!writer.Join(2000) || !reader.Join(2000) || !errors.Join(2000) ||
                        failed != 0 || (writerFailed != 0 && p.ExitCode == 0))
                        throw new Exception("IO");
                    byte[] redacted = stderr.ToArray();
                    try {
                        return new Result { ExitCode = p.ExitCode,
                            Output = output.ToArray(),
                            FailureKind = p.ExitCode == 255 ? Classify(redacted) : "SSH_NA" };
                    } finally { Array.Clear(redacted, 0, redacted.Length); }
                } finally {
                    // Clear the bounded diagnostic capture regardless of exit status.
                    if (stderr.Length > 0) {
                        var backing = stderr.GetBuffer();
                        Array.Clear(backing, 0, backing.Length);
                    }
                    if (started && !p.HasExited) { p.Kill(); if (!p.WaitForExit(3000)) throw new Exception("CLEANUP"); }
                    foreach (var t in new[] {writer, reader, errors})
                        if (t != null && t.IsAlive && !t.Join(3000)) throw new Exception("CLEANUP");
                }
            }
        }
    }
}
