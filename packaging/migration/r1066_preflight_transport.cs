// Windows .NET Framework / PowerShell 5.1. Bounded binary read-only probe carrier.
using System;
using System.Diagnostics;
using System.IO;
using System.Threading;
namespace FlopR1066 {
    public sealed class Result { public int ExitCode; public byte[] Output; }
    public static class Transport {
        // No shell, inherited credentials, unbounded ReadToEnd, stderr disclosure
        // or automatic retries. Caller pins executable, arguments and source.
        public static Result Run(string executable, string arguments, byte[] input, int timeout) {
            if (input.Length > 32768 || timeout < 1 || timeout > 58000) throw new Exception("BOUND");
            var start = new ProcessStartInfo(executable, arguments);
            start.UseShellExecute = false; start.CreateNoWindow = true;
            start.RedirectStandardInput = start.RedirectStandardOutput = start.RedirectStandardError = true;
            start.EnvironmentVariables.Clear();
            start.EnvironmentVariables["SystemRoot"] = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            using (var p = new Process()) using (var output = new MemoryStream()) {
                p.StartInfo = start;
                int failed = 0; bool started = false;
                Thread writer = null, reader = null, errors = null;
                try {
                    started = p.Start(); if (!started) throw new Exception("START");
                    writer = new Thread(delegate() {
                        try { p.StandardInput.BaseStream.Write(input, 0, input.Length); p.StandardInput.Close(); }
                        catch { Interlocked.Exchange(ref failed, 1); }
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
                        }} catch { Interlocked.Exchange(ref failed, 1); }
                        finally { Array.Clear(b, 0, b.Length); }
                    });
                    writer.IsBackground = reader.IsBackground = errors.IsBackground = true;
                    writer.Start(); reader.Start(); errors.Start();
                    if (!p.WaitForExit(timeout)) throw new Exception("TIMEOUT");
                    if (!writer.Join(2000) || !reader.Join(2000) || !errors.Join(2000) || failed != 0)
                        throw new Exception("IO");
                    return new Result { ExitCode = p.ExitCode, Output = output.ToArray() };
                } finally {
                    if (started && !p.HasExited) { p.Kill(); if (!p.WaitForExit(3000)) throw new Exception("CLEANUP"); }
                    foreach (var t in new[] {writer, reader, errors})
                        if (t != null && t.IsAlive && !t.Join(3000)) throw new Exception("CLEANUP");
                }
            }
        }
    }
}
