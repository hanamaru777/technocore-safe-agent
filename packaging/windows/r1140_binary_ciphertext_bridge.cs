// R1140 Windows PS5.1 internal binary bridge; no SSH endpoint or credentials.
// EXACT owner/host/source/destination enrollment MUST be done by audited caller.
// No standalone CLI, no disk writes, no trust enrollment, no network in tests.
using System;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace FlopR1140 {
  public sealed class Result {
    public byte[] RecipientReport;
    public long ForwardedBytes;
    public int SourceExit;
    public int RecipientExit;
  }
  public static class Bridge {
    const int WireLimit = 32 * 1024 * 1024;
    const int SourceControlLimit = 4 * 1024 * 1024;
    const int RecipientReportLimit = 4096;
    const int Chunk = 65536;
    const int StderrLimit = 65536;
    static readonly byte[] Magic = Encoding.ASCII.GetBytes("FLOPST01");
    // In .NET Framework / PowerShell 5.1, Process.Start can initialize
    // StandardInput with a UTF-8 BOM BEFORE callers access BaseStream.
    // Mirror accepted R1079's narrowly scoped, no-BOM launch policy.
    static readonly object LaunchLock = new object();
    static bool StartNoBom(Process process) {
      lock (LaunchLock) {
        Encoding previous = Console.InputEncoding;
        try {
          Console.InputEncoding = new UTF8Encoding(false);
          return process.Start();
        } finally {
          Console.InputEncoding = previous;
        }
      }
    }

    static void Need(bool valid, string reason) {
      if (!valid) throw new InvalidOperationException(reason);
    }
    static void Kill(Process p) {
      if (p == null) return;
      try { if (!p.HasExited) p.Kill(); } catch (Exception) { }
    }
    static ProcessStartInfo Program(string executable, string arguments) {
      Need(Environment.OSVersion.Platform == PlatformID.Win32NT,
           "WINDOWS_REQUIRED");
      Need(!String.IsNullOrEmpty(executable) && Path.IsPathRooted(executable)
           && File.Exists(executable) && arguments != null &&
           arguments.Length <= 32768 && arguments.IndexOf('\0') < 0,
           "PINNED_PROCESS_REQUIRED");
      ProcessStartInfo start = new ProcessStartInfo(executable, arguments);
      start.CreateNoWindow = true;
      start.UseShellExecute = false;
      start.RedirectStandardInput = true;
      start.RedirectStandardOutput = true;
      start.RedirectStandardError = true;
      start.EnvironmentVariables.Clear();
      string systemRoot = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
      string programData = Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
      Need(Directory.Exists(systemRoot) && Directory.Exists(programData),
           "WINDOWS_PROFILE_STOP");
      start.EnvironmentVariables["SystemRoot"] = systemRoot;
      start.EnvironmentVariables["ProgramData"] = programData;
      return start;
    }
    static Thread StartDrain(Process process, Action<string> failed) {
      Thread thread = new Thread(delegate() {
        byte[] buffer = new byte[2048]; int total = 0;
        try {
          Stream stream = process.StandardError.BaseStream; int read;
          while ((read = stream.Read(buffer, 0, buffer.Length)) > 0) {
            total += read;
            if (total > StderrLimit) {
              failed("STDERR_LIMIT_STOP"); Kill(process); return;
            }
          }
        } catch(Exception) { failed("STDERR_IO_STOP"); }
        finally { Array.Clear(buffer, 0, buffer.Length); }
      });
      thread.IsBackground = true;
      thread.Start();
      return thread;
    }
    static Thread StartRecipientReader(Process process, MemoryStream report,
                                       Action<string> failed) {
      Thread thread = new Thread(delegate() {
        byte[] buffer = new byte[512];
        try {
          int read;
          while ((read = process.StandardOutput.BaseStream.Read(buffer, 0,
                   buffer.Length)) > 0) {
            if (report.Length + read > RecipientReportLimit) {
              failed("RECIPIENT_REPORT_BOUND_STOP"); Kill(process); return;
            }
            report.Write(buffer, 0, read);
          }
        } catch(Exception) { failed("RECIPIENT_REPORT_IO_STOP"); }
        finally { Array.Clear(buffer, 0, buffer.Length); }
      });
      thread.IsBackground = true;
      thread.Start();
      return thread;
    }
    // Returned raw recipient bytes are UNTRUSTED; caller MUST validate strict
    // non-authoritative R1129 result BEFORE displaying/accepting a receipt.
    // This component never claims authenticated source, AEAD, or cutover.
    public static Result Pump(string sourceExe, string sourceArgs,
                              string recipientExe, string recipientArgs,
                              byte[] sourceRequest, int timeoutMillis) {
      if (sourceRequest == null) throw new InvalidOperationException("BOUND_STOP");
      if (sourceRequest.Length > SourceControlLimit ||
          timeoutMillis < 1000 || timeoutMillis > 180000) {
        Array.Clear(sourceRequest,0,sourceRequest.Length);
        throw new InvalidOperationException("BOUND_STOP");
      }
      Process source = null, recipient = null;
      Thread inputThread = null, fromErr = null, toErr = null, toOut = null;
      Timer timeout = null;
      int timedOut = 0, failed = 0;
      string failure = "TRANSFER_STOP";
      long forwarded = 0;
      MemoryStream report = new MemoryStream();
      byte[] buffer = new byte[Chunk];
      byte[] prefix = new byte[Magic.Length];
      Action<string> fail = delegate(string reason) {
        failure = reason;
        Interlocked.Exchange(ref failed, 1);
      };
      try {
        ProcessStartInfo sourceStart = Program(sourceExe, sourceArgs);
        ProcessStartInfo recipientStart = Program(recipientExe, recipientArgs);
        recipient = new Process(); recipient.StartInfo = recipientStart;
        Need(StartNoBom(recipient), "RECIPIENT_LAUNCH_STOP");
        source = new Process(); source.StartInfo = sourceStart;
        Need(StartNoBom(source), "SOURCE_LAUNCH_STOP");
        Process aliveSource = source, aliveRecipient = recipient;
        timeout = new Timer(delegate(object ignored) {
          Interlocked.Exchange(ref timedOut, 1);
          Kill(aliveSource); Kill(aliveRecipient);
        }, null, timeoutMillis, Timeout.Infinite);
        fromErr = StartDrain(source, fail);
        toErr = StartDrain(recipient, fail);
        toOut = StartRecipientReader(recipient, report, fail);
        inputThread = new Thread(delegate() {
          try {
            source.StandardInput.BaseStream.Write(sourceRequest, 0, sourceRequest.Length);
            source.StandardInput.BaseStream.Close();
          } catch(Exception) { fail("SOURCE_CONTROL_IO_STOP"); }
        });
        inputThread.IsBackground = true;
        inputThread.Start();
        int offset=0, read;
        while (offset < prefix.Length) {
          read = source.StandardOutput.BaseStream.Read(prefix,offset,prefix.Length-offset);
          Need(read > 0, "SOURCE_MAGIC_STOP");
          offset += read;
        }
        for(int i=0;i<Magic.Length;i++)
          Need(prefix[i] == Magic[i], "SOURCE_MAGIC_STOP");
        recipient.StandardInput.BaseStream.Write(prefix,0,prefix.Length);
        forwarded = prefix.Length;
        while ((read=source.StandardOutput.BaseStream.Read(buffer,0,buffer.Length)) > 0) {
          forwarded += read;
          Need(forwarded <= WireLimit, "WIRE_LIMIT_STOP");
          Need(Interlocked.CompareExchange(ref timedOut,0,0) == 0,
               "TIME_LIMIT_STOP");
          recipient.StandardInput.BaseStream.Write(buffer,0,read);
        }
        recipient.StandardInput.BaseStream.Close();
        Need(source.WaitForExit(3000) && recipient.WaitForExit(3000),
             "CHILD_TIMEOUT_STOP");
        Need(inputThread.Join(3000) && toErr.Join(3000) &&
             fromErr.Join(3000) && toOut.Join(3000), "THREAD_TIMEOUT_STOP");
        Need(Interlocked.CompareExchange(ref timedOut,0,0)==0 &&
             Interlocked.CompareExchange(ref failed,0,0)==0,
             failure);
        Need(source.ExitCode == 0 && recipient.ExitCode == 0,
             "CHILD_EXIT_STOP");
        Need(report.Length > 0 && report.Length <= RecipientReportLimit,
             "RECIPIENT_REPORT_STOP");
        return new Result {
          RecipientReport = report.ToArray(), ForwardedBytes = forwarded,
          SourceExit = source.ExitCode, RecipientExit = recipient.ExitCode
        };
      } finally {
        if (timeout != null) timeout.Dispose();
        Kill(source); Kill(recipient);
        foreach(Thread t in new Thread[]{inputThread,fromErr,toErr,toOut}) {
          if (t != null && t.IsAlive) t.Join(3000);
        }
        if (source != null) source.Dispose();
        if (recipient != null) recipient.Dispose();
        Array.Clear(sourceRequest,0,sourceRequest.Length);
        Array.Clear(buffer,0,buffer.Length);
        Array.Clear(prefix,0,prefix.Length);
        if(report.Length > 0) {
          byte[] backing=report.GetBuffer();
          Array.Clear(backing,0,backing.Length);
        }
        report.Dispose();
      }
    }
  }
}
