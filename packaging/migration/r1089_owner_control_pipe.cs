// PowerShell 5.1: binary owner-control pipe. No secrets in argv/env/disk/logs.
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Threading;
namespace FlopR1089 {
 public sealed class Result { public int ExitCode; public byte[] Output; }
 public static class OwnerPipe {
  [StructLayout(LayoutKind.Sequential)] struct Limits {
   public long ProcessTime,JobTime;public uint Flags;public UIntPtr Minimum,Maximum;
   public uint Processes;public UIntPtr Affinity;public uint Priority,Scheduling;
  }
  [StructLayout(LayoutKind.Sequential)] struct Counters {public ulong A,B,C,D,E,F;}
  [StructLayout(LayoutKind.Sequential)] struct Extended {
   public Limits Basic;public Counters Io;public UIntPtr ProcessMemory,JobMemory,PeakProcess,PeakJob;
  }
  [DllImport("kernel32.dll",CharSet=CharSet.Unicode)] static extern IntPtr CreateJobObject(IntPtr attributes,string name);
  [DllImport("kernel32.dll")] static extern bool SetInformationJobObject(IntPtr job,int kind,ref Extended info,uint size);
  [DllImport("kernel32.dll")] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
  static readonly object LaunchLock=new object();
  public static Result Run(string python,string args,byte[] control,SecureString recovery,int timeout) {
   if(control==null||control.Length>4194304||timeout<1||timeout>14400000) throw new Exception("BOUND");
   var info=new ProcessStartInfo(python,args);
   info.UseShellExecute=false;info.CreateNoWindow=true;
   info.RedirectStandardInput=info.RedirectStandardOutput=info.RedirectStandardError=true;
   info.EnvironmentVariables.Clear();
   info.EnvironmentVariables["SystemRoot"]=Environment.GetFolderPath(Environment.SpecialFolder.Windows);
   info.EnvironmentVariables["ProgramData"]=Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData);
   var temporary=Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),"Temp");
   if(!Directory.Exists(temporary)||(File.GetAttributes(temporary)&FileAttributes.ReparsePoint)!=0)throw new Exception("TEMP");
   info.EnvironmentVariables["TEMP"]=info.EnvironmentVariables["TMP"]=temporary;
   using(var p=new Process()) using(var output=new MemoryStream()) {
    p.StartInfo=info;bool started=false;int failed=0;IntPtr job=IntPtr.Zero;
    Thread writer=null,reader=null,errors=null;
    try {
     job=CreateJobObject(IntPtr.Zero,null);
     var limits=new Extended();limits.Basic.Flags=0x2000; // KILL_ON_JOB_CLOSE
     if(job==IntPtr.Zero||!SetInformationJobObject(job,9,ref limits,(uint)Marshal.SizeOf(typeof(Extended))))throw new Exception("JOB");
     lock(LaunchLock) {var before=Console.InputEncoding;
      try {Console.InputEncoding=new UTF8Encoding(false);started=p.Start();}
      finally {Console.InputEncoding=before;}}
     if(!started) throw new Exception("START");
     // The trusted owner interpreter waits for our control bytes before it
     // creates any descendant. Enrol the whole process tree BEFORE input.
     if(!AssignProcessToJobObject(job,p.Handle))throw new Exception("JOB");
     writer=new Thread(delegate(){
      byte[] material=null;char[] chars=null;IntPtr pointer=IntPtr.Zero;
      try {
       var stream=p.StandardInput.BaseStream;
       stream.Write(Encoding.ASCII.GetBytes("FLOPR189"),0,8);
       byte[] size=BitConverter.GetBytes(control.Length);if(BitConverter.IsLittleEndian)Array.Reverse(size);
       stream.Write(size,0,4);stream.Write(control,0,control.Length);
       if(recovery!=null) {
        pointer=Marshal.SecureStringToBSTR(recovery);
        int count=Marshal.ReadInt32(pointer,-4)/2;
        if(count<1||count>1024)throw new Exception("RECOVERY");
        chars=new char[count];Marshal.Copy(pointer,chars,0,count);
        material=Encoding.UTF8.GetBytes(chars);
        if(material.Length<32||material.Length>1024)throw new Exception("RECOVERY");
        size=BitConverter.GetBytes(material.Length);if(BitConverter.IsLittleEndian)Array.Reverse(size);
        stream.Write(size,0,4);stream.Write(material,0,material.Length);
       }
       stream.Close();
      } catch {Interlocked.Exchange(ref failed,1);try{p.Kill();}catch{}}
      finally {
       if(material!=null)Array.Clear(material,0,material.Length);
       if(chars!=null)Array.Clear(chars,0,chars.Length);
       if(pointer!=IntPtr.Zero)Marshal.ZeroFreeBSTR(pointer);
      }
     });
     reader=new Thread(delegate(){
      byte[] b=new byte[2048];int n;
      try {while((n=p.StandardOutput.BaseStream.Read(b,0,b.Length))>0){
       if(output.Length+n>65536){Interlocked.Exchange(ref failed,1);p.Kill();return;}
       output.Write(b,0,n);
      }}catch{Interlocked.Exchange(ref failed,1);}finally{Array.Clear(b,0,b.Length);}
     });
     errors=new Thread(delegate(){
      byte[] b=new byte[2048];int n,total=0;
      try {while((n=p.StandardError.BaseStream.Read(b,0,b.Length))>0){
       total+=n;if(total>65536){Interlocked.Exchange(ref failed,1);p.Kill();return;}
      }}catch{Interlocked.Exchange(ref failed,1);}finally{Array.Clear(b,0,b.Length);}
     });
     writer.IsBackground=reader.IsBackground=errors.IsBackground=true;
     writer.Start();reader.Start();errors.Start();
     if(!p.WaitForExit(timeout))throw new Exception("TIMEOUT");
     if(!writer.Join(3000)||!reader.Join(3000)||!errors.Join(3000)||failed!=0)throw new Exception("IO");
     return new Result{ExitCode=p.ExitCode,Output=output.ToArray()};
    } finally {
     if(job!=IntPtr.Zero){if(!CloseHandle(job))throw new Exception("CLEANUP");job=IntPtr.Zero;}
     if(started&&!p.HasExited){p.Kill();if(!p.WaitForExit(3000))throw new Exception("CLEANUP");}
     foreach(var t in new[]{writer,reader,errors})if(t!=null&&t.IsAlive&&!t.Join(3000))throw new Exception("CLEANUP");
    }
   }
  }
 }
}
