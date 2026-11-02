// R1151 framing/journal primitives only. No process, network, key lookup or log.
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace FlopR1151 {
 public static class Control {
  static void Need(bool value,string code) {if(!value)throw new InvalidOperationException(code);}
  static void Number(Stream output,int value) {
   output.WriteByte((byte)(value>>24));output.WriteByte((byte)(value>>16));
   output.WriteByte((byte)(value>>8));output.WriteByte((byte)value);
  }
  public static byte[] Frame(byte[] publicRequest,SecureString recovery) {
   IntPtr ptr=IntPtr.Zero;char[] chars=null;byte[] bytes=null;
   try {
    Need(publicRequest!=null && publicRequest.Length>0 && publicRequest.Length<=1048576,"CONTROL_BOUND_STOP");
    Need(recovery!=null && recovery.Length>=1 && recovery.Length<=1024,"INDEPENDENT_RECOVERY_STOP");
    ptr=Marshal.SecureStringToBSTR(recovery);chars=new char[recovery.Length];
    Marshal.Copy(ptr,chars,0,chars.Length);bytes=new UTF8Encoding(false,true).GetBytes(chars);
    Need(bytes.Length>=32 && bytes.Length<=1024,"INDEPENDENT_RECOVERY_STOP");
    using(var stream=new MemoryStream()) {
     try {
      byte[] magic=Encoding.ASCII.GetBytes("R1151S01");stream.Write(magic,0,magic.Length);
      Number(stream,publicRequest.Length);stream.Write(publicRequest,0,publicRequest.Length);
      Number(stream,bytes.Length);stream.Write(bytes,0,bytes.Length);
      return stream.ToArray();
     } finally {Array.Clear(stream.GetBuffer(),0,(int)stream.Length);}
    }
   } finally {
    if(ptr!=IntPtr.Zero)Marshal.ZeroFreeBSTR(ptr);
    if(chars!=null)Array.Clear(chars,0,chars.Length);
    if(bytes!=null)Array.Clear(bytes,0,bytes.Length);
   }
  }
  static void PrivateDirectory(string root) {
   Need(Environment.OSVersion.Platform==PlatformID.Win32NT && Path.IsPathRooted(root) && Directory.Exists(root),"JOURNAL_SCOPE_STOP");
   for(DirectoryInfo dir=new DirectoryInfo(root);dir!=null;dir=dir.Parent)
    Need((dir.Attributes&FileAttributes.ReparsePoint)==0,"JOURNAL_LINK_STOP");
   var sid=WindowsIdentity.GetCurrent().User;
   var acl=Directory.GetAccessControl(root);
   Need(acl.AreAccessRulesProtected && acl.GetOwner(typeof(SecurityIdentifier)).Equals(sid),"JOURNAL_CUSTODY_STOP");
   bool own=false;
   foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier))) {
    string id=rule.IdentityReference.Value;
    Need(!rule.IsInherited && rule.AccessControlType==AccessControlType.Allow &&
         (id==sid.Value || id=="S-1-5-18"),"JOURNAL_CUSTODY_STOP");
    if(id==sid.Value)own=true;
   }
   Need(own,"JOURNAL_CUSTODY_STOP");
  }
  public static void Reserve(string root,string archiveId,string bindingDigest) {
   Need(archiveId!=null && Regex.IsMatch(archiveId,"\\A[0-9a-f]{32}\\z") &&
        bindingDigest!=null && Regex.IsMatch(bindingDigest,"\\A[0-9a-f]{64}\\z"),"JOURNAL_BINDING_STOP");
   PrivateDirectory(root);
   string path=Path.Combine(root,"r1151-"+archiveId+".unknown.json");
   var acl=new FileSecurity();var sid=WindowsIdentity.GetCurrent().User;
   acl.SetOwner(sid);acl.SetAccessRuleProtection(true,false);
   foreach(var id in new SecurityIdentifier[]{sid,new SecurityIdentifier("S-1-5-18")})
    acl.AddAccessRule(new FileSystemAccessRule(id,FileSystemRights.FullControl,AccessControlType.Allow));
   // Exclusive creation is the attempt fence; never overwrite/remove/retry.
   using(var file=new FileStream(path,FileMode.CreateNew,FileSystemRights.FullControl,
                                FileShare.None,4096,FileOptions.WriteThrough,acl)) {
    byte[] data=Encoding.ASCII.GetBytes("{\"phase\":\"R1151\",\"state\":\"UNKNOWN_POST\",\"binding_sha256\":\""+bindingDigest+"\"}");
    try {file.Write(data,0,data.Length);file.Flush(true);}finally{Array.Clear(data,0,data.Length);}
   }
  }
 }
}
