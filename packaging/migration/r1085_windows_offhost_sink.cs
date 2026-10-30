// Windows PowerShell 5.1/.NET Framework: R1085 binary ciphertext sink.
// Does not decrypt, invoke SSH, read Oracle, authorize K137 or start services.
using System;
using System.IO;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace FlopR1085 {
public static class Sink {
  const long GIB=1073741824L, MAX_TOTAL=64L*GIB+128L*1024*1024;
  const long MAX_PART=128L*1024*1024+4096;
  const int FRAME_MAX=1048576+8192;
  static readonly SecurityIdentifier Sys=new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null);
  static void Check(bool yes,string why) { if (!yes) throw new InvalidOperationException(why); }
  static byte[] Read(Stream input,int n) {
    Check(n>=0 && n<=FRAME_MAX,"FRAME_BOUND");
    byte[] b=new byte[n]; int at=0;
    while (at<n) { int k=input.Read(b,at,n-at); Check(k>0,"TRUNCATED"); at+=k; }
    return b;
  }
  static long Big64(byte[] b) {
    ulong n=0; for(int i=0;i<8;i++) n=(n<<8)|b[i];
    Check(n<=(ulong)MAX_PART,"FILE_LENGTH"); return (long)n;
  }
  static bool Equal(byte[] x,byte[] y,int offset) {
    if (x.Length!=32 || y.Length<offset+32) return false;
    int diff=0; for(int i=0;i<32;i++) diff|=x[i]^y[offset+i]; return diff==0;
  }
  static SecurityIdentifier Owner() {
    using(var w=WindowsIdentity.GetCurrent()) { Check(w!=null && w.User!=null,"IDENTITY"); return w.User; }
  }
  static void Private(string path,SecurityIdentifier owner) {
    var cursor=new DirectoryInfo(path);
    while(cursor!=null) {
      Check(cursor.Exists && (cursor.Attributes&FileAttributes.ReparsePoint)==0,"REPARSE_PARENT");
      cursor=cursor.Parent;
    }
    var acl=new DirectoryInfo(path).GetAccessControl(AccessControlSections.Owner|AccessControlSections.Access);
    Check(acl.AreAccessRulesProtected &&
      acl.GetOwner(typeof(SecurityIdentifier)).Equals(owner),"OWNER_DACL");
    bool seen=false;
    foreach(FileSystemAccessRule rule in acl.GetAccessRules(true,true,typeof(SecurityIdentifier))) {
      var sid=(SecurityIdentifier)rule.IdentityReference;
      Check(!rule.IsInherited && rule.AccessControlType==AccessControlType.Allow &&
         (sid.Equals(owner)||sid.Equals(Sys)),"UNAPPROVED_ACE");
      if(sid.Equals(owner)) seen=true;
    }
    Check(seen,"OWNER_NOT_ALLOWED");
  }
  static DirectorySecurity FolderAcl(SecurityIdentifier owner) {
    var acl=new DirectorySecurity(); acl.SetOwner(owner); acl.SetAccessRuleProtection(true,false);
    foreach(var id in new[]{owner,Sys})
      acl.AddAccessRule(new FileSystemAccessRule(id,FileSystemRights.FullControl,
        InheritanceFlags.ContainerInherit|InheritanceFlags.ObjectInherit,
        PropagationFlags.None,AccessControlType.Allow));
    return acl;
  }
  static FileSecurity FileAcl(SecurityIdentifier owner) {
    var acl=new FileSecurity(); acl.SetOwner(owner); acl.SetAccessRuleProtection(true,false);
    foreach(var id in new[]{owner,Sys})
      acl.AddAccessRule(new FileSystemAccessRule(id,FileSystemRights.FullControl,AccessControlType.Allow));
    return acl;
  }
  public static void AdmitExistingParent(string parent,long requiredFreeBytes) {
    Check(!String.IsNullOrEmpty(parent)&&Path.IsPathRooted(parent)&&requiredFreeBytes>=0,"PARENT");
    Private(Path.GetFullPath(parent),Owner());
    var drive=new DriveInfo(Path.GetPathRoot(parent));
    Check(drive.IsReady&&drive.DriveFormat=="NTFS","NTFS_ONLY");
    Check(drive.AvailableFreeSpace>=requiredFreeBytes+GIB,"OFFHOST_SPACE");
  }
  public static string Receive(Stream input,string privateParent,string newFolder,long quota) {
    Check(input!=null && input.CanRead,"INPUT");
    Check(!String.IsNullOrEmpty(privateParent) && Path.IsPathRooted(privateParent),"PARENT");
    Check(Regex.IsMatch(newFolder??"", @"\A[a-z0-9][a-z0-9_-]{0,47}\z"),"TARGET");
    Check(quota>=GIB && quota<=MAX_TOTAL,"QUOTA");
    string parent=Path.GetFullPath(privateParent);
    var owner=Owner(); Private(parent,owner);
    var drive=new DriveInfo(Path.GetPathRoot(parent));
    Check(drive.IsReady && drive.DriveFormat=="NTFS","NTFS_ONLY");
    Check(drive.AvailableFreeSpace>=checked(quota+GIB),"OFFHOST_SPACE");
    string target=Path.Combine(parent,newFolder);
    Check(!Directory.Exists(target)&&!File.Exists(target),"NO_OVERWRITE");
    Check(Encoding.ASCII.GetString(Read(input,8))=="FLOPST01","MAGIC");
    Directory.CreateDirectory(target,FolderAcl(owner)); Private(target,owner);
    FileStream output=null; SHA256 hash=null;
    string current=null; long fileBytes=0,received=0;
    int files=0; bool committed=false;
    byte[] data=new byte[65536];
    try {
      while(true) {
        var h=Read(input,5);
        uint size=((uint)h[1]<<24)|((uint)h[2]<<16)|((uint)h[3]<<8)|h[4];
        Check(size<=FRAME_MAX,"FRAME_SIZE");
        char type=(char)h[0];
        if(type=='F') {
          Check(size==0&&output==null&&committed&&files>=3&&files<=258
            &&input.ReadByte()==-1,"FINAL_EOF"); break;
        }
        if(type=='S') {
          Check(output==null&&!committed&&size>0&&size<=32,"START_ORDER");
          string name=Encoding.ASCII.GetString(Read(input,(int)size));
          Check(Regex.IsMatch(name, @"\A(?:header\.bin|commit\.bin|part-[0-9]{4}\.bin)\z"),"NAME");
          string expected=files==0?"header.bin":("part-"+(files-1).ToString("D4")+".bin");
          Check(name==expected||(name=="commit.bin"&&files>=2&&files<=257),"PART_SEQUENCE");
          current=name; committed=name=="commit.bin"; fileBytes=0; files++;
          string path=Path.Combine(target,committed?"commit.bin.pending":name);
          output=new FileStream(path,FileMode.CreateNew,FileAccess.Write,FileShare.None,
                                65536,FileOptions.WriteThrough);
          File.SetAccessControl(path,FileAcl(owner)); hash=SHA256.Create();
        } else if(type=='D') {
          Check(output!=null&&size>0,"DATA_ORDER");
          long cap=current=="header.bin"?52:current=="commit.bin"?262144:MAX_PART;
          Check(fileBytes+size<=cap&&received+size<=quota,"CAPACITY");
          int remain=(int)size;
          while(remain>0) {
            int n=Math.Min(remain,data.Length);
            byte[] b=Read(input,n);
            output.Write(b,0,n);
            hash.TransformBlock(b,0,n,b,0);
            fileBytes+=n; received+=n; remain-=n;
          }
        } else if(type=='E') {
          Check(output!=null&&size==40&&fileBytes>0,"END_ORDER");
          var receipt=Read(input,40);
          hash.TransformFinalBlock(new byte[0],0,0);
          Check(Big64(receipt)==fileBytes&&Equal(hash.Hash,receipt,8),"FILE_SHA");
          output.Flush(true); output.Dispose(); output=null;
          hash.Dispose(); hash=null;
        } else throw new InvalidOperationException("UNKNOWN_FRAME");
      }
      var header=File.ReadAllBytes(Path.Combine(target,"header.bin"));
      Check(header.Length==52&&Encoding.ASCII.GetString(header,0,8)=="FLOPENV1","HEADER");
      string pending=Path.Combine(target,"commit.bin.pending"), final=Path.Combine(target,"commit.bin");
      Check(File.Exists(pending)&&!File.Exists(final),"INCOMPLETE_COMMIT");
      File.Move(pending,final); Private(target,owner);
      return "CIPHERTEXT_ONLY_NOT_AEAD_VERIFIED";
    } finally {
      if(hash!=null) hash.Dispose();
      if(output!=null) output.Dispose();
      Array.Clear(data,0,data.Length);
    }
  }
}
}
