// R1088: read-only Windows offhost R1001 archive ACL authorization.
// This NEVER opens private keys, decrypts, starts SSH or modifies any object.
using System;
using System.IO;
using System.Linq;
using System.Collections.Generic;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.RegularExpressions;

namespace FlopR1088 {
 public static class Custody {
  static readonly SecurityIdentifier SystemSid =
    new SecurityIdentifier(WellKnownSidType.LocalSystemSid,null);
  static void Need(bool value,string reason) {
   if(!value) throw new InvalidOperationException(reason);
  }
  static SecurityIdentifier Owner() {
   using(var identity=WindowsIdentity.GetCurrent()) {
    Need(identity!=null && identity.User!=null,"IDENTITY_STOP");
    return identity.User;
   }
  }
  static void DirsNoReparse(string path) {
   var d=new DirectoryInfo(path);
   while(d!=null) {
    Need(d.Exists&&(d.Attributes&FileAttributes.ReparsePoint)==0,"REPARSE_STOP");
    d=d.Parent;
   }
  }
  static void Rules(AuthorizationRuleCollection rules,SecurityIdentifier user) {
   bool found=false;
   foreach(FileSystemAccessRule rule in rules) {
    SecurityIdentifier sid=(SecurityIdentifier)rule.IdentityReference;
    Need(rule.AccessControlType==AccessControlType.Allow && !rule.IsInherited &&
      (sid.Equals(user)||sid.Equals(SystemSid)),"UNAUTHORIZED_ACE_STOP");
    if(sid.Equals(user)) found=true;
   }
   Need(found,"USER_NOT_ALLOWED");
  }
  static void DirectoryAcl(string path,SecurityIdentifier user) {
   DirectorySecurity d=new DirectoryInfo(path).GetAccessControl(
    AccessControlSections.Owner|AccessControlSections.Access);
   Need(d.AreAccessRulesProtected &&
    d.GetOwner(typeof(SecurityIdentifier)).Equals(user),"DIR_ACL_STOP");
   Rules(d.GetAccessRules(true,true,typeof(SecurityIdentifier)),user);
  }
  static void FileAcl(string path,SecurityIdentifier user) {
   FileSecurity f=new FileInfo(path).GetAccessControl(
    AccessControlSections.Owner|AccessControlSections.Access);
   Need(f.AreAccessRulesProtected &&
    f.GetOwner(typeof(SecurityIdentifier)).Equals(user),"FILE_ACL_STOP");
   Rules(f.GetAccessRules(true,true,typeof(SecurityIdentifier)),user);
  }
  public static string Validate(string archive) {
   Need(!String.IsNullOrEmpty(archive)&&Path.IsPathRooted(archive),"ROOT_STOP");
   string root=Path.GetFullPath(archive);
   Need(Directory.Exists(root),"ARCHIVE_NOT_PRESENT");
   DirsNoReparse(root);
   var drive=new DriveInfo(Path.GetPathRoot(root));
   Need(drive.IsReady && drive.DriveFormat=="NTFS","NTFS_ONLY");
   SecurityIdentifier current=Owner();
   DirectoryAcl(root,current);
   string[] dirs=Directory.GetDirectories(root);
   Need(dirs.Length==0,"UNEXPECTED_DIR_STOP");
   string[] files=Directory.GetFiles(root);
   Need(files.Length>=3&&files.Length<=258,"FILE_COUNT_STOP");
   HashSet<string> names=new HashSet<string>(StringComparer.Ordinal);
   foreach(string path in files) {
    var info=new FileInfo(path);
    Need(info.Exists && (info.Attributes&(FileAttributes.ReparsePoint|
       FileAttributes.Directory|FileAttributes.Device))==0,
       "FILE_REPARSE_STOP");
    Need(info.Length>0 && info.Length<=128L*1024*1024+4096,
       "FILE_SIZE_STOP");
    FileAcl(path,current);
    names.Add(info.Name);
   }
   Need(names.Count==files.Length && names.Contains("header.bin") &&
    names.Contains("commit.bin") && !names.Contains("commit.bin.pending"),
    "FILE_SEQUENCE_STOP");
   Need(new FileInfo(Path.Combine(root,"header.bin")).Length==52,"HEADER_SIZE_STOP");
   Need(new FileInfo(Path.Combine(root,"commit.bin")).Length<=262144,"COMMIT_SIZE_STOP");
   int partCount=files.Length-2;
   Need(partCount>=1&&partCount<=256,"SHARD_COUNT_STOP");
   for(int i=0;i<partCount;i++)
    Need(names.Contains("part-"+i.ToString("D4")+".bin"),"SHARD_SEQUENCE_STOP");
   return "NTFS_PRIVATE_CIPHERTEXT_ARCHIVE";
  }
 }
}
