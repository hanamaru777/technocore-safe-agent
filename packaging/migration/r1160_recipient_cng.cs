// Windows .NET Framework / PowerShell 5.1. Recipient encryption key ONLY.
// No approval-key creation/export, source credential access, network or logging.
using System;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
namespace FlopR1160 {
 public static class Recipient {
  static void Need(bool ok) {if(!ok)throw new Exception("R1160_CNG_STOP");}
  static CngProvider Provider = new CngProvider("Microsoft Software Key Storage Provider");
  public static void Validate(CngKey key) {
   Need(key!=null && !key.IsMachineKey && key.AlgorithmGroup==CngAlgorithmGroup.Rsa &&
     key.Provider==Provider && key.ExportPolicy==CngExportPolicies.None && key.KeySize==3072 &&
     (key.KeyUsage & (CngKeyUsages.Decryption|CngKeyUsages.Signing))==(CngKeyUsages.Decryption|CngKeyUsages.Signing));
  }
  static string Name(string id) {Need(id!=null && Regex.IsMatch(id,"\\A[a-f0-9]{32}\\z"));return "FLOP-R1160-"+id;}
  static CngKey Open(string id) {
   var key=CngKey.Open(Name(id),Provider,CngKeyOpenOptions.UserKey);
   try {Validate(key);Need(!key.IsEphemeral);return key;}catch{key.Dispose();throw;}
  }
  public static byte[] Create(string id) {
   string name=Name(id);Need(!CngKey.Exists(name,Provider,CngKeyOpenOptions.UserKey));
   var p=new CngKeyCreationParameters {Provider=Provider,KeyUsage=CngKeyUsages.Decryption|CngKeyUsages.Signing,
     ExportPolicy=CngExportPolicies.None,KeyCreationOptions=CngKeyCreationOptions.None};
   p.Parameters.Add(new CngProperty("Length",BitConverter.GetBytes(3072),CngPropertyOptions.None));
   // Do not delete/recreate on failure; ambiguous setup requires owner review.
   using(var key=CngKey.Create(CngAlgorithm.Rsa,name,p)) {Validate(key);return key.Export(CngKeyBlobFormat.GenericPublicBlob);}
  }
  public static byte[] Public(string id) {using(var key=Open(id)){return key.Export(CngKeyBlobFormat.GenericPublicBlob);}}
  public static byte[] SignRecipient(string id,byte[] data) {
   Need(data!=null && data.Length<=8192);
   using(var key=Open(id))using(var rsa=new RSACng(key)) {return rsa.SignData(data,HashAlgorithmName.SHA256,RSASignaturePadding.Pss);}
  }
  public static byte[] Unwrap(string id,string expectedFingerprint,byte[] ciphertext) {
   Need(ciphertext!=null && ciphertext.Length==384 && expectedFingerprint!=null && Regex.IsMatch(expectedFingerprint,"\\A[a-f0-9]{64}\\z"));
   using(var key=Open(id))using(var sha=SHA256.Create()) {
    byte[] pub=key.Export(CngKeyBlobFormat.GenericPublicBlob);
    string actual=BitConverter.ToString(sha.ComputeHash(pub)).Replace("-","").ToLowerInvariant();
    Need(actual==expectedFingerprint);
    using(var rsa=new RSACng(key)) {byte[] value=rsa.Decrypt(ciphertext,RSAEncryptionPadding.OaepSHA256);
     if(value.Length!=32){Array.Clear(value,0,value.Length);throw new Exception("R1160_CNG_STOP");}return value;}
   }
  }
 }
}
