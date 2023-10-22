# password-manager

## 開発環境

|Software|Version|
|--|--|
|macOS|Venture 13.5.2|
|Xcode|15.0|
|iOS|17.0|

## コードの開発にあたりやったこと

1. Xcode で　Target に Application Extension の AutoFil Credential Provider を追加する。
2. Signing & Capabilities に AutoFil Credential Provider を追加する。
3. CBORを使うためにライブラリを入れる  
[CBORCoding](https://github.com/SomeRandomiOSDev/CBORCoding)
