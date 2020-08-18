--if(not FileLoaded()) then CreateProcess('C:\\Games\\Call of Duty Modern Warfare\\ModernWarfare.exe') Sleep(2000) local p = FindProcess('modernwarfare.exe') if p > 0 then Attach(p) Log('pid '..p) else Log('bad pid') return end
if(not FileLoaded()) then LoadFile('C:\\Games\\Call of Duty Modern Warfare\\ModernWarfare_dump 17-08.exe')
else ResetDbg() end

--entities
local r = DoScan('41 81 F8 FE 07 00 00 72')
Log(string.format('ENC_PTR: 0x%X',ReadDword(r+0x25)))
--Log(string.format('Scan Result: %x',r-GetBase()))
Decode(GetBase()+r,function(rip,it)
	r = rip
if it.mnemonic == 304 then return false end--jz
return true
end)
--get 2 previous inst
--find test and not
local ret_r = 0
local peb_r = 0
Decode(r-3,function(rip,it)
ret_r=it.reg_0
end)
Decode(r-6,function(rip,it)
peb_r=it.reg_0
end)
print(string.format('%i / %i - %i / %i',ret_r,peb_r,RAX,RBX))
--find jump..
Decode(r,function(rip,it)
	r = rip
if it.mnemonic == 291 then r = r + it.length return false end--jmp
return true
end)

SetRva(r-GetBase())

SetAlias(ret_r,'ret')
SetAlias(peb_r,'not_peb')
StepOver(180)

local t = Track(ret_r)
Log('Entities Dump {') Log(t:dump('entities')) Log('}')
--if 1 ==1 then return end
--bones
ResetDbg()

local r = DoScan('0F BF B4 59')
Log(string.format('ENC_PTR: 0x%X',r+0x13+ReadDword(r+0x16)+7))
--Log(string.format('Scan Result: %x',r-GetBase()))
SetRva(r)
SetRva(0x13C9975)
SetAlias(RDX,'ret')
SetAlias(R11,'not_peb')
StepOver(124)

local t = Track(RDX)
Log('Bones Dump {') Log(t:dump('bones')) Log('}')

--if 1 ==1 then return end
ResetDbg()
--client_info
local r = 0x13D939D-0x23
Log(string.format('ENC_PTR: 0x%X',r+ReadDword(r+3)+7))
SetRva(0x13D939D)
SetAlias(RBX,'ret')
SetAlias(RDX,'not_peb')
StepOver(24)

local t = Track(RBX)
Log('ClientInfo Dump {') Log(t:dump('client_info')) Log('}')

--if 1==1 then return end
ResetDbg()

--client_info_base
local r = DoScan('0F B6 4C 24 40 48 C1 C9 0C 83 E1 0F 48 83 F9 0E')
local r2 = r-0x27
Log(string.format('ENC_PTR: 0x%X',ReadDword(r2+3)))

local iSkip = 0
Decode(GetBase()+r,function(rip,it)
	iSkip=iSkip+1 r = rip return iSkip<10
end)
--Log(string.format('Scan Result: %x',r-GetBase()))
SetRva(r-GetBase())
SetAlias(RAX,'ret')
StepOver(180)
--local c = GetContext()
--Log(string.format('Hi! %x',c.rip))
local t = Track(RAX)
--Log(string.format('RAX Track! %x',t.rva))
Log('ClientInfoBase Dump {') Log(t:dump('client_info_base')) Log('}')