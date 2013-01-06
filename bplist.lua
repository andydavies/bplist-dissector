-- bplist.lua
--
-- Wireshark  dissector for Apple bplist protocol used by Safari Remote Debugging
--
-- Copyright (C) 2013 Andy Davies (hello@andydavies.me)
--
-- Example usage
--  tshark -X lua_script:bplist.lua -i lo0 -f "tcp port 27753" -O bplist -V
--
-- Heavily influenced by
--   http://delog.wordpress.com/2010/09/27/create-a-wireshark-dissector-in-lua/
--   http://opensource.apple.com/source/CF/CF-550/CFBinaryPList.c
--   https://github.com/nearinfinity/node-bplist-parser
--   http://code.google.com/p/plist/
--
-- This program is free software: you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation, either version 3 of the License, or
-- (at your option) any later version.
-- 
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
-- 
-- You should have received a copy of the GNU General Public License
-- along with this program.  If not, see <http://www.gnu.org/licenses/>.

do

  p_bplist = Proto ("bplist", "Apple Binary Plist")

  local f_offsetSize = ProtoField.uint8("bplist.offsetSize", "offsetSize", base.DEC)
  local f_objectRefSize = ProtoField.uint8("bplist.objectRefSize", "objectRefSize", base.DEC)
  local f_numObjects = ProtoField.uint64("bplist.numObjects", "numObjects", base.DEC)
  local f_topObject = ProtoField.uint64("bplist.topObject", "topObject", base.DEC)
  local f_offsetTableOffset = ProtoField.uint64("bplist.offsetTableOffset", "offsetTableOffset", base.DEC)
  local f_data = ProtoField.string("bplist.data", "data")

  p_bplist.fields = {f_offsetSize, f_objectRefSize, f_numObjects, f_topObject, f_offsetTableOffset, f_data}

  local offsetTable = {}
  local offsetSize = 0
  local objectRefSize = 0
  local numObjects = 0
  local topObject = 0
  local offsetTableOffset = 0

  local buffer 

  -- myproto dissector function
  function p_bplist.dissector(buf, pkt, root)  

    -- Check buffer length, otheriwse quit
    if buf:len() < 6 then return end

    -- Check for magic number, otherwise quit
    local magic_number = buf(0,6):string()
    if magic_number ~= "bplist" then return end
    
--    print(buf():string())

    pkt.cols.protocol = p_bplist.name

    -- create subtree for myproto
    subtree = root:add(p_bplist, buf(0))

    -- add protocol fields to subtree
    -- trailer is last 32 bytes of data
    local trailer = buf:len() - 32

    offsetSize = buf(trailer + 6, 1):uint()
    objectRefSize = buf(trailer + 7, 1):uint()
    numObjects = tonumber(tostring(buf(trailer + 8, 8):uint64()))
    topObject = tonumber(tostring(buf(trailer + 16, 8):uint64()))
    offsetTableOffset = tonumber(tostring(buf(trailer + 24, 8):uint64()))

--    subtree:add(f_offsetSize, offsetSize)
--    subtree:add(f_objectRefSize, objectRefSize)
--    subtree:add(f_numObjects, numObjects)
--    subtree:add(f_topObject, topObject)
--    subtree:add(f_offsetTableOffset, offsetTableOffset)

--    subtree:add(f_data, buf(0):string())

    buffer = buf
--    print(buf)
--    print(buffer)
    
--    offsetTable = {}
    for i = 0, numObjects, 1 do
      local offsetBytes = buf(offsetTableOffset + i * offsetSize, offsetSize):uint();
      offsetTable[i] = offsetBytes;
--      print("Offset for Object #", i, " is ", offsetBytes) --, " [", offsetTable[i]:string(), "]");

--      print("type: ", buf(offsetBytes, 1):uint())
--      print(parseObject(i))

    end

    local t = parseObject(topObject)
--    print("table.maxn(t)", table.maxn(t))
--    print("===== =====")
    table_print(t, 4)

  end

  function table_print (tt, indent, done)
    done = done or {}
    indent = indent or 0
    if type(tt) == "table" then
      for key, value in pairs (tt) do
--        print(string.rep (" ", indent)) -- indent it
        if type (value) == "table" then
          print(string.format("%s: ", tostring (key)));
--          print(string.rep (" ", indent+4)) -- indent it
          print("{");
          table_print (value, indent + 7, done)
--          print(string.rep (" ", indent+4)) -- indent it
          print("}");
        else
          print(string.format("%s: %s", tostring (key), tostring(value)))
        end
      end
    else
      print(tt)
    end
  end

  function parseObject(tableOffset)

    local startPos = offsetTable[tableOffset];
--    print("tableOffset: ", tableOffset)
--    print("startPos: ", startPos)
  
--    if(startPos > buffer:len() - 1) then
--      print("Error - startPos > buffer:len()", startPos)
--    end

  -- each table entry starts with single byte header, indicating type and extra info
    local type = buffer(startPos, 1):uint()

    local objType = bit.rshift(type, 4) 
    local objInfo = bit.band(type, 0x0F)
--    print("type: ", type)
--    print("objType", objType)
--    print("objInfo", objInfo)

-- null
    if objType == 0x0 and objInfo == 0x0 then -- null
--          print("===== null =====")
      return nil

-- false          
    elseif objType == 0x0 and objInfo == 0x8 then -- false
--          print("===== false =====")
      return false

-- true          
    elseif objType == 0x0 and objInfo == 0x9 then -- true
--          print("===== true =====")
      return true

-- filler          
    elseif objType == 0x0 and objInfo == 0xF then -- filler byte
--          print("===== null =====")
      return nil

-- integer
-- UID
    elseif objType == 0x1 or
           objType == 0x8 then
      local length = 2 ^ objInfo
--      print("===== integer ===== ", buffer(startPos + 1, length):uint())

      return buffer(startPos + 1, length):uint()

-- real        
    elseif objType == 0x2 then -- real
      local length = 2 ^ objInfo
--      print("===== real ===== ", buffer(startPos + 1, length):float())

      return buffer(startPos + 1, length):float()

-- date        
    elseif objType == 0x3 then -- date
      if (objInfo ~= 0x3) then
          print("Error: Unknown date type :", objInfo)
      end
--      print("===== date ===== ", buffer(startPos + 1, 8):float()) -- TODO: Format correctly
    return buffer(startPos + 1, 8):float() -- TODO: Format correctly

-- data        
    elseif objType == 0x4 then -- data
      local length = objInfo
      local dataOffset = 1
      if(objInfo == 0xF) then -- 1111
        local int_type = buffer(startPos + 1, 1):int()
        local intType = bit.band(int_type, 0xF0) / 0x10;
        if intType ~= 0x1 then
          print("Error : 0x4 Unexpected length - int-type", intType)
        end
        intInfo = bit.band(int_type, 0x0F)
        intLength = 2 ^ intInfo
        dataOffset = 2 + intLength
        length = buffer(startPos + 2, intLength):int()
      end

-- how to determine which one to use?        
--        print(buffer(startPos + dataOffset, length):bytes())
-- 0x7B is {
--      print("===== data ===== ", buffer(startPos + dataOffset, length):string())
      return buffer(startPos + dataOffset, length):string()

-- ASCII String        
    elseif objType == 0x5 then -- ASCII
      local length = objInfo
      local strOffset = 1
      if(objInfo == 0xF) then -- 1111
        local int_type = buffer(startPos + 1, 1):int()
        local intType = bit.band(int_type, 0xF0) / 0x10;
        if intType ~= 0x1 then
          print("Error : 0x5 Unexpected length - int-type", intType)
        end
        intInfo = bit.band(int_type, 0x0F)
        intLength = 2 ^ intInfo
        strOffset = 2 + intLength
        length = buffer(startPos + 2, intLength):int()
      end
--      print("===== ASCII String ===== ", buffer(startPos + strOffset, length):string())
      return buffer(startPos + strOffset, length):string()

-- UTF16 String        
    elseif objType == 0x6 then -- UTF-16
      local length = objInfo
      local strOffset = 1
      if(objInfo == 0xF) then -- 1111
        local int_type = buffer(startPos + 1, 1):int()
        local intType = bit.band(int_type, 0xF0) / 0x10;
        if intType ~= 0x1 then
          print("Error : 0x6 Unexpected length - int-type", intType)
        end
        intInfo = bit.band(int_type, 0x0F)
        intLength = 2 ^ intInfo
        strOffset = 2 + intLength
        length = buffer(startPos + 2, intLength):int()
      end
      length = length * 2
--      print("===== UTF16 String =====")
--      print("length: ", length)
--      print(buffer(startPos + strOffset, length):len())
--      print(buffer(startPos + strOffset, length):ustring())
      return "UTF16String"


-- Array        
    elseif objType == 0xA then
      local length = objInfo
      local arrayOffset = 1
      if(objInfo == 0xF) then -- 1111
        local int_type = buffer(startPos + 1, 1):int()
        local intType = bit.band(int_type, 0xF0) / 0x10;
        if intType ~= 0x1 then
          print("Error : 0xA Unexpected length - int-type", intType)
        end
        intInfo = bit.band(int_type, 0x0F)
        intLength = 2 ^ intInfo
        arrayOffset = 2 + intLength
        length = buffer(startPos + 2, intLength):int()
      end
--      print("===== parseArray =====")
      local array = {}
      for i = 0, length - 1, 1 do
        objRef = buffer(startPos + arrayOffset + i * objectRefSize, objectRefSize)
        array[i] = parseObject(objRef)
      end
      return array

-- Set
    elseif objType == 0xC then
--      print("===== Set =====")  
      return "Set!!!"

-- Dictionary        
    elseif objType == 0xD then
      local length = objInfo
--      print("length:", length)
      local dictOffset = 1
      if(objInfo == 0xF) then -- 1111
        local int_type = buffer(startPos + 1, 1):int()
        local intType = bit.band(int_type, 0xF0) / 0x10;
        if intType ~= 0x1 then
          print("Error : 0xD Unexpected length - int-type", intType)
        end
        intInfo = bit.band(int_type, 0x0F)
        intLength = 2 ^ intInfo
        dictOffset = 2 + intLength
        length = buffer(startPos + 2, intLength):int()
      end
--      print("===== Dictionary =====")
      local dict = {}
      for i = 0, length - 1, 1 do
--        print("buffer(startPos): ", buffer(startPos + dictOffset))
--        print("length: ", length)
--        print("object: ", i)
--        print("startPos: ", startPos)
--        print("dictOffset: ", dictOffset)
--        print("objectRefSize: ", objectRefSize)

        local keyRef = buffer((startPos + dictOffset) + (i * objectRefSize), objectRefSize):uint()
        local valRef = buffer((startPos + dictOffset + length) + (i * objectRefSize), objectRefSize):uint()
--        print("(startPos + dictOffset + length) + (i * objectRefSize): ", (startPos + dictOffset + length) + (i * objectRefSize))
--        print("keyRef: ", keyRef)
--        print("valRef: ", valRef)
        local key = parseObject(keyRef);
        local val = parseObject(valRef);
--        print("key: ", key)
--        print("val: ", val)
        dict[key] = val
      end
--        print("return parseDictionary();")
      return dict

    end

-- Unkown type return error message
    return "Error : Unknown object type - " .. objType

  end

  -- Initialization routine
  function p_bplist.init()
  end

-- register chained dissector on port 27753 (is it always this port?)
  tcp_dissector_table = DissectorTable.get("tcp.port")
  tcp_dissector_table:add(27753, p_bplist)

end