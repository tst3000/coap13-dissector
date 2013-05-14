do
  -- Declare CoAP protocol
  coap_proto = Proto("coap13","CoAP Protocol")
  
  -- Create the protocol fields
  local pdutypes= {[0]="CONFIRMABLE", [1]="NON-CONFIRMABLE", [2]="ACKNOWLEDGEMENT", [3]="RESET"}
  
  local codes= {
    [1]="GET",[2]="POST",[3]="PUT",[4]="DELETE",
    [65]="2.01 Created",
    [66]="2.02 Deleted",
    [67]="2.03 Valid",
    [68]="2.04 Changed",
    [69]="2.05 Content",
    [128]="4.00 Bad Request",
    [129]="4.01 Unauthorized",
    [130]="4.02 Bad Option",                
    [131]="4.03 Forbidden",
    [132]="4.04 Not Found",
    [133]="4.05 Method Not Allowed",
    [134]="4.06 Not Acceptable",
    [140]="4.12 Precondition Failed",
    [141]="4.13 Request Entity Too Large",
    [143]="4.15 Unsupported Content-Format",
    [160]="5.00 Internal Server Error",
    [161]="5.01 Not Implemented",
    [162]="5.02 Bad Gateway",
    [163]="5.03 Service Unavailable",
    [164]="5.04 Gateway Timeout",
    [165]="5.05 Proxying Not Supported" }
  
  local options= {
    [1]="If-Match",
    [3]="Uri-Host",
    [4]="ETag",
    [5]="If-None-Match",
    [7]="Uri-Port",
    [8]="Location-Path",
    [11]="URI-Path",
    [12]="Content-Format",
    [14]="Max-Age",
    [15]="Uri-Query",
    [16]="Accept",
    [20]="Location-Query",
    [35]="Proxy-Uri",
    [39]="Proxy-Scheme",
    [23]="Block2",
    [28]="Size",
    [27]="Block1"
    }
  
  local contentFormats =  {
    [0]="text/plain; charset=utf-8",
    [40]="application/link-format",
    [41]="application/xml",
    [42]="application/octet-stream",
    [47]="application/exi",
    [50]="application/json"
    }
  
  local f = coap_proto.fields
	
  f.version = ProtoField.uint8 ("coap.version",  "Version",nil,nil,0xC0)
  f.type = ProtoField.uint8 ("coap.type",  "PDU Type",nil,pdutypes,0x30)
  f.tkl = ProtoField.uint8 ("coap.tkl",  "Token Length",nil,nil,0x0f)
  f.code = ProtoField.uint8 ("coap.code",  "Code",nil,codes)
  f.msgid = ProtoField.uint16 ("coap.msgid",  "Message ID",base.HEX )
  f.token = ProtoField.bytes ("coap.token",  "Token")
  
  f.option = ProtoField.uint8 ("coap.option", "Option",nil,options)
  f.contentFormat = ProtoField.uint8 ("coap.contentFormat", "Content-Format",nil,contentFormats)

  f.blockOption8Num = ProtoField.uint8 ("coap.blockOption8Num", "Block Numb",nil,nil,0xF0)
  f.blockOption8More = ProtoField.uint8 ("coap.blockOption8More", "More blocks",nil,nil,0x08)
  f.blockOption8BlockSize = ProtoField.uint8 ("coap.blockOption8BlockSize", "Block size",nil,nil,0x07)


  
  f.payload = ProtoField.bytes("coap.payload", "Payload")
  
  -- create a function to dissect it
  function coap_proto.dissector(buffer,pinfo,tree)
      pinfo.cols.protocol = "CoAP"
      local subtree = tree:add(coap_proto,buffer(),"CoAP Protocol Data")
      subtree:add (f.version, buffer (0, 1))
      subtree:add (f.type, buffer (0, 1))
      subtree:add (f.tkl, buffer (0, 1))
      subtree:add (f.code, buffer (1, 1))
      subtree:add (f.msgid, buffer (2, 2))

      --local tp = bit.band(buffer(0,1):uint(),0x30)
      --pinfo.cols.info = "CoAP "..tp
      
      local tkl = bit.band(buffer(0,1):uint(),0x0f)
      local i = 4
      
      if tkl > 0 and tkl <= 8 then
        -- read token
        subtree:add(f.token,buffer(i,tkl))
      end
      
      i = i+tkl
      local lastOption = 0
      local optionsDone = false
       
      -- loop over options until buffer ends or payload delimiter reached
      while i<buffer:len() and (not optionsDone) do
        local of = buffer(i,1):uint()
        local oDelta = bit.rshift(bit.band(of,0xf0),4)
        local oLength = bit.band(of,0x0f)
        print("oDelta: "..oDelta..", oLength:"..oLength)
        if (of==0xff) then
          optionsDone = true
          i = i + 1
          oLength = 0
        else
	  local optionStart = i
	  local optionHeaderLen = 1

	  -- check if option delta ext. is used
	  if (oDelta==0x0d) then
	    oDelta = buffer(i+1,1):uint() + 13
	    i = i+1
	    optionHeaderLen = optionHeaderLen + 1
	  end

	  -- check if option length ext. is used
	  if (oLength==0x0d) then
	    oLength = buffer(i+1,1):uint() + 13
	    i = i+1
	    optionHeaderLen = optionHeaderLen + 1
	  elseif (oLength==0x0e) then
	    oLength = bit.lshift(buffer(i+1,1):uint(),8) + buffer(i+2,1):uint() + 269
	    i = i+2
	    optionHeaderLen = optionHeaderLen + 2
	  end
          
	  print("oLength: "..oLength)

          local optType = lastOption + oDelta
          local otree = subtree:add (f.option, buffer(optionStart,oLength+optionHeaderLen), optType)
          if (optType == 11) or (optType == 8) then
            otree:append_text(" "..buffer(i+1,oLength):string())
          elseif (optType == 12) then
            otree:add (f.contentFormat, buffer(i+1,oLength))
	  elseif (optType == 27 or optType == 23) and oLength == 1 then
            otree:add (f.blockOption8Num, buffer(i+1,oLength))
            otree:add (f.blockOption8More, buffer(i+1,oLength))
            otree:add (f.blockOption8BlockSize, buffer(i+1,oLength))
          end
          
          lastOption = optType
          i = i + oLength + 1
        end
      end
       
      -- if still data available, add as payload
      if i<buffer:len() then
        subtree:add(f.payload,buffer(i,buffer:len()-i))
      end
      
  end
  -- load the udp.port table
  udp_table = DissectorTable.get("udp.port")
  -- register our protocol to handle udp port 5683
  udp_table:add(5683,coap_proto)
  
end  
