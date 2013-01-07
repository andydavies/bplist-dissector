#bplist-dissector

Wireshark dissector for Safari Remote Debugging Protocol

*This is a work in progress*

Currently uses print so will only show packets in tshark

##Usage/Installation

###tshark

```tshark -X lua_script:bplist.lua -i lo0 -f "tcp port 27753" -O bplist -V```

###Wireshark

On OSX

Copy bplist.lua to ~/.wireshark

Add ```dofile(USER_DIR.."bplist.lua")``` to the end of ```/Applications/Wireshark.app/Contents/Resources/share/wireshark/init.lua```

##TODO

- Implement Sets, UTF16
- Format dates correctly
- Move port number into prefs?
- Tests
- Can tree be defaulted open?
- ~~ Display in Wireshark rather then relying on print!~~
