coap13-dissector
================

Wireshark Dissector for CoAP (Draft 13)

This is a .lua dissector for Wireshark dissecting the CoAP (Contrained Application Protocol) as of Draft-13.

http://tools.ietf.org/html/draft-ietf-core-coap-13

TODOs
----------------

* add all request/response codes
* add missing options 
* add missing content formats
* implement correct dissection of option length (length: 13 and 14 need to include additional length fields)

