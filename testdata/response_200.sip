SIP/2.0 200 OK
Via: SIP/2.0/UDP pc33.atlanta.example.com;branch=z9hG4bK776asdhds;received=192.0.2.1
To: Bob <sip:bob@biloxi.example.com>;tag=a6c85cf
From: Alice <sip:alice@atlanta.example.com>;tag=1928301774
Call-ID: a84b4c76e66710@pc33.atlanta.example.com
CSeq: 314159 INVITE
Contact: <sip:bob@192.0.2.4>
Content-Type: application/sdp
Content-Length: 228

v=0
o=bob 2808844564 2808844564 IN IP4 192.0.2.4
s=Session SDP
c=IN IP4 192.0.2.4
t=0 0
m=audio 3456 RTP/AVP 0 8
a=rtpmap:0 PCMU/8000
a=rtpmap:8 PCMA/8000
a=ssrc:87654321 cname:bob@biloxi.example.com
