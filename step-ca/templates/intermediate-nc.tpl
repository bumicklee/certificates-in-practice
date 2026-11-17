{
  "subject": {{ toJson .Subject }},
  "keyUsage": ["certSign", "crlSign"],
  "basicConstraints": { "isCA": true, "maxPathLen": 0 },
  "nameConstraints": {
    "critical": true,
    "permittedDNSDomains": ["lab.example"],
    "permittedURIDomains": ["lab.example"],
    "permittedIPRanges": ["127.0.0.0/8", "10.0.0.0/8"]
  }
}
