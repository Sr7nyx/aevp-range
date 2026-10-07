"""The sinkhole: the destination that all range egress is routed to (the Tier 0
egress proxy stand-in). It logs every request it receives to the event log; the
P1 oracle later scans those logged payloads for known canaries. The sink itself
makes no judgement.
"""
