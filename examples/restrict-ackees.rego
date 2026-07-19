# METADATA
# title: restrict-ackees
package restrict_ackees

defaults := {"record:read": "ng"}

is_owner if input.requester.ccid == ccuri_owner(input.self.key)

is_ackee if {
	input.requester.ccid != ""
	is_not_empty(concrnt_call(
		ccuri_owner(input.self.key),
		"net.concrnt.core.acknowledges",
		"from", ccuri_owner(input.self.key),
		"to", input.requester.ccid))
}

reader_allowed if is_owner

reader_allowed if is_ackee

ok contains "reader is the owner or an ackee of the owner" if {
	input.action == "record:read"
	key_matches("")
	reader_allowed
}
