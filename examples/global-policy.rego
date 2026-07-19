# METADATA
# title: global-policy
# description: The built-in global policy of a concrnt server.
package global_policy

defaults := {
	"record:create": "ng",
	"record:read": "ok",
	"record:update": "ng",
	"record:delete": "ng",
	"association:create": "ok",
	"association:read": "ok",
	"association:delete": "ng",
}

is_local_requester if input.requester.domain == input.globals.fqdn

owns_record_namespace if input.requester.ccid == ccuri_owner(input.self.key)

authored_or_owned if input.requester.ccid == input.self.author

authored_or_owned if owns_record_namespace

may_delete_association if input.requester.ccid == input.self.author

may_delete_association if input.requester.ccid == ccuri_owner(input.self.associate)

allow contains "ALLOW if the record is created under the namespace of the requester" if {
	input.action == "record:create"
	key_matches("*")
	is_local_requester
	owns_record_namespace
}

ok contains "OK if the record is created under the namespace of this server" if {
	input.action == "record:create"
	key_matches("*")
	is_local_requester
	ccuri_owner(input.self.key) == input.globals.fqdn
}

allow contains "ALLOW if the record is in the namespace of the requester" if {
	input.action == "record:read"
	key_matches("*")
	owns_record_namespace
}

allow contains "ALLOW if the requester is the author of the record or the record is in the namespace of the requester" if {
	input.action == "record:update"
	key_matches("*")
	authored_or_owned
}

allow contains "ALLOW if the requester is the author of the record or the record is in the namespace of the requester" if {
	input.action == "record:delete"
	key_matches("*")
	authored_or_owned
}

allow contains "ALLOW if the requester is the author of the association or the parent of the association is in the namespace of the requester" if {
	input.action == "association:delete"
	key_matches("*")
	may_delete_association
}
