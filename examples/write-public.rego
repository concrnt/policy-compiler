# METADATA
# title: write-public
# custom:
#   paramSchema:
#     type: object
#     properties: {}
#     required: []
#     ui: {}
package write_public

ok contains "OK: this is a write-public timline" if {
	input.action == "record:create"
	key_matches("./*")
}
