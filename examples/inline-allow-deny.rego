# METADATA
# title: timeline-inline-allow-deny
# custom:
#   paramSchema:
#     type: object
#     properties:
#       writeListMode:
#         type: boolean
#         oneOf:
#           - {const: false, title: DenyList}
#           - {const: true, title: AllowList}
#         default: false
#       writer:
#         type: array
#         items: {type: string}
#       readListMode:
#         type: boolean
#         oneOf:
#           - {const: false, title: DenyList}
#           - {const: true, title: AllowList}
#         default: false
#       reader:
#         type: array
#         items: {type: string}
#     required: [writeListMode, readListMode, writer, reader]
#     ui:
#       writeListMode: {"ui:widget": select}
#       readListMode: {"ui:widget": select}
#       writer: {"ui:widget": userPicker}
#       reader: {"ui:widget": userPicker}
package timeline_inline_allow_deny

deny contains "DENY this timline is allow-list mode and you are not in the reader list" if {
	input.action == "record:read"
	key_matches("./*")
	input.params.readListMode
	not input.requester.ccid in input.params.reader
}

deny contains "DENY this timline is deny-list mode and you are in the reader list" if {
	input.action == "record:read"
	key_matches("./*")
	not input.params.readListMode
	input.requester.ccid in input.params.reader
}

deny contains "DENY this timline is allow-list mode and you are not in the writer list" if {
	input.action == "record:create"
	key_matches("./*")
	input.params.writeListMode
	not input.requester.ccid in input.params.writer
}

deny contains "DENY this timline is deny-list mode and you are in the writer list" if {
	input.action == "record:create"
	key_matches("./*")
	not input.params.writeListMode
	input.requester.ccid in input.params.writer
}
