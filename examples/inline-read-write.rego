# METADATA
# title: timeline-inline-read-write
# custom:
#   paramSchema:
#     type: object
#     properties:
#       isWritePublic: {type: boolean}
#       isReadPublic: {type: boolean}
#     allOf:
#       - if:
#           properties:
#             isWritePublic: {const: false}
#         then:
#           properties:
#             writer:
#               type: array
#               items: {type: string}
#       - if:
#           properties:
#             isReadPublic: {const: false}
#         then:
#           properties:
#             reader:
#               type: array
#               items: {type: string}
#     required: [isWritePublic, isReadPublic, writer, reader]
#     ui:
#       writer: {"ui:widget": userPicker}
#       reader: {"ui:widget": userPicker}
package timeline_inline_read_write

deny contains "DENY this timline is not public and you are not in the reader list" if {
	input.action == "record:read"
	key_matches("./*")
	not input.params.isReadPublic
	not input.requester.ccid in input.params.reader
}

ok contains "OK this timeline is public" if {
	input.action == "record:read"
	key_matches("./*")
	input.params.isReadPublic
}

deny contains "DENY this timline is not public and you are not in the writer list" if {
	input.action == "record:create"
	key_matches("./*")
	not input.params.isWritePublic
	not input.requester.ccid in input.params.writer
}

ok contains "OK this timeline is public" if {
	input.action == "record:create"
	key_matches("./*")
	input.params.isWritePublic
}
