# METADATA
# title: restrict-readers
# custom:
#   paramSchema:
#     type: object
#     properties:
#       entities:
#         type: array
#         items: {type: string}
#     required: [entities]
#     ui:
#       entities: {"ui:widget": userPicker}
package restrict_readers

deny if {
	input.action == "record:read"
	key_matches("./*")
	not input.requester.ccid in input.params.entities
}
