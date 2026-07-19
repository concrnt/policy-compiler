# METADATA
# title: allow-writers
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
package allow_writers

ok if {
	input.action == "record:create"
	key_matches("./*")
	input.requester.ccid in input.params.entities
}
