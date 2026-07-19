# METADATA
# title: whisper
# description: Only the author and listed participants can read records.
# custom:
#   paramSchema:
#     type: object
#     properties:
#       participants:
#         type: array
#         items: {type: string}
#     required: [participants]
#     ui:
#       participants: {"ui:widget": userPicker}
package whisper

can_read if input.self.author == input.requester.ccid

can_read if input.requester.ccid in input.params.participants

deny contains "DENY: you are not a participant of this whisper" if {
	input.action == "record:read"
	key_matches("./*")
	not can_read
}
