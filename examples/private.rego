# METADATA
# title: private
package private

deny contains "This record is private and cannot be read by others." if {
	input.action == "record:read"
	key_matches(".")
}
