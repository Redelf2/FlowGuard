# LABEL: SAFE
# PROVENANCE: Author-written; created without opening evaluate.py, rules.py, or existing samples.
# Reason: The value returned by input() is not passed to a configured FG002 command sink.
typed_text = input("Enter a note: ")
print("Note received")
