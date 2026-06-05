# Generate an animated demo GIF with charmbracelet/vhs:
#   brew install vhs        # or: go install github.com/charmbracelet/vhs@latest
#   vhs examples/demo.tape  # writes assets/demo.gif
#
# This drives a throwaway repo, tries to commit the malicious fixture (blocked),
# removes the payload, then commits successfully.

Output assets/demo.gif

Set FontSize 18
Set Width 1100
Set Height 600
Set Theme "Dracula"
Set Padding 18

Type "git init -q demo && cd demo" Enter
Type "cp ../test/fixtures/malicious.config.js tailwind.config.js" Enter
Sleep 500ms

Type "# Try to commit a config file with a hidden injected payload..." Enter
Type "git add tailwind.config.js && npx polin-guard --staged" Enter
Sleep 3s

Type "# Blocked. Remove the malicious line, then commit cleanly." Enter
Type "printf 'module.exports = {}\\n' > tailwind.config.js" Enter
Type "git add tailwind.config.js && npx polin-guard --staged" Enter
Sleep 2.5s
