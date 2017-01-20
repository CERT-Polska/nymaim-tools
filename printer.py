indent_level = 0
indent_text = '    '
silent = False


def config(silent_val=False, indent_text_val='    '):
    global silent
    global indent_text

    silent = silent_val
    indent_text = indent_text_val


def pprint(*text):
    global indent_level, silent
    if not silent:
        text = ' '.join(str(s) for s in text)
        print indent_level * indent_text + text


def indent():
    global indent_level
    indent_level += 1


def undent():
    global indent_level
    indent_level -= 1


def zero_indent():
    global indent_level
    indent_level = 0