"""Simple CSV parser that handles quoted fields and escaped quotes."""


def parse_csv(text):
    """Parse a CSV string into a list of rows (each row is a list of fields)."""
    rows = []
    current_row = []
    current_field = ""
    in_quotes = False
    field_started = False
    i = 0

    while i < len(text):
        char = text[i]

        if char == '"':
            field_started = True
            if in_quotes and i + 1 < len(text) and text[i + 1] == '"':
                # Escaped quote: "" becomes "
                current_field += '"'
                i += 2
                continue
            else:
                in_quotes = not in_quotes
        elif char == ',' and not in_quotes:
            current_row.append(current_field)
            current_field = ""
        elif char == '\r' and not in_quotes:
            if i + 1 < len(text) and text[i + 1] == '\n':
                # CRLF: skip \r, the \n will be handled next iteration
                i += 1
                continue
            else:
                # Bare \r is also a line ending (old Mac)
                if current_field or current_row:
                    current_row.append(current_field)
                rows.append(current_row)
                current_row = []
                current_field = ""
        elif char == '\n' and not in_quotes:
            if current_field or current_row:
                current_row.append(current_field)
            rows.append(current_row)
            current_row = []
            current_field = ""
        else:
            current_field += char

        i += 1

    # Don't forget the last field/row
    if current_field or current_row:
        current_row.append(current_field)
        rows.append(current_row)

    return rows


def test_parse_csv():
    # Basic CSV
    result = parse_csv("a,b,c\n1,2,3")
    assert result == [["a", "b", "c"], ["1", "2", "3"]], f"Basic failed: {result}"

    # Quoted fields
    result = parse_csv('a,"b,c",d\n1,2,3')
    assert result == [["a", "b,c", "d"], ["1", "2", "3"]], f"Quoted failed: {result}"

    # Escaped quotes (doubled quotes inside quoted field)
    result = parse_csv('a,"he said ""hello""",c')
    assert result == [["a", 'he said "hello"', "c"]], f"Escaped quotes failed: {result}"

    # Empty fields
    result = parse_csv("a,,c\n,b,")
    assert result == [["a", "", "c"], ["", "b", ""]], f"Empty fields failed: {result}"

    # Multiline quoted field
    result = parse_csv('a,"line1\nline2",c')
    assert result == [["a", "line1\nline2", "c"]], f"Multiline failed: {result}"

    # Empty quoted field
    result = parse_csv('"",b,c')
    assert result == [["", "b", "c"]], f"Empty quoted failed: {result}"

    # Field with only a quote inside
    result = parse_csv('a,"""",c')
    assert result == [["a", '"', "c"]], f"Single quote field failed: {result}"

    # Trailing newline
    result = parse_csv("a,b,c\n")
    assert result == [["a", "b", "c"]], f"Trailing newline failed: {result}"

    # CRLF line endings
    result = parse_csv("a,b,c\r\n1,2,3")
    assert result == [["a", "b", "c"], ["1", "2", "3"]], f"CRLF failed: {result}"

    # Quoted field containing literal \r\n (should preserve it)
    result = parse_csv('"has\r\ninside",b\r\n1,2')
    assert result == [["has\r\ninside", "b"], ["1", "2"]], f"Quoted CRLF failed: {result}"

    # Bare \r as line ending (old Mac style)
    result = parse_csv("a,b\r1,2")
    assert result == [["a", "b"], ["1", "2"]], f"Bare CR line ending failed: {result}"

    print("All tests passed!")


if __name__ == "__main__":
    test_parse_csv()
