from collections.abc import Iterable


def flatten(nested_list):
    """Flatten a nested list of arbitrary depth."""
    result = []
    for item in nested_list:
        if isinstance(item, Iterable) and not isinstance(item, (str, bytes, tuple, dict)):
            result.extend(flatten(item))
        else:
            result.append(item)
    return result


def test_flatten():
    # Basic test
    assert flatten([1, [2, 3], [4, [5, 6]]]) == [1, 2, 3, 4, 5, 6]

    # Empty list
    assert flatten([]) == []

    # Already flat
    assert flatten([1, 2, 3]) == [1, 2, 3]

    # Deeply nested
    assert flatten([[[1]], [[2]], [[3]]]) == [1, 2, 3]

    # Mixed types with tuples — should treat tuples as values, not sublists
    assert flatten([1, (2, 3), [4, (5, 6)]]) == [1, (2, 3), 4, (5, 6)]

    # Nested with None values
    assert flatten([1, [None, 2], [3, [None]]]) == [1, None, 2, 3, None]

    # This should flatten generator expressions too
    assert flatten([1, [2, iter([3, 4])]]) == [1, 2, 3, 4]

    # Strings should not be flattened into characters
    assert flatten([1, ["hello", 2], [3]]) == [1, "hello", 2, 3]

    # Dicts should not be flattened into keys
    assert flatten([1, {"a": 1}, [2]]) == [1, {"a": 1}, 2]

    # Bytes should not be flattened
    assert flatten([1, [b"hello", 2]]) == [1, b"hello", 2]

    print("All tests passed!")


if __name__ == "__main__":
    test_flatten()
