def label(value):
    return "Python says: " + value


def reverse_bytes(data):
    return data[::-1]


def is_gak_header(data):
    return data.startswith(b"GAK")
