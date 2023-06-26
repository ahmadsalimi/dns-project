def num2bytes(num: int) -> bytes:
    return num.to_bytes((num.bit_length() + 7) // 8, 'big')
