"""Small stdlib-only HTTP/2 fixture; first-response status and body, no dependency."""
import socket


def integer(value, prefix, mask=0):
    maximum = (1 << prefix) - 1
    if value < maximum:
        return bytes((mask | value,))
    output = bytearray((mask | maximum,))
    value -= maximum
    while value >= 128:
        output.append((value & 127) | 128)
        value >>= 7
    output.append(value)
    return bytes(output)


def string(value):
    value = value.encode()
    return integer(len(value), 7) + value


def frame(kind, flags, stream, body=b''):
    return len(body).to_bytes(3, 'big') + bytes((kind, flags)) + stream.to_bytes(4, 'big') + body


def status(block):
    if block[0] & 128:
        return {8: 200, 9: 204, 10: 206, 11: 304, 12: 400, 13: 404, 14: 500}[block[0] & 127]
    prefix = 6 if block[0] & 64 else 4
    assert block[0] & ((1 << prefix) - 1) == 8, block
    length = block[1] & 127
    value = block[2:2 + length]
    if not block[1] & 128:
        return int(value)
    # RFC 7541 appendix B, only the three decimal :status digits are needed.
    codes = ['00000', '00001', '00010', '011001', '011010',
             '011011', '011100', '011101', '011110', '011111']
    bits = ''.join(f'{byte:08b}' for byte in value)
    digits = ''
    for _ in range(3):
        for digit, code in enumerate(codes):
            if bits.startswith(code):
                digits += str(digit)
                bits = bits[len(code):]
                break
        else:
            raise AssertionError(('invalid status Huffman', value))
    assert len(bits) < 8 and all(bit == '1' for bit in bits), value
    return int(digits)


def request(port, path, fields, body=b'', method='GET', tls_context=None):
    headers = bytes((0x82 if method == 'GET' else 0x83, 0x86, 0x04)) + string(path)
    headers += b'\x01' + string('localhost')
    for name, value in [*fields, ('content-length', str(len(body)))]:
        headers += b'\x00' + string(name.lower()) + string(value)
    transport = socket.create_connection(('127.0.0.1', port), timeout=8)
    if tls_context is not None:
        try:
            transport = tls_context.wrap_socket(transport, server_hostname='localhost')
        except BaseException:
            transport.close()
            raise
    with transport as connection:
        connection.sendall(b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n' + frame(4, 0, 0) +
                           frame(1, 4 if body else 5, 1, headers) +
                           (frame(0, 1, 1, body) if body else b''))

        def exact(length):
            output = b''
            while len(output) < length:
                chunk = connection.recv(length - len(output))
                assert chunk, 'HTTP/2 response closed early'
                output += chunk
            return output

        code, output = None, b''
        for _ in range(40):
            header = exact(9)
            payload = exact(int.from_bytes(header[:3], 'big'))
            kind, flags = header[3:5]
            stream = int.from_bytes(header[5:], 'big') & 0x7fffffff
            assert kind not in (3, 7), (kind, payload)
            if kind == 4 and not flags & 1:
                connection.sendall(frame(4, 1, 0))
            if stream == 1 and kind == 1:
                assert flags & 4 and not flags & (8 | 32), flags
                code = status(payload)
            if stream == 1 and kind == 0:
                assert not flags & 8
                output += payload
            if stream == 1 and kind in (0, 1) and flags & 1:
                assert code is not None
                return code, output
        raise AssertionError('HTTP/2 response did not finish')
