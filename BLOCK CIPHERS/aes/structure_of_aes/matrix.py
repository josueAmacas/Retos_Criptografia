def bytes2matrix(text):
    """ Convierte una matriz de 16 bytes en una matriz de 4x4. """
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix2bytes(matrix):
    """ Convierte una matriz de 4x4 en una matriz de 16 bytes. """
    arr = []

    # O(n^2) atraviesa la matriz 4x4 y construye la matriz.
    for i in range(0, len(matrix)):
        m = matrix[i]
        for j in range(0, len(m)):
            arr.append(m[j])
    return arr

def pro_matrix2bytes(matrix):
    """ Convierte una matriz de 4x4 en una matriz de 16 bytes. (Robin Jadoul) """
    return bytes(sum(matrix, []))

matrix = [
    [99, 114, 121, 112],
    [116, 111, 123, 105],
    [110, 109, 97, 116],
    [114, 105, 120, 125],
]

# Probando la naturaleza de la función
print(bytes2matrix([1, 2, 3, 4, 5, 6, 7, 8]))

# Recuperar bandera con implementación propia
flag = matrix2bytes(matrix)
print("".join([chr(f) for f in flag]))

# Recuperar bandera con implementación pro
flag = pro_matrix2bytes(matrix)
print(flag.decode("utf-8"))