state = [
    [206, 243, 61, 34],
    [171, 11, 93, 31],
    [16, 200, 91, 108],
    [150, 3, 194, 51],
]

round_key = [
    [173, 129, 68, 82],
    [223, 100, 38, 109],
    [32, 189, 53, 8],
    [253, 48, 187, 78],
]


def add_round_key(state, round_key):
    """ Matriz de teclas redondas XOR con matriz de estado """
    arr = []

    if len(state) != len(round_key):
        raise Exception("No de la misma longitud")
 
    size = len(state)

    for i in range(size):
        row = []
        for j in range(size):
            row.append(state[i][j] ^ round_key[i][j])
        arr.append(row)
    return arr

def pro_matrix2bytes(matrix):
    """Convierte una matriz de 4x4 en una matriz de 16 bytes. (Robin Jadoul)  """
    return bytes(sum(matrix, []))

# Agregar operación de tecla redonda a matrices
matrix = add_round_key(state, round_key)
print(matrix)

# Recuperar bandera con implementación pro
flag = pro_matrix2bytes(matrix)
print(flag.decode("utf-8"))