N_ROUNDS = 10

key        = b'\xc3,\\\xa6\xb5\x80^\x0c\xdb\x8d\xa5z*\xb6\xfe\\'
ciphertext = b'\xd1O\x14j\xa4+O\xb6\xa1\xc4\x08B)\x8f\x12\xdd'



def expand_key(master_key):
    """
    Expande y devuelve una lista de matrices clave para la clave maestra dada.
    """

    # Constantes redondas https://en.wikipedia.org/wiki/AES_key_schedule#Round_constants
    r_con = (
        0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
        0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
        0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
        0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
    )

    # Inicializar claves redondas con material de clave en bruto.
    key_columns = bytes2matrix(master_key)
    iteration_size = len(master_key) // 4

    # Cada iteración tiene exactamente tantas columnas como el material clave.
    columns_per_iteration = len(key_columns)
    i = 1
    while len(key_columns) < (N_ROUNDS + 1) * 4:
        # copiar la palabra anterior.
        word = list(key_columns[-1])

        # Realice schedule_core una vez en cada "fila-->row".
        if len(key_columns) % iteration_size == 0:
            # Desplazamiento circular.
            word.append(word.pop(0))
            #Mapa de S-BOX.
            word = [s_box[b] for b in word]
            # XOR con el primer byte de R-CON, ya que los otros bytes de R-CON son 0.
            word[0] ^= r_con[i]
            i += 1
        elif len(master_key) == 32 and len(key_columns) % iteration_size == 4:
            # Ejecute word a través de S-box en la cuarta iteración cuando utilice una
            # clave de 256-bit.
            word = [s_box[b] for b in word]

        # XOR con palabra equivalente de iteración anterior.
        word = bytes(i^j for i, j in zip(word, key_columns[-iteration_size]))
        key_columns.append(word)

    # Agrupe las palabras clave en matrices de 4x4 bytes.
    return [key_columns[4*i : 4*(i+1)] for i in range(len(key_columns) // 4)]


def decrypt(key, ciphertext):
    round_keys = expand_key(key) # recuerdea comenzar desde la última clave de ronda y trabajar hacia atrás a través de ellos al descifrar

    # Convertir texto cifrado en matriz de estado

    # Paso clave inicial para agregar ronda

    for i in range(N_ROUNDS - 1, 0, -1):
        pass # Hacer ronda
    
# Ejecutar la ronda final (omite el paso InvMixColumns)

    # Convertir matriz de estado en texto plano

    return plaintext


print(decrypt(key, ciphertext))
