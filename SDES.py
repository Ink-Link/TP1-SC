##### Listas de Permutação e Substituição #####
P4 =  [1,3,2,0]
P8 =  [5,2,6,3,7,4,9,8]
P10 = [2,4,1,6,3,9,0,8,7,5]
IP =  [1,5,2,0,3,7,4,6]
IPI = [3,0,2,4,6,1,7,5]
EP =  [3,0,1,2,1,2,3,0]

S0 = [[1,0,3,2],
      [3,2,1,0],
      [0,2,1,3],
      [3,1,3,2]]

S1 = [[0,1,2,3],
      [2,0,1,3],
      [3,0,1,0],
      [2,1,0,3]]

##### Geração de Chave #####

def perm(bits, lista):
  return [bits[i] for i in lista]

def shift(bits, n):
  return bits[n:] + bits[:n]

def genChave(chave):
  chave_perm = perm(chave, P10)
  left, right = chave_perm[:5], chave_perm[5:]

  k1 = ''.join(perm(shift(left, 1) + shift(right, 1), P8))
  k2 = ''.join(perm(shift(left, 3) + shift(right, 3), P8))
  return k1, k2

##### Criptografia #####

def switch(bits):
  return bits[4:] + bits[:4]

def sBox(bits, sbox):
  linha = int(bits[0]+bits[3], 2)
  coluna = int(bits[1]+bits[2], 2)
  return '{:02b}'.format(sbox[linha][coluna])

def fk(bits, chave):
  left, right = ''.join(bits[:4]), ''.join(bits[4:])
  right_exp = ''.join(perm(right, EP))

  xor = '{:08b}'.format(int(right_exp, 2) ^ int(chave, 2))
  sbox = sBox(xor[:4], S0) + sBox(xor[4:], S1)

  resultado = ''.join(perm(sbox, P4))
  return '{:04b}'.format(int(left, 2) ^ int(resultado, 2)) + right

def encSDES(bits, chave):
  k1, k2 = genChave(chave)
  print("Subchaves:", k1, k2)

  bits_perm = perm(bits, IP)
  parte1 = fk(bits_perm, k1)
  parte2 = fk(switch(parte1), k2)
  return perm(parte2, IPI)

def decSDES(bits, chave):
  k1, k2 = genChave(chave)

  bits_perm = perm(bits, IP)
  parte1 = fk(bits_perm, k2)
  parte2 = fk(switch(parte1), k1)
  return perm(parte2, IPI)

##### Teste #####
# Resultado esperado: 10101000

chave = '1010000010'
bloco = '11010111'

print("Chave:", chave)
print("Bloco:", bloco)
print("--------------------")

bloco = encSDES(bloco, chave)

print("Bloco criptografado:", ''.join(bloco))

bloco = decSDES(bloco, chave)

print("Bloco descriptografado:", ''.join(bloco))