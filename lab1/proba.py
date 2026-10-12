plaintext = "IAMHURTVERYBADLYHELP"
circumference = 5

cols = len(plaintext)
rows = circumference
matrix = [['.' for _ in range(cols)] for _ in range(rows)]

for i, char in enumerate(plaintext):
        row = i % circumference
        col = i
        matrix[row][col] = char

result = ""
for i in range(rows):
    for j in range(cols):
          if matrix[i][j] != '.':
                result += matrix[i][j]

print(result)